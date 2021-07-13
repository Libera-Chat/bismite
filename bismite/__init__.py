import asyncio, re, traceback
from collections import deque, OrderedDict
from datetime    import datetime
from random      import randint
from time        import monotonic, time
from typing      import Any, Deque, Dict, List, Optional, Tuple
from typing      import OrderedDict as TOrderedDict

from irctokens import build, Line, Hostmask
from ircrobots import Bot as BaseBot
from ircrobots import Server as BaseServer

from ircstates.numerics   import *
from ircrobots.matching   import Response, ANY, Folded, SELF
from ircchallenge         import Challenge

from .config   import Config
from .database import Database

from .common   import Event, MaskType, User, to_pretty_time
from .common   import mask_compile, mask_find, mask_token, mask_weight

# not in ircstates yet...
RPL_RSACHALLENGE2      = "740"
RPL_ENDOFRSACHALLENGE2 = "741"
RPL_WHOISOPERATOR      = "313"
RPL_YOUREOPER          = "381"

MAX_RECENT = 1000

RE_OPERNAME = re.compile(r"^is opered as (\S+)(?:,|$)")

# decorator, for command usage strings
def usage(usage_string: str):
    def usage_inner(object: Any):
        if not hasattr(object, "_usage"):
            object._usage: List[str] = []
        # decorators eval bottom up, insert to re-invert order
        object._usage.insert(0, usage_string)
        return object
    return usage_inner

class UsageError(Exception):
    pass

class Server(BaseServer):
    def __init__(self,
            bot:    BaseBot,
            name:   str,
            config: Config):

        super().__init__(bot, name)
        self._config  = config
        self._database = Database(config.database)

        self._users:          Dict[str, User] = {}
        self._recent_masks:   Deque[Tuple[List[str], Set[str]]] = deque()
        self._compiled_masks: TOrderedDict[int, Tuple[Pattern, Set[str]]] \
            = OrderedDict()
        self._reasons:        Dict[str, str] = {}

        self.delayed_send: Deque[Tuple[int, str]] = deque()

        self.to_check: Deque[Tuple[float, str, User]] = deque()
        self._nick_change_whois: Deque[str] = deque()

    def set_throttle(self, rate: int, time: float):
        # turn off throttling
        pass

    async def _oper_challenge(self,
            oper_name: str,
            oper_file: str,
            oper_pass: str):
        try:
            challenge = Challenge(keyfile=oper_file, password=oper_pass)
        except Exception:
            traceback.print_exc()
        else:
            await self.send(build("CHALLENGE", [oper_name]))
            challenge_text = Response(RPL_RSACHALLENGE2,      [SELF, ANY])
            challenge_stop = Response(RPL_ENDOFRSACHALLENGE2, [SELF])
            #:lithium.libera.chat 740 sandcat :foobarbazmeow
            #:lithium.libera.chat 741 sandcat :End of CHALLENGE

            while True:
                challenge_line = await self.wait_for({
                    challenge_text, challenge_stop
                })
                if challenge_line.command == RPL_RSACHALLENGE2:
                    challenge.push(challenge_line.params[1])
                else:
                    retort = challenge.finalise()
                    await self.send(build("CHALLENGE", [f"+{retort}"]))
                    break

    async def _oper_up(self,
            oper_name: str,
            oper_pass: str,
            oper_file: Optional[str]):

        if oper_file is not None:
            await self._oper_challenge(oper_name, oper_file, oper_pass)
        else:
            await self.send(build("OPER", [oper_name, oper_pass]))

    async def _get_oper(self, nickname: str):
        await self.send(build("WHOIS", [nickname]))

        whois_oper = Response(RPL_WHOISOPERATOR, [SELF, Folded(nickname)])
        whois_end  = Response(RPL_ENDOFWHOIS,    [SELF, Folded(nickname)])
        #:lithium.libera.chat 320 sandcat sandcat :is opered as sandcat, privset sandcat
        #:lithium.libera.chat 318 sandcat sandcat :End of /WHOIS list.

        whois_line = await self.wait_for({
            whois_end, whois_oper
        })
        # return the oper name or nothing
        if whois_line.command == RPL_WHOISOPERATOR:
            match = RE_OPERNAME.search(whois_line.params[2])
            if match is not None:
                return match.group(1)
        return None

    def _format(self,
            string: str,
            extras: Dict[str, str]
            ):

        formats = self._reasons.copy()
        formats.update(extras)

        # expand reason templates
        for i in range(10):
            changed = False
            for k, v in formats.items():
                k = f"${k}"
                if k in string:
                    changed = True
                    string = string.replace(k, v)
            if not changed:
                # don't keep going if nothing changes
                break
        return string.rstrip()

    async def _idle_reset(self):
        # send ourselves a PM to reset our idle time
        if self._config.antiidle:
            await self.send(build("PRIVMSG", [self.nickname, "hello self"]))

    async def _mask_match(self,
            nick:  str,
            user:  User,
            event: Event
            ) -> List[int]:

        uflags: Set[str] = set()
        if user.account is not None:
            uflags.add("a")
        else:
            uflags.add("A")

        if user.secure:
            uflags.add("z")
        else:
            uflags.add("Z")

        if event == Event.CONNECT:
            uflags.add("n")

        references = [f"{nick}!{user.user}@{user.host} {user.real}"]
        if user.ip is not None:
            # has no i-line spoof
            uflags.add("S")

            if user.host == user.ip:
                # if the user has an IP and IP != host, also match against IP
                references.append(f"{nick}!{user.user}@{user.ip} {user.real}")
        else:
            # has an i-line spoof
            uflags.add("s")

        self._recent_masks.append((references, uflags))
        if len(self._recent_masks) > MAX_RECENT:
            self._recent_masks.popleft()

        matches: List[int] = []
        for mask_id, (pattern, flags) in self._compiled_masks.items():
            # which flags does the pattern want that we've not got?
            nflags = flags - uflags
            if nflags:
                continue

            for ref in references:
                if pattern.search(ref):
                    matches.append(mask_id)
                    # skip to the next mask
                    break
        return matches

    async def mask_check(self,
            nick:  str,
            user:  User,
            event: Event):

        await self._idle_reset()
        match_ids = await self._mask_match(nick, user, event)
        if match_ids:
            for match_id in match_ids:
                await self._database.masks.hit(match_id)

            # get all (mask, details) for matched IDs
            matches = [(i, await self._database.masks.get(i)) \
                for i in match_ids]
            types   = {d.type for i, (m, d) in matches}

            # sort by mask type, descending
            # this should order: exclude, dlethal, lethal, kill, warn
            matches.sort(
                key=lambda m: mask_weight(m[1][1].type),
                reverse=True
            )

            mask_id, (mask, d) = matches[0]

            ident  = user.user
            # if the user doesn't have identd, bin the whole host
            if ident.startswith("~"):
                ident = "*"

            # format reason $aliases
            reason = self._format(d.reason, {
                "mask_id": str(mask_id)
            })

            user_reason, _, oper_reason = reason.partition("|")

            info = {
                "ident":  ident,
                "user":   user,
                "reason": reason,
                "rand":   randint(160, 320),
                "mask_id":     str(mask_id),
                "user_reason": user_reason,
                "oper_reason": oper_reason
            }

            ban = self._config.bancmd.format(**info)
            if d.type == MaskType.LETHAL:
                await self.send_raw(ban)
            elif d.type == MaskType.DLETHAL:
                self.delayed_send.append((monotonic(), ban))
            elif d.type == MaskType.KILL:
                await self.send(build("KILL", [nick, user_reason]))

            if (d.type == MaskType.EXCLUDE and
                    len(types) == 1):
                # we matched an EXCLUDE but no other types.
                # do not log
                pass
            else:
                await self.send(build("PRIVMSG", [
                    self._config.channel,
                    (
                        f"MASK: {d.type.name} mask {mask_id} "
                        f"{nick}!{user.user}@{user.host} {user.real}"
                    )
                ]))

    async def line_read(self, line: Line):
        if line.command == RPL_WELCOME:
            self._compiled_masks.clear()
            self._reasons.clear()
            # load and compile all masks/reason templates
            for mask_id, mask in await self._database.masks.list_enabled():
                cmask, flags = mask_compile(mask)
                self._compiled_masks[mask_id] = (cmask, flags)

            for key, value in await self._database.reasons.list():
                self._reasons[key] = value

            await self.send(build("MODE", [self.nickname, "+g"]))
            oper_name, oper_pass, oper_file = self._config.oper
            await self._oper_up(oper_name, oper_pass, oper_file)

        elif line.command == RPL_YOUREOPER:
            # F far cliconn
            # c near cliconn
            # n nick changes
            await self.send(build("MODE", [self.nickname, "-s+s", "+Fcn"]))

        elif line.command == RPL_WHOISACCOUNT:
            nick    = line.params[1]
            account = line.params[2]

            if nick in self._users:
                self._users[nick].account = account

        elif line.command == RPL_WHOISSECURE:
            nick = line.params[1]

            if nick in self._users:
                self._users[nick].secure = True

        elif line.command == RPL_ENDOFWHOIS:
            nick = line.params[1]
            if (self._nick_change_whois and
                    self._nick_change_whois[0] == nick):

                self._nick_change_whois.popleft()

                # this should be safe.
                # if the connection using `nick` has changed between sending
                # whois and getting a response, the whois should be for the
                # new user of the nick

                # < nick1 NICK nick2
                # > WHOIS nick2
                # < nick2 NICK nick3
                # < nick4 NICK nick2
                # < [response for new nick2 user]

                if nick in self._users:
                    user = self._users[nick]
                    await self.mask_check(nick, user, Event.NICK)

        elif (line.command == "PRIVMSG" and
                not self.is_me(line.hostmask.nickname) and
                self.is_me(line.params[0])):

            # private message

            out = f"[PV] <{line.source}> {line.params[1]}"
            await self.send(build("PRIVMSG", [self._config.channel, out]))

            cmd, _, args = line.params[1].partition(" ")
            await self.cmd(line.hostmask, cmd.lower(), args)

        else:

            rawline   = line.format()
            p_cliconn = self._config.cliconnre.search(rawline)
            p_cliexit = self._config.cliexitre.search(rawline)
            p_clinick = self._config.clinickre.search(rawline)

            if p_cliconn is not None:
                nick = p_cliconn.group("nick")
                user = p_cliconn.group("user")
                host = p_cliconn.group("host")
                real = p_cliconn.group("real")
                # the regex might not have an `ip` group
                ip: Optional[str] = p_cliconn.groupdict().get("ip", None)

                if ip == "0":
                    # remote i-line spoof
                    ip = None

                user = User(user, host, real, ip)
                # we hold on to nick:User of all connected users
                self._users[nick] = user
                # send a WHOIS to check accountname
                await self.send(build("WHOIS", [nick]))

                self.to_check.append((monotonic(), nick, user))

            elif p_cliexit is not None:
                nick = p_cliexit.group("nick")

                if nick in self._users:
                    user = self._users.pop(nick)
                    # .connected is used to not match clients that disconnect
                    # too quickly (e.g. due to OPM murder)
                    user.connected = False

            elif p_clinick is not None:
                old_nick = p_clinick.group("old")
                new_nick = p_clinick.group("new")

                if old_nick in self._users:
                    user = self._users.pop(old_nick)
                    self._users[new_nick] = user
                    # refresh what we think this user's account is
                    self._nick_change_whois.append(new_nick)
                    user.account = None
                    await self.send(build("WHOIS", [new_nick]))

    async def cmd(self,
            who:     Hostmask,
            command: str,
            args:    str):

        opername = await self._get_oper(who.nickname)
        if opername is not None:
            opername = None if opername == "<grant>" else opername
            attrib  = f"cmd_{command}"
            if hasattr(self, attrib):
                func = getattr(self, attrib)
                outs: List[str] = []
                try:
                    outs.extend(await func(opername, str(who), args))
                except UsageError as e:
                    outs.append(str(e))
                    for usage in func._usage:
                        outs.append(f"usage: {command.upper()} {usage}")

                for out in outs:
                    await self.send(build("NOTICE", [who.nickname, out]))
            else:
                await self.send(build("NOTICE", [who.nickname, f"\x02{command.upper()}\x02 is not a valid command"]))

    def _mask_format(self,
            mask_id: int,
            mask:    str,
            details: str
            ) -> str:

        last_hit = ""
        if details.last_hit is not None:
            last_hit = to_pretty_time(int(time()-details.last_hit))
            last_hit = f", last hit {last_hit} ago"

        return (
            f"{str(mask_id).rjust(3)}:"
            f" \x02{mask}\x02"
            f" ({details.hits} hits{last_hit})"
            f" \x02{details.type.name}\x02"
            f" [{details.reason or ''}]"
        )

    @usage("<mask-id>")
    async def cmd_getmask(self, oper: Optional[str], nick: str, sargs: str):
        args = sargs.split(None, 1)
        if not args:
            raise UsageError("please provide a mask id")
        elif not args[0].isdigit():
            raise UsageError("that's not an id/number")

        mask_id = int(args[0])
        if not await self._database.masks.has_id(mask_id):
            return [f"unknown mask id {mask_id}"]
        mask, d = await self._database.masks.get(mask_id)
        history = await self._database.masks.history(mask_id)

        outs = [self._mask_format(mask_id, mask, d)]
        if history:
            outs.append("\x02changes:\x02")
            for who_nick, who_oper, ts, change in history:
                if who_oper is not None:
                    who = f"{who_nick} ({who_oper})"
                else:
                    who = f"{who_nick}"
                tss = datetime.utcfromtimestamp(ts).isoformat()
                outs.append(
                    f" {tss}"
                    f" by \x02{who}\x02:"
                    f" {change}"
                )
        return outs

    @usage("/<regex>/ <public reason>[|<oper reason>]")
    @usage('"<string>" <public reason>[|<oper reason>]')
    async def cmd_addmask(self, oper: Optional[str], nick: str, args: str):
        try:
            mask, args   = mask_token(args)
            if not args:
                raise UsageError("please provide a mask reason")
            cmask, flags = mask_compile(mask)
        except ValueError as e:
            raise UsageError(f"syntax error: {str(e)}")
        except re.error as e:
            return [f"regex compilation error: {str(e)}"]

        reason = args
        # if there's no explicit oper reason, assume this
        # is an oper reason. safer than assuming public.
        if not "|" in reason:
            reason = f"|{reason}"

        mask_id = await self._database.masks.add(nick, oper, mask, reason)
        self._compiled_masks[mask_id] = (cmask, flags)

        # check/warn about how many users this will hit
        matches = 0
        samples = 0
        for i in range(MAX_RECENT):
            if i == len(self._recent_masks):
                break
            samples += 1
            recent_masks, uflags = self._recent_masks[i]
            for recent_mask in recent_masks:
                nflags = flags - uflags
                if not nflags and cmask.search(recent_mask):
                    matches += 1
                    # only breaks one level of `for`
                    break

        return [
            f"added {mask_id} "
            f"(hits {matches} out of last {samples} users)"
        ]

    @usage("<mask-id>")
    async def cmd_togglemask(self, oper: Optional[str], nick: str, sargs: str):
        args = sargs.split(None, 1)
        if not args:
            raise UsageError("please provide a mask id")
        elif not args[0].isdigit():
            raise UsageError("that's not an id/number")

        mask_id = int(args[0])
        if not await self._database.masks.has_id(mask_id):
            return [f"unknown mask id {mask_id}"]

        mask, d   = await self._database.masks.get(mask_id)
        enabled   = await self._database.masks.toggle(nick, oper, mask_id)
        enabled_s = "enabled" if enabled else "disabled"

        if enabled:
            cmask, flags = mask_compile(mask)
            self._compiled_masks[mask_id] = (cmask, flags)
            self._compiled_masks = OrderedDict(
                sorted(self._compiled_masks.items())
            )
        else:
            del self._compiled_masks[mask_id]

        if oper is not None:
            who = f"{nick} ({oper})"
        else:
            who = f"{nick}"

        out = (
            f"{who} TOGGLEMASK: {enabled_s}"
            f" {d.type.name} mask \x02{mask}\x02"
        )
        await self.send(build("PRIVMSG", [self._config.channel, out]))
        return [f"{d.type.name} mask {mask_id} {enabled_s}"]

    @usage("<id> <type>")
    async def cmd_setmask(self, oper: Optional[str], nick: str, sargs: str):
        args   = sargs.split()
        mtypes = {m.name for m in MaskType}
        if len(args) < 2:
            raise UsageError("not enough params")
        elif not args[0].isdigit():
            raise UsageError("that's not an id/number")
        elif not args[1].upper() in mtypes:
            return [f"mask type must be one of {mtypes!r}"]

        mask_id   = int(args[0])
        mask_type = MaskType[args[1].upper()]
        if not await self._database.masks.has_id(mask_id):
            return [f"unknown mask id {mask_id}"]

        mask, d = await self._database.masks.get(mask_id)
        if d.type == mask_type:
            return [f"{mask} is already {mask_type.name}"]
        if oper is not None:
            who = f"{nick} ({oper})"
        else:
            who = f"{nick}"
        await self._database.masks.set_type(nick, oper, mask_id, mask_type)

        log = f"{who} SETMASK: type {mask_type.name} \x02{mask}\x02 (was {d.type.name})"
        await self.send(build("PRIVMSG", [self._config.channel, log]))

        return [f"{mask} changed from {d.type.name} to {mask_type.name}"]

    async def cmd_listmask(self, oper: Optional[str], nick: str, args: str):
        outs: List[str] = []
        for mask_id, _ in self._compiled_masks.items():
            mask, d = await self._database.masks.get(mask_id)
            outs.append(self._mask_format(mask_id, mask, d))

        outs.append(f"{len(outs)} active masks")
        return outs

    @usage("<alias> <text ...>")
    async def cmd_addreason(self, oper: Optional[str], nick: str, args: str):
        args = args.split(None, 1)
        if len(args) < 2:
            raise UsageError("not enough params")

        alias = args[0].lower()
        if await self._database.reasons.has_key(alias):
            return [f"reason alias \x02${alias}\x02 already exists"]

        await self._database.reasons.add(alias, args[1])
        self._reasons[alias] = args[1]
        return [f"added reason alias \x02${alias}\x02"]

    @usage("<alias>")
    async def cmd_delreason(self, oper: Optional[str], nick: str, args: str):
        args = args.split(1)
        if len(args) < 1:
            raise UsageError("not enough params")

        alias = args[0].lower()
        if await self._database.reasons.has_key(alias):
            await self._database.reasons.delete(alias)
            del self._reasons[alias]
            return [f"deleted reason alias \x02${alias}\x02"]
        else:
            return [f"the reason alias \x02${alias}\x02 does not exist"]

    async def cmd_listreason(self, oper: Optional[str], nick: str, args: str):
        args = args.split()
        outs: List[str] = []
        for key, value in self._reasons.items():
            outs.append(f"\x02${key}\x02: {value}")
        return outs or ["no reason aliases"]

    @usage("/<pattern>/")
    async def cmd_testmask(self, oper: Optional[str], nick: str, args: str):
        try:
            mask, args   = mask_token(args)
            cmask, flags = mask_compile(mask)
        except ValueError as e:
            raise UsageError(f"syntax error: {str(e)}")
        except re.error as e:
            return [f"regex compilation error: {str(e)}"]

        max = 10
        if args.strip() == "-all":
            max = MAX_RECENT

        samples = 0
        matches: List[str] = []
        for i in range(MAX_RECENT):
            if i == len(self._recent_masks):
                break
            samples += 1
            recent_masks, uflags = self._recent_masks[i]
            for recent_mask in recent_masks:
                nflags = flags - uflags
                if not nflags and cmask.search(recent_mask):
                    matches.append(recent_mask)
                    # only breaks one level of `for`
                    break

        outs: List[str] = []
        for match in matches[:max]:
            outs.append(f" {match}")

        if outs:
            outs.insert(0, f"mask \x02{mask}\x02 matches...")
            if len(matches) > max:
                outs.append(f" (and {len(matches)-max} more)")
            outs.append(f"... out of {samples}")
        else:
            outs.insert(0, f"mask \x02{mask}\x02 matches 0 out of {samples}")
        return outs

    def line_preread(self, line: Line):
        print(f"< {line.format()}")
    def line_presend(self, line: Line):
        print(f"> {line.format()}")

class Bot(BaseBot):
    def __init__(self, config: Config):
        super().__init__()
        self._config = config

    def create_server(self, name: str):
        return Server(self, name, self._config)
