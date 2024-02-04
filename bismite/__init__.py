import asyncio, random, re, traceback
from collections import deque, OrderedDict
from dataclasses import dataclass
from datetime    import datetime
from heapq       import heappush
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

from .common   import Event, MaskAction, MaskModifier, User
from .common   import (mask_compile, mask_find, mask_token, mtype_weight,
    mtype_tostring, mtype_fromstring, mtype_getaction)
from .common   import from_pretty_time, to_pretty_time

# not in ircstates yet...
RPL_RSACHALLENGE2      = "740"
RPL_ENDOFRSACHALLENGE2 = "741"
RPL_WHOISOPERATOR      = "313"
RPL_YOUREOPER          = "381"

RE_OPERNAME = re.compile(r"^is opered as (\S+)(?:,|$)")

@dataclass
class Caller(object):
    source: str
    nick:   str
    oper:   str

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
            bot:      BaseBot,
            name:     str,
            config:   Config,
            database: Database):

        super().__init__(bot, name)
        self._config   = config
        self._database = database

        self._users:          Dict[str, User] = {}
        self._recent_masks:   Deque[List[str]] = deque()
        self.active_masks:    TOrderedDict[int, Pattern] = OrderedDict()
        self._reasons:        Dict[str, str] = {}

        self.delayed_send: List[Tuple[int, str]] = []

        self.to_check: Deque[Tuple[float, str, User]] = deque()
        self._nick_change_whois: Deque[Tuple[str, bool]] = deque() # nick, should_check

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
        # sort keys by length backwards
        # "$user_reason" will match $user if we don't
        fkeys   = sorted(formats.keys(), key=len, reverse=True)

        # expand reason templates
        for i in range(10):
            changed = False
            for key in fkeys:
                fkey = f"${key}"
                if fkey in string:
                    changed = True
                    string = string.replace(fkey, formats[key])
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

        uflags = "".join([
            "0" if user.account is None   else "1",
            "0" if not user.secure        else "1",
            "0" if event == Event.CONNECT else "1",
            "\n"
        ])

        ni = nick
        us = user.user
        ho = user.host
        ip = user.ip
        re = user.real

        references = [f"{uflags}{ni}!{us}@{ho} {re}"]
        if user.ip is not None and not user.host == user.ip:
            # if the user has an IP and IP != host, also match against IP
            references.append(f"{uflags}{ni}!{us}@{ip} {re}")

        self._recent_masks.append(references)
        if len(self._recent_masks) > self._config.history:
            self._recent_masks.popleft()

        matches: List[int] = []
        for mask_id, pattern in self.active_masks.items():
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
            # this should order: exclude, lethal, kill, resv, warn
            matches.sort(
                key=lambda m: mtype_weight(m[1][1].type),
                reverse=True
            )

            mask_id, (mask, d) = matches[0]
            mtype_action       = mtype_getaction(d.type)

            user_reason, _, oper_reason = d.reason.partition("|")

            # computed "optimal" values for user@host k-line mask
            ban_user = user.user
            if ban_user.startswith("~"):
                ban_user = "*"
            ban_host = user.host
            if user.ip is not None:
                ban_host = user.ip

            info = {
                "mask_id":     str(mask_id),
                "nick":        nick,
                "user":        user.user,
                "host":        user.host,
                "ip":          user.ip,

                "ban_user":    ban_user,
                "ban_host":    ban_host,
                "ban_time":    str(randint(160, 320)),

                "reason":      d.reason,
                "user_reason": user_reason,
                "oper_reason": oper_reason
            }

            action: Optional[str] = None
            if   mtype_action == MaskAction.LETHAL:
                action = self._format(self._config.bancmd, info)
            elif mtype_action == MaskAction.KILL:
                action = f"KILL {nick} :{user_reason}"
            elif mtype_action == MaskAction.RESV:
                action = f"RESV 60 {nick} ON * :bismite mask {mask_id}"

            if action is None:
                pass
            elif d.type & MaskModifier.DELAY:
                when = monotonic()
                if d.type & MaskModifier.QUICK:
                    when += 3
                else:
                    when += random.uniform(1,10)

                heappush(self.delayed_send, (when, action))
            else:
                await self.send_raw(action)

            mtype_str = mtype_tostring(d.type)
            output = (f"MASK: {mtype_str} mask {mask_id} "
                f"{nick}!{user.user}@{user.host} {user.real}"
                f" [{oper_reason}]")
            if (mtype_action == MaskAction.EXCLUDE and
                    len(types) == 1):
                # we matched an EXCLUDE but no other types.
                # do not log
                pass
            elif d.type & MaskModifier.QUIET:
                await self._verbose(output)
            elif not d.type & MaskModifier.SILENT:
                await self._verbose(output)
                if not self._config.channel == self._config.verbose:
                    await self.report(output)

    async def _report(self, channel: str, message: str):
        await self.send(build("PRIVMSG", [channel, message]))
    async def report(self, message: str):
        await self._report(self._config.channel, message)
    async def _verbose(self, message: str):
        await self._report(self._config.verbose, message)

    async def line_read(self, line: Line):
        if line.command == RPL_WELCOME:
            self.active_masks.clear()
            self._reasons.clear()
            # load and compile all masks/reason templates
            for mask_id, mask in await self._database.masks.list_enabled():
                self.active_masks[mask_id] = mask_compile(mask)

            for key, value in await self._database.reasons.list():
                self._reasons[key] = value

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
                    self._nick_change_whois[0][0] == nick):

                should_check = self._nick_change_whois[0][1]
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

                    if should_check:
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

                    # if the new nickname is a UID (because they were resv'd or collided),
                    # it is not necessary to check them
                    # only checking for a number in the first part of the nick is ok here
                    # because a nick cannot normally be this way except in the conditions mentioned above
                    # ~launchd 7/7/2022
                    should_check = not new_nick[0].isdigit()

                    # refresh what we think this user's account is
                    # and trigger a check if needed
                    self._nick_change_whois.append((new_nick, should_check))
                    user.account = None
                    await self.send(build("WHOIS", [new_nick]))

    async def cmd(self,
            hostmask: Hostmask,
            command:  str,
            args:     str):

        opername = await self._get_oper(hostmask.nickname)
        if opername is not None:
            attrib  = f"cmd_{command}"
            if hasattr(self, attrib):
                caller = Caller(str(hostmask), hostmask.nickname, opername)
                func   = getattr(self, attrib)
                outs: List[str] = []
                try:
                    outs.extend(await func(caller, args))
                except UsageError as e:
                    outs.append(str(e))
                    for usage in func._usage:
                        outs.append(f"usage: {command.upper()} {usage}")

                for out in outs:
                    await self.send(build("NOTICE", [hostmask.nickname, out]))
            else:
                err = f"\x02{command.upper()}\x02 is not a valid command"
                await self.send(build("NOTICE", [hostmask.nickname, err]))

    def _mask_format(self,
            mask_id: int,
            mask:    str,
            details: str
            ) -> str:

        last_hit = ""
        if details.hits > 0:
            last_hit = to_pretty_time(int(time()-details.last_hit))
            last_hit = f", last hit {last_hit} ago"

        mtype_str = mtype_tostring(details.type)
        return (
            f"{str(mask_id).rjust(3)}:"
            f" \x02{mask}\x02"
            f" ({details.hits} hits{last_hit})"
            f" \x02{mtype_str}\x02"
            f" [{details.reason or ''}]"
        )

    @usage("<mask-id>")
    async def cmd_getmask(self,
            caller: Caller,
            sargs:  str
            ) -> List[str]:

        args = sargs.split(None, 2)
        if not args:
            raise UsageError("please provide a mask id")
        elif not args[0].isdigit():
            raise UsageError("that's not an id/number")

        mask_id = int(args[0])
        if not await self._database.masks.has_id(mask_id):
            return [f"unknown mask id {mask_id}"]
        mask, d = await self._database.masks.get(mask_id)
        changes = await self._database.changes.get(mask_id)

        outs = [
            self._mask_format(mask_id, mask, d),
            "\x02changes:\x02"
        ]

        change_max = len(changes) if "-all" in args else 10
        for who_nick, who_oper, ts, change in changes[-change_max:]:
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
    @usage('%<glob>% <public reason>[|<oper reason>]')
    async def cmd_addmask(self,
            caller: Caller,
            args:   str
            ) -> List[str]:

        try:
            mask, args = mask_token(args)
            cmask      = mask_compile(mask)
        except ValueError as e:
            raise UsageError(f"syntax error: {str(e)}")
        except re.error as e:
            return [f"regex compilation error: {str(e)}"]

        if not args:
            raise UsageError("please provide a mask reason")

        reason = args
        mask_id = await self._database.masks.add(mask, reason)
        await self._database.changes.add(
            mask_id, caller.source, caller.oper, "add"
        )
        self.active_masks[mask_id] = cmask

        # check/warn about how many users this will hit
        matches = 0
        samples = 0
        for i in range(self._config.history):
            if i == len(self._recent_masks):
                break
            samples += 1
            recent_masks = self._recent_masks[i]
            for recent_mask in recent_masks:
                if cmask.search(recent_mask):
                    matches += 1
                    # only breaks one level of `for`
                    break

        return [
            f"added {mask_id} "
            f"(hits {matches} out of last {samples} users)"
        ]

    @usage("<mask-id>")
    async def cmd_togglemask(self,
            caller: Caller,
            sargs:  str
            ) -> List[str]:

        args = sargs.split(None, 1)
        if not args:
            raise UsageError("please provide a mask id")
        elif not args[0].isdigit():
            raise UsageError("that's not an id/number")

        mask_id = int(args[0])
        if not await self._database.masks.has_id(mask_id):
            return [f"unknown mask id {mask_id}"]

        mask, d   = await self._database.masks.get(mask_id)
        enabled   = await self._database.masks.toggle(mask_id)
        enabled_s = "enabled" if enabled else "disabled"
        await self._database.changes.add(
            mask_id, caller.source, caller.oper, enabled_s
        )

        if enabled:
            self.active_masks[mask_id] = mask_compile(mask)
            self.active_masks = OrderedDict(
                sorted(self.active_masks.items())
            )
        else:
            del self.active_masks[mask_id]

        mtype_str = mtype_tostring(d.type)
        who = f"{caller.nick} ({caller.oper})"
        out = (
            f"{who} TOGGLEMASK: {enabled_s}"
            f" {mtype_str} mask \x02{mask}\x02"
        )
        await self.send(build("PRIVMSG", [self._config.channel, out]))
        return [f"{mtype_str} mask {mask_id} {enabled_s}"]

    @usage("<id> <type>")
    async def cmd_setmask(self,
            caller: Caller,
            sargs:  str
            ) -> List[str]:

        args = sargs.split()
        if len(args) < 2:
            raise UsageError("not enough params")
        elif not args[0].isdigit():
            raise UsageError("that's not an id/number")

        mask_id = int(args[0])
        if not await self._database.masks.has_id(mask_id):
            return [f"unknown mask id {mask_id}"]

        mask, d = await self._database.masks.get(mask_id)

        outs: List[str] = []

        if args[1][0] in {"~", "+"}:
            timespec = args.pop(1)
            relative = timespec == "+"
            expire   = from_pretty_time(timespec[1:])

            if expire:
                if relative:
                    expire = -expire
                else:
                    expire = int(time()) + expire

                await self._database.masks.set_expire(mask_id, expire)
                await self._database.changes.add(
                    mask_id, caller.source, caller.oper, f"expire {timespec}"
                )
                outs.append(f"{mask} expiry set to {timespec}")
            else:
                raise UsageError("expiry must be in format +1w2d/~1w2d")

        if not args[1:]:
            return outs

        try:
            mtype = mtype_fromstring(args[1])
        except ValueError as e:
            raise UsageError(str(e))

        mtype_str = mtype_tostring(mtype)
        if d.type == mtype:
            return [f"{mask} is already \2{mtype_str}\2"]

        await self._database.masks.set_type(mask_id, mtype)
        await self._database.changes.add(
            mask_id, caller.source, caller.oper, f"type {mtype_str}"
        )

        # *p*revious mtype_str
        pmtype_str = mtype_tostring(d.type)
        who = f"{caller.nick} ({caller.oper})"
        log = f"{who} SETMASK: type {mtype_str} \x02{mask}\x02 (was {pmtype_str})"
        await self.send(build("PRIVMSG", [self._config.channel, log]))

        out = f"{mask} changed from \2{pmtype_str}\2 to \2{mtype_str}\2"
        outs.insert(0, out)
        return outs

    async def cmd_listmask(self,
            caller: Caller,
            sargs:  str
            ) -> List[str]:

        outs: List[str] = []
        for mask_id, _ in self.active_masks.items():
            mask, d = await self._database.masks.get(mask_id)
            outs.append(self._mask_format(mask_id, mask, d))

        outs.append(f"{len(outs)} active masks")
        return outs

    @usage("<alias> <text ...>")
    async def cmd_addreason(self,
            caller: Caller,
            sargs:  str
            ) -> List[str]:

        args = sargs.split(None, 1)
        if len(args) < 2:
            raise UsageError("not enough params")

        alias = args[0].lower()
        if await self._database.reasons.has_key(alias):
            return [f"reason alias \x02${alias}\x02 already exists"]

        await self._database.reasons.add(alias, args[1])
        self._reasons[alias] = args[1]
        return [f"added reason alias \x02${alias}\x02"]

    @usage("<alias>")
    async def cmd_delreason(self,
            caller: Caller,
            sargs:  str
            ) -> List[str]:

        args = sargs.split(None, 1)
        if len(args) < 1:
            raise UsageError("not enough params")

        alias = args[0].lower()
        if await self._database.reasons.has_key(alias):
            await self._database.reasons.delete(alias)
            del self._reasons[alias]
            return [f"deleted reason alias \x02${alias}\x02"]
        else:
            return [f"the reason alias \x02${alias}\x02 does not exist"]

    async def cmd_listreason(self,
            caller: Caller,
            args:   str
            ) -> List[str]:

        args = args.split()
        outs: List[str] = []
        for key, value in self._reasons.items():
            outs.append(f"\x02${key}\x02: {value}")
        return outs or ["no reason aliases"]

    @usage("/<pattern>/")
    async def cmd_testmask(self,
            caller: Caller,
            args:   str
            ) -> List[str]:

        try:
            mask, args = mask_token(args)
            cmask      = mask_compile(mask)
        except ValueError as e:
            raise UsageError(f"syntax error: {str(e)}")
        except re.error as e:
            return [f"regex compilation error: {str(e)}"]

        max = 10
        if args.strip() == "-all":
            max = self._config.history

        samples = 0
        matches: List[str] = []
        for i in range(self._config.history):
            if i == len(self._recent_masks):
                break
            samples += 1
            recent_masks = self._recent_masks[i]
            for recent_mask in recent_masks:
                if cmask.search(recent_mask):
                    matches.append(recent_mask)
                    # only breaks one level of `for`
                    break

        outs: List[str] = []
        for match in matches[:max]:
            match = match.replace("\n", "#")
            outs.append(f" {match}")

        if outs:
            outs.insert(0, f"mask \x02{mask}\x02 matches...")
            if len(matches) > max:
                outs.append(f" (and {len(matches)-max} more)")
            outs.append(f"... out of {samples}")
        else:
            outs.insert(0, f"mask \x02{mask}\x02 matches 0 out of {samples}")
        return outs

    async def cmd_compilemask(self,
            caller: Caller,
            args:   str
            ) -> List[str]:

        try:
            mask, args = mask_token(args)
            cmask      = mask_compile(mask)
        except ValueError as e:
            raise UsageError(f"syntax error: {str(e)}")
        except re.error as e:
            return [f"regex compilation error: {str(e)}"]

        return [f"\x02{mask}\x02 compiles to: {cmask.pattern}"]

    def line_preread(self, line: Line):
        print(f"< {line.format()}")
    def line_presend(self, line: Line):
        print(f"> {line.format()}")

class Bot(BaseBot):
    def __init__(self,
            config:   Config,
            database: Database):
        super().__init__()
        self._config   = config
        self._database = database

    def create_server(self, name: str):
        return Server(self, name, self._config, self._database)
