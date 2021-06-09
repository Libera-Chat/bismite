import asyncio, re, traceback
from collections import deque, OrderedDict
from datetime    import datetime
from time        import monotonic
from typing      import Deque, Dict, List, Optional, Tuple
from typing      import OrderedDict as TOrderedDict


from irctokens import build, Line
from ircrobots import Bot as BaseBot
from ircrobots import Server as BaseServer

from ircstates.numerics   import *
from ircrobots.matching   import Response, ANY, Folded, SELF
from ircchallenge         import Challenge
from ircrobots.formatting import strip as format_strip

from .common   import Event, MaskType, User, mask_compile, mask_find
from .config   import Config
from .database import Database

# not in ircstates yet...
RPL_RSACHALLENGE2      = "740"
RPL_ENDOFRSACHALLENGE2 = "741"
RPL_YOUREOPER          = "381"

class Server(BaseServer):
    def __init__(self,
            bot:    BaseBot,
            name:   str,
            config: Config):

        super().__init__(bot, name)
        self._config  = config
        self._database = Database(config.database)

        self._users:          Dict[str, User] = {}
        self._compiled_masks: TOrderedDict[int, Tuple[Pattern, str]] \
            = OrderedDict()
        self._reasons:        Dict[str, str] = {}

        self.delayed_send: Deque[Tuple[int, str]] = deque()

        self.to_check: Deque[Tuple[float, str, User, Event]] = deque()

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

    async def _is_oper(self, nickname: str):
        await self.send(build("WHOIS", [nickname]))

        whois_oper = Response(RPL_WHOISOPERATOR, [SELF, Folded(nickname)])
        whois_end  = Response(RPL_ENDOFWHOIS,    [SELF, Folded(nickname)])
        #:lithium.libera.chat 313 sandcat sandcat :is an IRC Operator
        #:lithium.libera.chat 318 sandcat sandcat :End of /WHOIS list.

        whois_line = await self.wait_for({
            whois_end, whois_oper
        })
        return whois_line.command == RPL_WHOISOPERATOR

    async def _format(self, string: str):
        # expand reason templates
        while "$" in string:
            for k, v in self._reasons.items():
                string = string.replace(f"${k}", v)
        return string.lstrip()

    async def _mask_match(self,
            nick:  str,
            user:  User,
            event: Event
            ) -> List[int]:

        references = [f"{nick}!{user.user}@{user.host} {user.real}"]
        if (user.ip is not None and
                not user.host == user.ip):
            # if the user has an IP and it doesn't match their visible 'host',
            # also match against that IP
            references.append(f"{nick}!{user.user}@{user.ip} {user.real}")

        matches: List[int] = []
        for mask_id, (pattern, flags) in self._compiled_masks.items():
            for ref in references:
                if ((not event == Event.NICK or "N" in flags) and
                        pattern.search(ref)):
                    matches.append(mask_id)
        return matches

    async def mask_check(self,
            nick:  str,
            user:  User,
            event: Event):

        match_ids = await self._mask_match(nick, user, event)
        if match_ids:
            for match_id in match_ids:
                await self._database.masks.hit(match_id)

            # get all (mask, details) for matched IDs
            matches = [await self._database.masks.get(i) for i in match_ids]

            # sort by mask type, descending
            # this should order: exclude, dlethal, lethal, warn
            matches.sort(key=lambda m: m[1].type, reverse=True)

            mask, d = matches[0]

            ident  = user.user
            # if the user doesn't have identd, bin the whole host
            if ident.startswith("~"):
                ident = "*"

            reason = d.reason.lstrip()
            # if the user-facing bit is `$thing`, see if `thing` is a known
            # reason alias

            # split off |oper reason
            reason, sep, oreason = reason.partition("|")
            reason  = await self._format(reason.rstrip())
            # reattach |oper reason
            reason += sep + oreason

            info = {
                "ident": ident,
                "user": user,
                "reason": reason
            }

            ban = self._config.bancmd.format(**info)
            if d.type == MaskType.LETHAL:
                await self.send_raw(ban)
            elif d.type == MaskType.DLETHAL:
                self.delayed_send.append((monotonic(), ban))

            await self.send(build("PRIVMSG", [
                self._config.channel,
                (
                    f"MASK: {d.type.name} mask {match_id} "
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

        elif (line.command == "PRIVMSG" and
                not self.is_me(line.hostmask.nickname) and
                self.is_me(line.params[0])):

            # private message

            out = f"[PV] <{line.source}> {line.params[1]}"
            await self.send(build("PRIVMSG", [self._config.channel, out]))

            cmd, _, args = line.params[1].partition(" ")
            await self.cmd(line.hostmask.nickname, cmd.lower(), args)

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

                self.to_check.append((monotonic(), nick, user, Event.CONNECT))

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

                    self.to_check.append(
                        (monotonic(), new_nick, user, Event.NICK)
                    )

    async def cmd(self,
            who:     str,
            command: str,
            args:    str):

        if await self._is_oper(who):
            attrib  = f"cmd_{command}"
            if hasattr(self, attrib):
                outs = await getattr(self, attrib)(who, args)
                for out in outs:
                    await self.send(build("NOTICE", [who, out]))
            else:
                await self.send(build("NOTICE", [who, f"\x02{command.upper()}\x02 is not a valid command"]))

    def _mask_format(self,
            mask_id: int,
            mask:    str,
            details: str
            ) -> str:
        return (
            f"{str(mask_id).rjust(3)}:"
            f" \x02{mask}\x02"
            f" ({details.hits} hits)"
            f" {details.type.name}"
            f" [{details.reason or ''}]"
        )

    async def cmd_getmask(self, nick: str, args: str):
        mask_id_s = args.split(None, 1)[0]
        if mask_id_s.isdigit():
            mask_id = int(mask_id_s)
            if await self._database.masks.has_id(mask_id):
                mask, d = await self._database.masks.get(mask_id)
                history = await self._database.masks.history(mask_id)

                outs = [self._mask_format(mask_id, mask, d)]
                if history:
                    outs.append("\x02changes:\x02")
                for who, ts, change in history:
                    tss = datetime.utcfromtimestamp(ts).isoformat()
                    outs.append(
                        f" {tss}"
                        f" by \x02{who}\x02:"
                        f" {change}"
                    )
                return outs
            else:
                return [f"unknown mask id {mask_id}"]
        elif mask_id:
            return ["that's not an id/number"]
        else:
            return ["please provide a mask id"]

    async def cmd_addmask(self, nick: str, args: str):
        args = args.lstrip()
        if args:
            end = mask_find(args)
            if end > 0:
                mask = format_strip(args[:end])
                try:
                    cmask, flags = mask_compile(mask)
                except re.error as e:
                    return [f"regex error: {str(e)}"]
                else:
                    reason = args[end:].strip()
                    if reason:
                        # if there's no explicit oper reason, assume this
                        # is an oper reason. safer than assuming public.
                        if not "|" in reason:
                            reason = f"|{reason}"

                        mask_id = await self._database.masks.add(
                            nick, mask, reason
                        )
                        self._compiled_masks[mask_id] = (cmask, flags)
                        return [f"added {mask_id}"]
                    else:
                        return ["please provide a reason"]
            else:
                return ["unterminated regexen"]
        else:
            return ["no args provided"]

    async def cmd_togglemask(self, nick: str, args: str):
        mask_id_s = args.split(None, 1)[0]
        if mask_id_s.isdigit():
            mask_id = int(mask_id_s)
            if await self._database.masks.has_id(mask_id):
                enabled   = await self._database.masks.toggle(nick, mask_id)
                enabled_s = "enabled" if enabled else "disabled"

                if enabled:
                    mask, _      = await self._database.masks.get(mask_id)
                    cmask, flags = mask_compile(mask)
                    self._compiled_masks[mask_id] = (cmask, flags)
                    self._compiled_masks = OrderedDict(
                        sorted(self._compiled_masks.items())
                    )
                else:
                    del self._compiled_masks[mask_id]

                log = f"{nick} TOGGLEMASK: {enabled_s} mask \x02#{mask_id}\x02"
                await self.send(build("PRIVMSG", [self._config.channel, log]))
                return [f"mask {mask_id} {enabled_s}"]
            else:
                return [f"unknown mask id {mask_id}"]
        elif mask_id:
            return ["that's not an id/number"]
        else:
            return ["please provide a mask id"]

    async def cmd_setmask(self, nick: str, sargs: str):
        args = sargs.split()
        if len(args) < 2:
            return ["not enough params"]
        elif not args[0].isdigit():
            return ["that's not an id/number"]
        elif args[1].upper() in MaskType:
            return [f"unknown mask type {args[1].upper()}"]
        else:
            mask_id   = int(args[0])
            mask_type = MaskType[args[1].upper()]
            if await self._database.masks.has_id(mask_id):
                mask, d = await self._database.masks.get(mask_id)
                if not d.type == mask_type:
                    await self._database.masks.set_type(
                        nick, mask_id, mask_type
                    )
                    log = f"{nick} SETMASK: type {mask_type.name} \x02{mask}\x02 (was {d.type.name})"
                    await self.send(build("PRIVMSG", [self._config.channel, log]))
                    return [
                        f"{mask} changed from "
                        f"{d.type.name} to {mask_type.name}"
                    ]
                else:
                    return [f"{mask} is already {mask_type.name}"]
            else:
                return [f"unknown mask id {mask_id}"]

    async def cmd_listmask(self, nick: str, args: str):
        outs: List[str] = []
        for mask_id, _ in self._compiled_masks.items():
            mask, d = await self._database.masks.get(mask_id)
            outs.append(self._mask_format(mask_id, mask, d))
        return outs or ["no masks"]

    async def cmd_addreason(self, nick: str, args: str):
        args = args.split()
        if len(args) < 2:
            return ["syntax: addreason <alias> <text>"]

        if await self._database.reasons.has_key(args[0].lower()):
            return [f"the reason \x02${args[0].lower()}\x02 already exists"]

        await self._database.reasons.add(args[0].lower(), " ".join(args[1:]))
        self._reasons[args[0].lower()] = " ".join(args[1:])
        return [f"added \x02${args[0].lower()}\x02"]

    async def cmd_delreason(self, nick: str, args: str):
        args = args.split()
        if len(args) < 1:
            return ["syntax: delreason <alias>"]

        if await self._database.reasons.has_key(args[0].lower()):
            await self._database.reasons.delete(args[0].lower())
            del self._reasons[args[0].lower()]
            return [f"deleted \x02${args[0].lower()}\x02"]
        else:
            return [f"the reason \x02${args[0].lower()}\x02 does not exist"]

    async def cmd_listreason(self, nick: str, args: str):
        args = args.split()
        outs: List[str] = []
        for key, value in self._reasons.items():
            outs.append(f"${key}: \x02{value}\x02")
        return outs or ["no reason templates"]

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
