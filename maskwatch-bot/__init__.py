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

from .common   import MaskType, User, mask_compile, mask_find
from .config   import Config
from .database import Database

# not in ircstates yet...
RPL_RSACHALLENGE2      = "740"
RPL_ENDOFRSACHALLENGE2 = "741"
RPL_YOUREOPER          = "381"

RE_CLICONN = re.compile(r"^\*{3} Notice -- Client connecting: (?P<nick>\S+) .(?P<user>[^!]+)@(?P<host>\S+). .(?P<ip>[^]]+). \S+ .(?P<real>.+).$")
RE_CLIEXIT = re.compile(r"^\*{3} Notice -- Client exiting: (?P<nick>\S+) ")
RE_CLINICK = re.compile(r"^\*{3} Notice -- Nick change: From (?P<old>\S+) to (?P<new>\S+) .*$")

class Server(BaseServer):
    def __init__(self,
            bot:    BaseBot,
            name:   str,
            config: Config):

        super().__init__(bot, name)
        self._config  = config
        self._database = Database(config.database)

        self._users:          Dict[str, User] = {}
        self._compiled_masks: TOrderedDict[int, Pattern] = OrderedDict()

        self.delayed_send: Deque[Tuple[int, str]] = deque()

        self.to_check:      Deque[Tuple[float, str, User]] = deque()
        self.to_check_nick: Dict[str, int] = {}

    def set_throttle(self, rate: int, time: float):
        # turn off throttling
        pass

    async def _oper_up(self,
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

    async def _mask_match(self,
            nick: str,
            user: User
            ) -> Optional[int]:

        references = [f"{nick}!{user.user}@{user.host} {user.real}"]
        if (user.ip is not None and
                not user.host == user.ip):
            references.append(f"{nick}!{user.user}@{user.ip} {user.real}")

        for mask_id, pattern in self._compiled_masks.items():
            for ref in references:
                if pattern.search(ref):
                    return mask_id

    async def mask_check(self,
            nick: str,
            user: User):

        mask_id = await self._mask_match(nick, user)
        if mask_id is not None:
            _, d = await self._database.masks.get(mask_id)

            ident  = user.user
            if ident.startswith("~"):
                ident = "*"

            reason = d.reason.lstrip()
            if reason.startswith("$"):
                reason, sep, oreason = reason.partition("|")
                reason_name = reason.rstrip()[1:]
                if not reason_name in self._config.reasons:
                    raise ValueError(
                        f"unrecognised reason alias {reason_name}"
                    )

                reason  = self._config.reasons[reason_name]
                reason += sep + oreason

            ban = f"KLINE 1440 {ident}@{user.ip} :{reason}"
            if d.type == MaskType.LETHAL:
                await self.send_raw(ban)
            elif d.type == MaskType.DLETHAL:
                self.delayed_send.append((monotonic(), ban))

            await self._database.masks.hit(mask_id)
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
            for mask_id, mask in await self._database.masks.list_enabled():
                cmask = mask_compile(mask)
                self._compiled_masks[mask_id] = cmask

            await self.send(build("MODE", [self.nickname, "+g"]))
            oper_name, oper_file, oper_pass = self._config.oper
            await self._oper_up(oper_name, oper_file, oper_pass)

        elif line.command == RPL_YOUREOPER:
            # F far cliconn
            # c near cliconn
            # n nick changes
            await self.send(build("MODE", [self.nickname, "-s+s", "+Fcn"]))

        elif (line.command == "NOTICE" and
                line.params[0] == "*" and
                line.source is not None and
                not "!" in line.source):

            # snote!

            p_cliconn = RE_CLICONN.search(line.params[1])
            p_cliexit = RE_CLIEXIT.search(line.params[1])
            p_clinick = RE_CLINICK.search(line.params[1])

            if p_cliconn is not None:
                nick = p_cliconn.group("nick")
                user = p_cliconn.group("user")
                host = p_cliconn.group("host")
                real = p_cliconn.group("real")
                ip: Optional[str] = p_cliconn.group("ip")

                if ip == "0":
                    ip = None

                user = User(user, host, real, ip)
                self._users[nick] = user

                self.to_check.append((monotonic(), nick, user))
                self.to_check_nick[nick] = len(self.to_check)-1

            elif p_cliexit is not None:
                nick = p_cliexit.group("nick")
                if nick in self._users:
                    del self._users[nick]

                if nick in self.to_check_nick:
                    idx = self.to_check_nick.pop(nick)
                    ts, _, user = self.to_check[idx]
                    self.to_check[idx] = (-1, nick, user)

            elif p_clinick is not None:
                old_nick = p_clinick.group("old")
                new_nick = p_clinick.group("new")

                if old_nick in self._users:
                    user = self._users.pop(old_nick)
                    self._users[new_nick] = user
                if old_nick in self.to_check_nick:
                    idx = self.to_check_nick.pop(old_nick)
                    _1, _2, user = self.to_check[idx]

                    self.to_check.append((monotonic(), new_nick, user))
                    self.to_check_nick[new_nick] = len(self.to_check)-1

        elif (line.command == "PRIVMSG" and
                not self.is_me(line.hostmask.nickname) and
                self.is_me(line.params[0])):

            # private message

            out = f"[PV] <{line.source}> {line.params[1]}"
            await self.send(build("PRIVMSG", [self._config.channel, out]))

            cmd, _, args = line.params[1].partition(" ")
            await self.cmd(line.hostmask.nickname, cmd.lower(), args)

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
                    cmask = mask_compile(mask)
                except re.error as e:
                    return [f"regex error: {str(e)}"]
                else:
                    reason = args[end:].strip()
                    if reason:
                        mask_id = await self._database.masks.add(
                            nick, mask, reason
                        )
                        self._compiled_masks[mask_id] = cmask
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
                    mask, _ = await self._database.masks.get(mask_id)
                    cmask   = mask_compile(mask)
                    self._compiled_masks[mask_id] = cmask
                    self._compiled_masks = OrderedDict(
                        sorted(self._compiled_masks.items())
                    )
                else:
                    del self._compiled_masks[mask_id]

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
