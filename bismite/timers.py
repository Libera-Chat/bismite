import asyncio, re
from datetime import datetime
from time     import monotonic, time
from typing   import List, Optional, Tuple

from irctokens import build
from ircrobots import Bot, Server

from ircstates.numerics import *
from ircrobots.matching import ANY, Folded, Response, SELF

from .common   import Event, mtype_getaction, mtype_tostring, MaskAction
from .database import Database

SEND_DELAY = 10.0

async def delayed_send(bot: Bot):
    while True:
        now  = monotonic()
        next = SEND_DELAY - (now%SEND_DELAY)
        await asyncio.sleep(next)
        now += next

        if bot.servers:
            server = list(bot.servers.values())[0]
            while server.delayed_send:
                when, sline = server.delayed_send[0]
                if now-when >= SEND_DELAY:
                    server.delayed_send.popleft()
                    await server.send_raw(sline)
                else:
                    break

async def delayed_check(
        bot:   Bot,
        delay: int=3):

    while True:
        now  = monotonic()
        wait = 0.1

        if bot.servers:
            server = list(bot.servers.values())[0]
            while server.to_check:
                ts, nick, user = server.to_check[0]
                due = ts+delay

                if due <= now:
                    server.to_check.popleft()
                    if user.connected:
                        await server.mask_check(nick, user, Event.CONNECT)
                else:
                    wait = due-now
                    break

        await asyncio.sleep(wait)

async def expire_masks(
        bot: Bot,
        db:  Database):

    while True:
        now  = int(time())
        wait = 60.0

        if not bot.servers:
            await asyncio.sleep(wait)
            continue

        server = list(bot.servers.values())[0]
        source = f"{server.nickname}!{server.username}@{server.hostname}"
        for mask_id in list(server.active_masks.keys()):
            mask, details = await db.masks.get(mask_id)

            if details.expire is None:
                # no expiry
                continue
            elif details.expire < 0:
                # expire relative to last hit time
                expire = details.last_hit + abs(details.expire)
            else:
                expire = details.expire

            if expire > now:
                # not yet expired
                wait = min(wait, expire-now)
                continue

            # has expired
            mtype_action = mtype_getaction(details.type)
            mtype_str    = mtype_tostring(details.type)
            if mtype_action in {MaskAction.KILL, MaskAction.LETHAL}:
                # downgrade to WARN
                await db.masks.set_type(source, '', mask_id, MaskAction.WARN)
                await server.report(
                    f"MASK:EXPIRE: \x02{mask}\x02 {mtype_str} -> WARN"
                )
            else:
                # downgrade to disabled
                await db.masks.set_expire(None)
                await db.masks.toggle(source, '', mask_id)
                del server.active_masks[mask_id]
                await server.report(
                    f"MASK:EXPIRE: \x02{mask}\x02 {mtype_str}"
                )

        await asyncio.sleep(wait)
