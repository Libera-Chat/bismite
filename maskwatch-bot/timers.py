import asyncio, re, time
from datetime import datetime
from time     import monotonic
from typing   import List, Optional, Tuple

from irctokens import build
from ircrobots import Bot, Server

from ircstates.numerics import *
from ircrobots.matching import ANY, Folded, Response, SELF

from .common   import Event
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
