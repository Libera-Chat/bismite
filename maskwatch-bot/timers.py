import asyncio, re, time
from datetime import datetime
from time     import monotonic
from typing   import List, Optional, Tuple

from irctokens import build
from ircrobots import Bot, Server

from ircstates.numerics import *
from ircrobots.matching import ANY, Folded, Response, SELF

from .database import Database

SEND_DELAY = 10.0

async def delayed_send(bot: Bot):
    start = monotonic()

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
