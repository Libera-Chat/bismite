import asyncio
from argparse import ArgumentParser

from ircrobots import ConnectionParams, SASLUserPass

from .         import Bot
from .config   import Config, load as config_load
from .database import Database
from .timers   import delayed_send, delayed_check, expire_masks

async def main(config: Config):
    db  = Database(config.database)
    bot = Bot(config, db)

    sasl_user, sasl_pass = config.sasl

    params = ConnectionParams.from_hoststring(config.nickname, config.server)
    config.username = config.username,
    config.realname = config.realname,
    config.password = config.password,
    config.sasl = SASLUserPass(sasl_user, sasl_pass),
    config.autojoin = [config.channel, config.verbose]

    await bot.add_server("irc", params)
    await asyncio.wait([
        asyncio.create_task(delayed_send(bot)),
        asyncio.create_task(delayed_check(bot)),
        asyncio.create_task(expire_masks(bot, db)),
        asyncio.create_task(bot.run())
    ])

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("config")
    args   = parser.parse_args()

    config = config_load(args.config)
    asyncio.run(main(config))
