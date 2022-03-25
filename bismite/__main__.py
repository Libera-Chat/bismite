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

    host, port, tls      = config.server
    sasl_user, sasl_pass = config.sasl

    params = ConnectionParams(
        config.nickname,
        host,
        port,
        tls,
        username=config.username,
        realname=config.realname,
        password=config.password,
        sasl=SASLUserPass(sasl_user, sasl_pass),
        autojoin=[config.channel, config.verbose]
    )
    await bot.add_server(host, params)
    await asyncio.wait([
        delayed_send(bot),
        delayed_check(bot),
        expire_masks(bot, db),
        bot.run()
    ])

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("config")
    args   = parser.parse_args()

    config = config_load(args.config)
    asyncio.run(main(config))
