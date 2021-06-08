from dataclasses import dataclass
from enum        import Enum
from time        import time
from typing      import Dict, List, Optional, Tuple
import aiosqlite

from .common import MaskDetails, MaskType

# schema, also in make-database.sql
#
# masks:
#   id:       autoincrement
#   mask:     str not null
#   type:     int not null
#   enabled:  bool not null
#   reason:   str
#   hits:     int not null
#   last_hit: int
# primary key id
#
# changes:
#   mask_id: int not null
#   by:      str not null
#   time:    int not null
#   change:  str not null

class Table(object):
    def __init__(self, db_location: str):
        self._db_location = db_location

class Masks(Table):
    async def add(self,
            by:     str,
            mask:   str,
            reason: Optional[str]):

        async with aiosqlite.connect(self._db_location) as db:
            await db.execute("""
                INSERT INTO masks (mask, type, enabled, reason, hits)
                VALUES (?, ?, 1, ?, 0)
            """, [mask, MaskType.WARN.value, reason])
            await db.commit()

            cursor = await db.execute("""
                SELECT id
                FROM masks
                ORDER BY id DESC
                LIMIT 1
            """)
            mask_id = (await cursor.fetchone())[0]

            await db.execute("""
                INSERT INTO changes (mask_id, by, time, change)
                VALUES (?, ?, ?, ?)
            """, [mask_id, by, int(time()), 'add'])
            await db.commit()

            return mask_id

    async def has_id(self, mask_id: int) -> bool:
        async with aiosqlite.connect(self._db_location) as db:
            cursor = await db.execute("""
                SELECT 1
                FROM masks
                WHERE id=?
            """, [mask_id])
            return bool(await cursor.fetchall())

    async def get(self,
            mask_id: int
            ) -> Tuple[str, MaskDetails]:

        async with aiosqlite.connect(self._db_location) as db:
            cursor = await db.execute("""
                SELECT mask, type, enabled, reason, hits, last_hit
                FROM masks
                WHERE id=?
            """, [mask_id])

            row = await cursor.fetchone()
            mask, type, enabled, reason, hits, last_hit = row
            details = MaskDetails(
                MaskType(type),
                enabled,
                reason,
                hits,
                last_hit
            )
            return (mask, details)

    async def toggle(self,
            by:      str,
            mask_id: int
            ) -> bool:

        async with aiosqlite.connect(self._db_location) as db:
            cursor = await db.execute("""
                SELECT enabled
                FROM masks
                WHERE id=?
            """, [mask_id])
            enabled = bool((await cursor.fetchone())[0])
            enabled = not enabled

            await db.execute("""
                UPDATE masks
                SET enabled=?
                WHERE id=?
            """, [enabled, mask_id])
            await db.execute("""
                INSERT INTO changes (mask_id, by, time, change)
                VALUES (?, ?, ?, ?)
            """, [mask_id, by, int(time()), f'enabled {enabled}'])
            await db.commit()

            return enabled

    async def set_type(self,
            by:        str,
            mask_id:   int,
            mask_type: MaskType):
        async with aiosqlite.connect(self._db_location) as db:
            await db.execute("""
                UPDATE masks
                SET type=?
                WHERE id=?
            """, [mask_type.value, mask_id])
            await db.execute("""
                INSERT INTO changes (mask_id, by, time, change)
                VALUES (?, ?, ?, ?)
            """, [mask_id, by, int(time()), f'type {mask_type.name}'])
            await db.commit()

    async def hit(self, mask_id: int):
        async with aiosqlite.connect(self._db_location) as db:
            cursor = await db.execute("""
                SELECT hits
                FROM masks
                WHERE id=?
            """, [mask_id])
            hits = (await cursor.fetchone())[0]
            await db.execute("""
                UPDATE masks
                SET hits=?,last_hit=?
                WHERE id=?
            """, [hits+1, int(time()), mask_id])
            await db.commit()

    async def list_enabled(self
            ) -> List[Tuple[int, str]]:
        async with aiosqlite.connect(self._db_location) as db:
            cursor = await db.execute("""
                SELECT id, mask
                FROM masks
                WHERE enabled = 1
                ORDER BY id ASC
            """)
            return await cursor.fetchall()

    async def history(self,
            mask_id: int
            ) -> List[Tuple[str, int, str]]:
        async with aiosqlite.connect(self._db_location) as db:
            cursor = await db.execute("""
                SELECT by, time, change
                FROM changes
                WHERE mask_id=?
                ORDER BY time
            """, [mask_id])
            return await cursor.fetchall()

class Reasons(Table):
    async def add(self,
            key:   str,
            value: str):

        async with aiosqlite.connect(self._db_location) as db:
            await db.execute("""
                INSERT INTO reasons (key, value)
                VALUES (?, ?)
            """, [key, value])
            await db.commit()

    async def has_key(self, key: str) -> bool:
        async with aiosqlite.connect(self._db_location) as db:
            cursor = await db.execute("""
                SELECT 1
                FROM reasons
                WHERE key=?
            """, [key])
            return bool(await cursor.fetchall())

    async def list(self
            ) -> List[Tuple[str, str]]:
        async with aiosqlite.connect(self._db_location) as db:
            cursor = await db.execute("""
                SELECT key, value
                FROM reasons
            """)
            return await cursor.fetchall()

    async def delete(self, key:str):
        async with aiosqlite.connect(self._db_location) as db:
            cursor = await db.execute("""
                DELETE
                FROM reasons
                WHERE key=?
            """, [key])
            await db.commit()

class Database(object):
    def __init__(self, location: str):
        self.masks   = Masks(location)
        self.reasons = Reasons(location)
