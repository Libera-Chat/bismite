import re
from dataclasses import dataclass
from enum        import Enum, IntEnum
from typing      import Pattern, Optional, Set, Tuple

@dataclass
class User(object):
    user: str
    host: str
    real: str
    ip: Optional[str]
    account: Optional[str] = None

    connected: bool = True

class MaskType(IntEnum):
    WARN    = 1
    LETHAL  = 2
    DLETHAL = 3
    EXCLUDE = 4

    def __contains__(self, name: str):
        return name in {"WARN", "LETHAL", "DLETHAL", "EXCLUDE"}

class Event(Enum):
    CONNECT = 1
    NICK    = 2

@dataclass
class MaskDetails(object):
    type:     MaskType
    enabled:  bool
    reason:   Optional[str]
    hits:     int
    last_hit: Optional[int]


FLAGS_INCONEQUENTIAL = set("i")
def mask_compile(
        pattern: str
        ) -> Tuple[Pattern, Set[str]]:
    p, sflags = pattern.rsplit(pattern[0], 1)
    pattern   = p[1:]

    rflags = 0
    if not "N" in sflags:
        # only match if N not in sflags
        sflags.add("n")

    if "i" in sflags:
        rflags |= re.I

    return re.compile(pattern, rflags), set(sflags)

def _find_unescaped(s: str, c: str):
    i = 0
    while i < len(s):
        i += 1
        c2 = s[i]
        if c2 == "\\":
            i += 1
        elif c2 == c:
            return i
    else:
        return -1

def mask_find(s: str):
    start = s[0]
    if not start.isalnum():
        end = _find_unescaped(s, start)
        if end == -1:
            return end
        else:
            end = s.find(" ", end)
            if end == -1:
                return len(s)
            else:
                return end
    else:
        raise ValueError("pattern delim not found")

SECONDS_MINUTES = 60
SECONDS_HOURS   = SECONDS_MINUTES*60
SECONDS_DAYS    = SECONDS_HOURS*24
SECONDS_WEEKS   = SECONDS_DAYS*7

def to_pretty_time(total_seconds: int) -> str:
    weeks, days      = divmod(total_seconds, SECONDS_WEEKS)
    days, hours      = divmod(days, SECONDS_DAYS)
    hours, minutes   = divmod(hours, SECONDS_HOURS)
    minutes, seconds = divmod(minutes, SECONDS_MINUTES)

    units = list(filter(
        lambda u: u[0] > 0,
        [
            (weeks,   "w"),
            (days,    "d"),
            (hours,   "h"),
            (minutes, "m"),
            (seconds, "s")
        ]
    ))
    out = ""
    for i, unit in units[:2]:
        out += f"{i}{unit}"
    return out

