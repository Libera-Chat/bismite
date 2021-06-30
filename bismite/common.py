import re
from dataclasses import dataclass
from enum        import Enum, IntEnum
from typing      import Pattern, Optional, Set, Tuple

from ircrobots.formatting import strip as format_strip

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


FLAGS_INCONSEQUENTIAL = set("i")
def mask_compile(
        mask:  str
        ) -> Tuple[Pattern, Set[str]]:

    delimiter    = mask[0]
    mask, sflags = mask.rsplit(delimiter, 1)

    rflags = 0
    if "i" in sflags:
        rflags |= re.I

    flags  = set(sflags)
    flags -= FLAGS_INCONSEQUENTIAL

    # flags should be expressed as "only match x" rather than "also match x"
    # "N" means "also match nick changes" but "n" means "only match connect"
    # so if we have no "N", we add "n"
    if not "N" in flags:
        flags.add("n")
    else:
        flags.remove("N")

    mask = mask[1:]
    if delimiter in {"\"", "'"}:
        mask = re.escape(mask)

    return re.compile(mask, rflags), flags

def _find_unescaped(s: str, c: str):
    i = 1
    while i < len(s):
        c2 = s[i]
        i += 1
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
        raise ValueError("no pattern delimiter found")

def mask_token(
        input: str
        ) -> Tuple[Pattern, Set[str], str]:

    input = input.lstrip()
    if not input:
        raise ValueError("no input provided")

    end = mask_find(input)
    if end < 1:
        raise ValueError("unterminated regexen")

    mask = format_strip(input[:end])
    return mask, input[end+1:]

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

