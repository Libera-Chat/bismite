import re
from dataclasses import dataclass
from enum        import Enum
from typing      import Pattern, Optional, Tuple

@dataclass
class User(object):
    user: str
    host: str
    real: str
    ip: Optional[str]

    connected: bool = True

class MaskType(Enum):
    LETHAL  = 1
    WARN    = 2
    DLETHAL = 3

    def __contains__(self, name: str):
        return name in {"LETHAL", "WARN", "DLETHAL"}

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


def mask_compile(
        pattern: str
        ) -> Tuple[Pattern, str]:
    p, sflags = pattern.rsplit(pattern[0], 1)
    pattern   = p[1:]

    flags = 0
    if "i" in sflags:
        flags |= re.I

    return re.compile(pattern, flags), sflags

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
