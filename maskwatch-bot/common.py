import re
from dataclasses import dataclass
from enum        import Enum
from typing      import Pattern, Optional

@dataclass
class User(object):
    user: str
    host: str
    real: str
    ip:   str

class MaskType(Enum):
    LETHAL  = 1
    WARN    = 2
    DLETHAL = 3

    def __contains__(self, name: str):
        return name in {"LETHAL", "WARN", "DLETHAL"}

@dataclass
class MaskDetails(object):
    type:     MaskType
    enabled:  bool
    reason:   Optional[str]
    hits:     int
    last_hit: Optional[int]


def mask_compile(pattern: str) -> Pattern:
    p, sflags = pattern.rsplit(pattern[0], 1)
    pattern   = p[1:]

    flags = 0
    if "i" in sflags:
        flags |= re.I

    return re.compile(pattern, flags)
