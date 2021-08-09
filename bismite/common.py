import re
from dataclasses import dataclass
from enum        import Enum, IntEnum, IntFlag
from fnmatch     import translate as glob_translate
from typing      import Any, Dict, Pattern, Optional, Set, Tuple

from ircrobots.formatting import strip as format_strip

@dataclass
class User(object):
    user: str
    host: str
    real: str
    ip: Optional[str]
    account: Optional[str] = None
    secure: bool = False

    connected: bool = True

class MaskAction(IntEnum):
    KILL    = 0
    WARN    = 1
    LETHAL  = 2
    EXCLUDE = 4
class MaskModifier(IntFlag):
    NONE   = 0
    DELAY  = 0b001 << 4
    SILENT = 0b010 << 4

def mtype_getaction(
        mtype: int
        ) -> MaskAction:
    action = mtype & 0xf # get lowest 4 bits
    return MaskAction(action)

def mtype_fromstring(mstr: str) -> int:
    actions_available = {a.name for a in MaskAction}
    action, *modifiers = mstr.upper().split("|")
    if action in actions_available:
        mtype = MaskAction[action]
    else:
        raise ValueError(f"unknown mask action \2{action}\2")

    modifiers_available = {m.name for m in MaskModifier}
    for modifier in modifiers:
        if modifier in modifiers_available:
            mtype |= MaskModifier[modifier]
        else:
            raise ValueError(f"unknown mask modifier \2{modifier}\2")
    return mtype

def mtype_tostring(mtype: int) -> str:
    action = mtype_getaction(mtype)
    parts: List[str] = [action.name]

    if mtype & MaskModifier.DELAY:
        parts.append("DELAY")
    if mtype & MaskModifier.SILENT:
        parts.append("SILENT")
    return "|".join(parts)

MASK_SORT = [
    MaskAction.WARN,
    MaskAction.KILL,
    MaskAction.LETHAL,
    MaskAction.EXCLUDE
]
def mtype_weight(mtype: int) -> int:
    # split action and modifiers
    action    = mtype_getaction(mtype)
    modifiers = mtype>>4
    # get maximum modifier bit count so we know how far left
    # we need to bitshift `action`
    modifier_offset  = max(MaskModifier).value.bit_length()
    # swap order of modifier|action so instead of
    # NONE|LETHAL, DELAY|LETHAL, NONE|EXCLUDE
    # we'd have
    # LETHAL|NONE, LETHAL|DELAY, EXCLUDE|NONE
    # and rewrite action by MASK_SORT weight so it'll sort as
    # EXCLUDE|NONE, LETHAL|DELAY, LETHAL|NONE
    return (MASK_SORT.index(action)<<modifier_offset) + modifiers

class Event(Enum):
    CONNECT = 1
    NICK    = 2

def _unescape(input: str, char: str):
    i   = 0
    out = ""

    while i < len(input):
        input_char = input[i]
        if (input_char == "\\"
                and input[i+1] == char):
            out += char
            i   += 2
        else:
            out += input_char
            i   += 1
    return out

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

def _maskflag_match(
        flags:   Set[str],
        options: Dict[str, str],
        ) -> str:

    available = set(options.keys())&flags
    if available:
        return options[list(available)[0]]
    else:
        return options[""]

def mask_compile(mask: str) -> Pattern:
    delim       = mask[0]
    mask_end    = _find_unescaped(mask, delim)
    mask, flags = mask[1:mask_end-1], set(mask[mask_end:])

    if not mask:
        # empty string
        raise ValueError("empty mask provided")

    if delim in {"\"", "'"}:
        # string literal
        mask = _unescape(mask, delim)
        mask = re.escape(mask)
        if "^" in flags:
            mask = f"^{mask}"
        if "$" in flags:
            mask = f"{mask}$"
    elif delim == "%": # what's a better char?
        # glob
        mask = glob_translate(mask)
        mask = fr"\A{mask}"

    # we somewhat abuse re.MULTILINE so we can match arbitrary characteristics
    # about users by putting flags before their `nick!user@host real`
    # e.g. a user connecting with a no account using tls would be:
    #   "010\nnick!user@host real"
    # then we'd take a mask like /^jess-test!/A and turn it in to
    #   re.compile(r"0.0\n.*^jess-test!", re.MULTILINE)
    # re.MULTLINE means the ^ in the mask is still valid, but we were able to
    # insert a secondary matching criteria before the mask with its own ^.

    mask = "".join([
        "^",
        _maskflag_match(flags, {'': ".", "A": "0", "a": "1"}),
        _maskflag_match(flags, {'': ".", "Z": "0", "z": "1"}),
        _maskflag_match(flags, {'': "0", "N": "."}),
        r"\n.*"
    ]) + mask

    re_flags = re.MULTILINE
    if "i" in flags:
        re_flags |= re.IGNORECASE

    return re.compile(mask, re_flags)

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

RE_PRETTYTIME = re.compile("^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?$")
def from_pretty_time(s: str) -> Optional[int]:
    match = RE_PRETTYTIME.search(s)
    if match and match.group(0):
        seconds  = 0
        seconds += int(match.group(1) or "0") * SECONDS_WEEKS
        seconds += int(match.group(2) or "0") * SECONDS_DAYS
        seconds += int(match.group(3) or "0") * SECONDS_HOURS
        seconds += int(match.group(4) or "0") * SECONDS_MINUTES
        return seconds
    else:
        return None
