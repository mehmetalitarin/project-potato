"""Making untrusted text safe to show on screen.

The model's replies, and anything it repeats from tools, are untrusted. Qt
shows plain text faithfully, which includes characters that are invisible or
that reverse the order of what follows (the Trojan Source trick). Those could
make a reply look different from what it says. ``displayable`` replaces them
with a visible marker before anything is shown.
"""

import unicodedata
from typing import Final

MAX_DISPLAY_CHARACTERS: Final = 8000
MARKER: Final = "\ufffd"
CUT: Final = " [cut short]"

# Unicode categories that are never shown as they are: control characters,
# format characters (which include the direction overrides), private-use,
# surrogate and unassigned characters, and line or paragraph separators.
_HIDDEN_CATEGORIES: Final = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"})
_KEPT: Final = frozenset({"\n", "\t"})


def displayable(text: object, limit: int = MAX_DISPLAY_CHARACTERS) -> str:
    """Return ``text`` with hidden characters replaced and its length capped.

    Anything that is not a ``str`` becomes the empty string.
    """
    if not isinstance(text, str):
        return ""
    shown = "".join(
        character
        if character in _KEPT or unicodedata.category(character) not in _HIDDEN_CATEGORIES
        else MARKER
        for character in text[:limit]
    )
    if len(text) > limit:
        shown += CUT
    return shown
