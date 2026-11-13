"""Removes secrets from text before it is written anywhere.

Three layers, applied in this order (T-DATA-1 in ``docs/threat_model.md``):

1. **Known values.** A secret that Potato has loaded, such as the market data
   API key, is registered here and removed wherever it appears. This is the
   strongest layer because it does not depend on what the secret looks like.
2. **Known shapes.** Private key blocks, ``Authorization`` headers, bearer
   tokens and passwords inside web addresses.
3. **Known names.** A value that follows a name such as ``password`` or
   ``api_key`` is removed, whatever the value is.

Limits, stated plainly: a secret that was never registered, has no telltale
shape and sits next to no telltale name will not be recognised. Redaction is
a safety net. The first defence is not to pass secrets to the logger at all.
"""

import itertools
import math
import re
import threading
from collections.abc import Mapping
from typing import Final
from urllib.parse import quote, quote_plus

REDACTED: Final = "[REDACTED]"

# Shorter "secrets" would match ordinary words and shred the logs.
MIN_SECRET_LENGTH: Final = 8

# Nesting beyond this is replaced, which also stops self-referencing data.
_MAX_DEPTH: Final = 6

_SECRET_WORDS: Final = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "secrets",
        "token",
        "apikey",
        "authorization",
        "credential",
        "credentials",
    }
)
_SECRET_PAIRS: Final = frozenset(
    {("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"), ("auth", "key")}
)

# Splits "apiKey", "API_KEY", "x-api-key" and "accessToken2" into words.
_NAME_WORD: Final = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

_PRIVATE_KEY: Final = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*)",
    flags=re.DOTALL,
)
_AUTHORIZATION: Final = re.compile(r"(authorization[\"']?\s*[=:]\s*)[^\r\n]+", flags=re.IGNORECASE)
# Sixteen characters or more: long enough to skip "bearer of bad news".
_BEARER: Final = re.compile(r"\b(bearer)\s+[A-Za-z0-9._~+/=-]{16,}", flags=re.IGNORECASE)
_URL_PASSWORD: Final = re.compile(
    r"(?<![a-z0-9+.-])([a-z][a-z0-9+.-]*://[^/\s:@]*):[^@\s/]+@", flags=re.IGNORECASE
)
# name = value, name: value, "name": "value", ?name=value&...
# The name and the value are matched separately. If one pattern swallowed
# both, "https://host/?token=abc" would be read as the name "https" with the
# rest as its value, and the token inside would never be looked at.
# The lookbehind and the possessive ``++`` make the pattern try each name
# once, so a long run of letters cannot make it slow.
_NAME_AND_SEPARATOR: Final = re.compile(r"""(?<![\w.-])(?P<name>[\w.-]++)["']?\s*[=:]\s*""")
_VALUE: Final = re.compile(r""""[^"]*+"|'[^']*+'|[^\s&,;"'}\])]++""")


def is_secret_name(name: str) -> bool:
    """Say whether a setting, field or header name suggests a secret value.

    Args:
        name: For example ``api_key``, ``X-Api-Key``, ``accessToken``.

    Returns:
        ``True`` if the value that goes with this name should be hidden.
    """
    words = [word.lower() for word in _NAME_WORD.findall(name)]
    if any(word in _SECRET_WORDS for word in words):
        return True
    return any(pair in _SECRET_PAIRS for pair in itertools.pairwise(words))


def _hide_named_values(text: str) -> str:
    """Replace every value that follows a secret-looking name."""
    pieces = []
    position = 0
    for match in _NAME_AND_SEPARATOR.finditer(text):
        if match.start() < position or not is_secret_name(match["name"]):
            continue
        value = _VALUE.match(text, match.end())
        # Leave alone what an earlier layer has already replaced.
        if value is None or value[0].startswith("[REDACTED"):
            continue
        pieces.append(text[position : match.end()])
        pieces.append(REDACTED)
        position = value.end()
    pieces.append(text[position:])
    return "".join(pieces)


class Redactor:
    """Removes registered secrets and secret-shaped text. Safe to share between threads."""

    def __init__(self) -> None:
        """Create a redactor that knows no secret values yet."""
        self._lock = threading.Lock()
        self._secrets: tuple[str, ...] = ()

    def register_secret(self, secret: str) -> None:
        """Remember a secret value so that it is removed wherever it appears.

        Call this as soon as a secret is loaded, before anything can log it.

        Args:
            secret: The exact secret value.

        Raises:
            ValueError: The value is not text, or is too short to redact
                without also removing ordinary words. The message does not
                contain the value.
        """
        if type(secret) is not str or len(secret) < MIN_SECRET_LENGTH:
            raise ValueError(f"a secret must be text of at least {MIN_SECRET_LENGTH} characters")
        # The same secret as it appears inside a web address.
        forms = {secret, quote(secret, safe=""), quote_plus(secret)}
        with self._lock:
            # Longest first, so a secret that contains another is removed whole.
            self._secrets = tuple(sorted({*self._secrets, *forms}, key=len, reverse=True))

    def redact(self, text: str) -> str:
        """Return ``text`` with every recognised secret replaced.

        Args:
            text: Any text about to be logged, stored or shown.

        Returns:
            The text with secrets replaced by ``[REDACTED]``.
        """
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
        text = _AUTHORIZATION.sub(rf"\1{REDACTED}", text)
        text = _BEARER.sub(rf"\1 {REDACTED}", text)
        text = _URL_PASSWORD.sub(rf"\1:{REDACTED}@", text)
        return _hide_named_values(text)

    def redact_value(self, value: object, _depth: int = 0) -> object:
        """Return a copy of structured data that is safe to write as JSON.

        Text is redacted. A value stored under a secret-looking name is
        replaced whatever it is. Anything that is not plain data is replaced
        by its type name, because its text form is unknown and could contain
        anything.

        Args:
            value: Text, a number, ``True``/``False``/``None``, or a mapping,
                list or tuple of these.

        Returns:
            Data made only of dictionaries, lists, text, numbers,
            ``True``/``False`` and ``None``.
        """
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, float):
            # Infinity and not-a-number are not valid JSON.
            return value if math.isfinite(value) else str(value)
        if _depth >= _MAX_DEPTH:
            return "[TOO DEEPLY NESTED]"
        if isinstance(value, Mapping):
            cleaned: dict[str, object] = {}
            for key, item in value.items():
                if isinstance(key, str):
                    hidden = is_secret_name(key)
                    name = self.redact(key)
                else:
                    hidden = False
                    name = str(key) if isinstance(key, int) else f"<{type(key).__name__}>"
                cleaned[name] = REDACTED if hidden else self.redact_value(item, _depth + 1)
            return cleaned
        if isinstance(value, (list, tuple)):
            return [self.redact_value(item, _depth + 1) for item in value]
        return f"<{type(value).__name__}>"
