"""Validated application settings.

Settings are frozen dataclasses that check every value when they are created.
An invalid ``Settings`` object therefore cannot exist anywhere in the program,
whether its values came from a file or were written in code.

Security properties, with the threats they answer in ``docs/threat_model.md``:

* **The Ollama address is loopback-only** (T-NET-3, T-LLM-6). The host must be
  an IP address literal on the loopback interface. Host names are refused,
  including ``localhost``, because a name is resolved by something outside
  this program's control. The settings take a host and a port, never a URL,
  so there is no URL to be parsed in a surprising way.
* **Allowlists are code** (T-DATA-6, rule R7). The permitted model names are a
  constant in this file. A settings file can choose among them and cannot add
  to them.
* **Settings can only move within fixed bounds** (T-DATA-6). Every number has
  a minimum and a maximum.
* **Error messages never repeat the rejected value**, so nothing a user typed
  into the wrong field ends up in a log (T-DATA-1).

This module only parses text. Reading the file from disk is done by
``potato.storage.settings_file``.
"""

import ipaddress
import math
import re
import tomllib
from dataclasses import dataclass, field, fields
from typing import Any, Final

# Model names Potato will ask Ollama for. Adding one is a code change, reviewed
# like any other. Cloud-hosted models must never appear here.
ALLOWED_MODELS: Final[frozenset[str]] = frozenset({"qwen3:8b"})

# Larger than any sensible settings file; small enough to parse instantly.
MAX_SETTINGS_CHARACTERS: Final = 64 * 1024

# Ports below 1024 need administrator rights, which Potato never uses.
_PORT_RANGE: Final = (1024, 65535)
_REQUEST_TIMEOUT_RANGE: Final = (1.0, 300.0)
_CONTEXT_LENGTH_RANGE: Final = (2048, 32768)
_IDLE_TIMEOUT_RANGE: Final = (30.0, 3600.0)
_APPROVAL_LIFETIME_RANGE: Final = (5.0, 120.0)

# Where the TOML parser says a syntax error is. Digits only, so safe to repeat.
_POSITION: Final = re.compile(r"line \d+, column \d+")


class ConfigError(ValueError):
    """A setting is missing, of the wrong type or outside its allowed range."""


def _require_integer(name: str, value: object, bounds: tuple[int, int]) -> None:
    """Reject anything that is not a whole number within ``bounds``."""
    low, high = bounds
    # True and False are integers in Python, so they are excluded by name.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be a whole number")
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}")


def _require_number(name: str, value: object, bounds: tuple[float, float]) -> None:
    """Reject anything that is not a finite number within ``bounds``."""
    low, high = bounds
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be a number")
    # TOML can express infinity and not-a-number; neither is a usable setting.
    if not math.isfinite(value) or not low <= value <= high:
        raise ConfigError(f"{name} must be between {low:g} and {high:g}")


def _require_loopback_address(name: str, value: object) -> None:
    """Reject anything that is not a loopback IP address in its standard form.

    The order of the checks matters. Each one closes a specific way of writing
    an address that looks local but is not, or that different software would
    read differently.
    """
    problem = ConfigError(f"{name} must be a loopback IP address such as 127.0.0.1 or ::1")

    # The ipaddress module also accepts integers and raw bytes. 2130706433 is
    # 127.0.0.1 written as a number; only text is accepted here.
    if type(value) is not str:
        raise problem

    # Refuses host names, URLs, ports, brackets, whitespace, non-ASCII digits
    # and shortened or octal-looking forms such as "127.1" and "0177.0.0.1".
    # The parser's own error quotes the value, so it is dropped, not chained.
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is None:
        raise problem

    # "::1%en0" names a network interface. "::ffff:127.0.0.1" is an IPv4
    # address in IPv6 clothing, and Python versions disagree about whether it
    # counts as loopback. Neither form is needed, so both are refused.
    if isinstance(address, ipaddress.IPv6Address) and (
        address.scope_id is not None or address.ipv4_mapped is not None
    ):
        raise problem

    if not address.is_loopback:
        raise problem

    # One spelling per address: "0:0:0:0:0:0:0:1" must be written "::1".
    if str(address) != value:
        raise problem


@dataclass(frozen=True, slots=True)
class OllamaSettings:
    """How Potato reaches the local model.

    Attributes:
        host: Loopback IP address Ollama listens on.
        port: TCP port Ollama listens on.
        model: Name of the model to use. Must be in ``ALLOWED_MODELS``.
        request_timeout_seconds: Longest Potato waits for one response.
        context_length: Context window, in tokens, requested from Ollama.
    """

    host: str = "127.0.0.1"
    port: int = 11434
    model: str = "qwen3:8b"
    request_timeout_seconds: float = 60.0
    context_length: int = 8192

    def __post_init__(self) -> None:
        """Validate every field."""
        _require_loopback_address("ollama.host", self.host)
        _require_integer("ollama.port", self.port, _PORT_RANGE)
        if type(self.model) is not str or self.model not in ALLOWED_MODELS:
            allowed = ", ".join(sorted(ALLOWED_MODELS))
            raise ConfigError(f"ollama.model must be one of: {allowed}")
        _require_number(
            "ollama.request_timeout_seconds", self.request_timeout_seconds, _REQUEST_TIMEOUT_RANGE
        )
        _require_integer("ollama.context_length", self.context_length, _CONTEXT_LENGTH_RANGE)

    @property
    def base_url(self) -> str:
        """Address of the Ollama API, built only from validated parts."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"


@dataclass(frozen=True, slots=True)
class AssistantSettings:
    """How the assistant behaves over time.

    Attributes:
        idle_timeout_seconds: Time without interaction before Potato returns
            to standby and unloads the model.
    """

    idle_timeout_seconds: float = 300.0

    def __post_init__(self) -> None:
        """Validate every field."""
        _require_number(
            "assistant.idle_timeout_seconds", self.idle_timeout_seconds, _IDLE_TIMEOUT_RANGE
        )


@dataclass(frozen=True, slots=True)
class SecuritySettings:
    """Adjustable security parameters. Each can only move within fixed bounds.

    Attributes:
        approval_lifetime_seconds: How long a physical approval stays valid.
    """

    approval_lifetime_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Validate every field."""
        _require_number(
            "security.approval_lifetime_seconds",
            self.approval_lifetime_seconds,
            _APPROVAL_LIFETIME_RANGE,
        )


@dataclass(frozen=True, slots=True)
class Settings:
    """All of Potato's settings. The defaults are safe to run with."""

    ollama: OllamaSettings = field(default_factory=OllamaSettings)
    assistant: AssistantSettings = field(default_factory=AssistantSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)

    def __post_init__(self) -> None:
        """Refuse sections that are not the validated classes."""
        for name, expected in _SECTIONS.items():
            if type(getattr(self, name)) is not expected:
                raise ConfigError(f"{name} settings must be created by {expected.__name__}")


_SECTIONS: Final[dict[str, type[OllamaSettings | AssistantSettings | SecuritySettings]]] = {
    "ollama": OllamaSettings,
    "assistant": AssistantSettings,
    "security": SecuritySettings,
}


def _parse_toml(text: str) -> dict[str, Any]:
    """Parse TOML, turning every parser failure into a ``ConfigError``.

    The error is raised after the ``except`` blocks have finished, so the
    parser's own exception is not attached to it. Newer Python versions keep
    the whole document on that exception; only the position is passed on.
    """
    if len(text) > MAX_SETTINGS_CHARACTERS:
        raise ConfigError("the settings file is too large")

    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        position = _POSITION.search(str(error))
        where = f" ({position.group(0)})" if position else ""
        failure = f"the settings file is not valid TOML{where}"
    except RecursionError:
        # Thousands of nested brackets exhaust the parser's stack.
        failure = "the settings file is nested too deeply"
    raise ConfigError(failure)


def parse_settings(text: str) -> Settings:
    """Build validated settings from the text of a TOML settings file.

    Anything the text does not mention keeps its default. Unknown sections and
    unknown settings are errors, not ignored: a misspelt setting that silently
    did nothing would leave the user believing it had taken effect.

    Args:
        text: Contents of a settings file. An empty string gives the defaults.

    Returns:
        The validated settings.

    Raises:
        ConfigError: The text is not valid TOML, or a section or value is not
            allowed.
    """
    document = _parse_toml(text)

    if set(document) - set(_SECTIONS):
        allowed = ", ".join(_SECTIONS)
        raise ConfigError(f"unknown section in the settings file; allowed sections: {allowed}")

    sections: dict[str, Any] = {}
    for name, section_class in _SECTIONS.items():
        table = document.get(name, {})
        if not isinstance(table, dict):
            raise ConfigError(f"[{name}] must be a table of settings")
        known = [setting.name for setting in fields(section_class)]
        if set(table) - set(known):
            allowed = ", ".join(known)
            raise ConfigError(f"unknown setting in [{name}]; allowed settings: {allowed}")
        sections[name] = section_class(**table)
    return Settings(**sections)
