"""Tests for the validated settings.

The most important group proves that the Ollama address can only ever be a
loopback address (threats T-NET-3 and T-LLM-6 in docs/threat_model.md). This
is item 10 of the specification's required security tests: "the Ollama
endpoint is not configured for network exposure".
"""

import dataclasses
import ipaddress
import random
import re
from typing import Any
from urllib.parse import urlsplit

import pytest

from potato.core.config import (
    ALLOWED_MODELS,
    MAX_SETTINGS_CHARACTERS,
    AssistantSettings,
    ConfigError,
    OllamaSettings,
    SecuritySettings,
    Settings,
    parse_settings,
)

# --- Defaults -----------------------------------------------------------------


def test_defaults_are_valid_and_local() -> None:
    settings = Settings()

    assert settings.ollama.host == "127.0.0.1"
    assert settings.ollama.port == 11434
    assert settings.ollama.model in ALLOWED_MODELS
    assert settings.ollama.base_url == "http://127.0.0.1:11434"


def test_settings_cannot_be_changed_after_creation() -> None:
    settings = Settings()

    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.ollama.host = "0.0.0.0"  # type: ignore[misc]  # noqa: S104
    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.ollama = OllamaSettings()  # type: ignore[misc]


def test_sections_must_be_the_validated_classes() -> None:
    with pytest.raises(ConfigError, match="ollama"):
        Settings(ollama={"host": "0.0.0.0"})  # type: ignore[arg-type]  # noqa: S104


# --- The Ollama address is loopback-only (T-NET-3, T-LLM-6) -------------------

# 127.x.y.z with each part 0-255 and no leading zeros, written independently of
# the code under test.
_OCTET = r"(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])"
STANDARD_IPV4_LOOPBACK = re.compile(rf"127\.{_OCTET}\.{_OCTET}\.{_OCTET}")


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"])
def test_loopback_addresses_are_accepted(host: str) -> None:
    assert OllamaSettings(host=host).host == host


@pytest.mark.parametrize(
    "host",
    [
        # Every network interface: the classic way to expose a local service.
        "0.0.0.0",  # noqa: S104
        "::",
        # Other machines, private and public.
        "192.168.1.10",
        "10.0.0.1",
        "172.16.0.1",
        "169.254.1.1",
        "8.8.8.8",
        "fe80::1",
        "2001:db8::1",
        # Host names are resolved by something outside our control.
        "localhost",
        "LOCALHOST",
        "localhost.",
        "example.com",
        "127.0.0.1.example.com",
        "localhost.example.com",
        # Other spellings of 127.0.0.1 that some software accepts.
        "127.1",
        "127.0.1",
        "0x7f.0.0.1",
        "0x7f000001",
        "0177.0.0.1",
        "127.0.0.01",
        "2130706433",
        "\uff11\uff12\uff17.0.0.1",  # full-width digits
        "127\u30020\u30020\u30021",  # ideographic full stops
        # IPv4 dressed as IPv6; Python versions disagree on whether it is loopback.
        "::ffff:127.0.0.1",
        "::ffff:7f00:1",
        "::127.0.0.1",
        "64:ff9b::7f00:1",
        # IPv6 with a network interface attached, or not in its standard form.
        "::1%lo0",
        "::1%en0",
        "0:0:0:0:0:0:0:1",
        "0000:0000:0000:0000:0000:0000:0000:0001",
        "::0001",
        # More than a bare address.
        "127.0.0.1:11434",
        "[::1]",
        "[::1]:11434",
        "http://127.0.0.1",
        "http://127.0.0.1:11434",
        "127.0.0.1/8",
        "127.0.0.1/32",
        "user@127.0.0.1",
        "127.0.0.1@example.com",
        "127.0.0.1#example.com",
        "127.0.0.1?example.com",
        "127.0.0.1\\example.com",
        # Whitespace and control characters.
        " 127.0.0.1",
        "127.0.0.1 ",
        "127.0.0.1\n",
        "127.0.0.1\r\n",
        "127.0.0.1\t",
        "127.0.0.1\x00",
        "127.0.0.1\x00.example.com",
        "",
        " ",
    ],
)
def test_everything_else_is_rejected_as_a_host(host: str) -> None:
    with pytest.raises(ConfigError, match=r"ollama\.host must be a loopback IP address"):
        OllamaSettings(host=host)


@pytest.mark.parametrize(
    "host",
    [
        2130706433,  # 127.0.0.1 as an integer, which the ipaddress module accepts
        b"\x7f\x00\x00\x01",  # and as packed bytes
        ipaddress.ip_address("127.0.0.1"),
        ["127.0.0.1"],
        None,
        True,
        1.0,
    ],
)
def test_host_must_be_text(host: Any) -> None:
    with pytest.raises(ConfigError, match=r"ollama\.host"):
        OllamaSettings(host=host)


def test_any_accepted_host_is_a_plain_loopback_literal() -> None:
    # Take addresses, good and bad, and damage them at random: insert, delete
    # or replace a character. Whatever the check still accepts must match an
    # independent definition of "loopback address in standard form".
    generator = random.Random(20261113)  # noqa: S311 - not used for security
    seeds = ["127.0.0.1", "127.255.0.9", "::1", "0.0.0.0", "::", "::ffff:127.0.0.1", "1.2.3.4"]  # noqa: S104
    alphabet = "0123456789.:fx%[]/ @\n"
    accepted = set()

    for _ in range(30000):
        candidate = list(generator.choice(seeds))
        for _ in range(generator.randint(0, 3)):
            position = generator.randint(0, len(candidate))
            action = generator.choice(["insert", "delete", "replace"])
            if action == "insert":
                candidate.insert(position, generator.choice(alphabet))
            elif candidate and position < len(candidate):
                if action == "delete":
                    del candidate[position]
                else:
                    candidate[position] = generator.choice(alphabet)
        host = "".join(candidate)
        try:
            OllamaSettings(host=host)
        except ConfigError:
            continue
        accepted.add(host)

    assert len(accepted) > 50, "the generator should produce many valid addresses"
    for host in accepted:
        assert host == "::1" or STANDARD_IPV4_LOOPBACK.fullmatch(host), host


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1"])
def test_base_url_points_at_the_validated_host_and_nothing_else(host: str) -> None:
    parts = urlsplit(OllamaSettings(host=host, port=12345).base_url)

    assert parts.scheme == "http"
    assert parts.hostname == host
    assert parts.port == 12345
    assert parts.username is None
    assert parts.password is None
    assert parts.path == ""
    assert parts.query == ""
    assert parts.fragment == ""
    assert ipaddress.ip_address(parts.hostname).is_loopback


# --- The model allowlist (T-LLM-6, R7) ----------------------------------------


@pytest.mark.parametrize("model", sorted(ALLOWED_MODELS))
def test_allowlisted_models_are_accepted(model: str) -> None:
    assert OllamaSettings(model=model).model == model


@pytest.mark.parametrize(
    "model",
    [
        "qwen3:8b-cloud",
        "gpt-oss:120b-cloud",
        "qwen3",
        "qwen3:latest",
        "llama3",
        "QWEN3:8B",
        "qwen3:8b ",
        " qwen3:8b",
        "qwen3:8b\n",
        "",
        8,
        None,
        ["qwen3:8b"],
    ],
)
def test_models_off_the_allowlist_are_rejected(model: Any) -> None:
    with pytest.raises(ConfigError, match=r"ollama\.model must be one of"):
        OllamaSettings(model=model)


def test_no_allowlisted_model_is_a_cloud_model() -> None:
    assert not [model for model in ALLOWED_MODELS if "cloud" in model.lower()]


# --- Numbers stay inside fixed bounds (T-DATA-6) ------------------------------

INTEGER_FIELDS: list[tuple[type, str, float, float]] = [
    (OllamaSettings, "port", 1024, 65535),
    (OllamaSettings, "context_length", 2048, 32768),
]
NUMBER_FIELDS: list[tuple[type, str, float, float]] = [
    (OllamaSettings, "request_timeout_seconds", 1.0, 300.0),
    (AssistantSettings, "idle_timeout_seconds", 30.0, 3600.0),
    (SecuritySettings, "approval_lifetime_seconds", 5.0, 120.0),
]


def test_every_numeric_setting_is_covered_by_the_bounds_tests() -> None:
    covered = {(section, name) for section, name, _, _ in INTEGER_FIELDS + NUMBER_FIELDS}
    numeric = {
        (section, setting.name)
        for section in (OllamaSettings, AssistantSettings, SecuritySettings)
        for setting in dataclasses.fields(section)
        if setting.type in (int, float)
    }

    assert covered == numeric, "a numeric setting was added without bounds tests"


@pytest.mark.parametrize(("section", "name", "low", "high"), INTEGER_FIELDS + NUMBER_FIELDS)
def test_bounds_are_inclusive(section: type, name: str, low: float, high: float) -> None:
    assert getattr(section(**{name: low}), name) == low
    assert getattr(section(**{name: high}), name) == high


@pytest.mark.parametrize(("section", "name", "low", "high"), INTEGER_FIELDS)
@pytest.mark.parametrize("pick", ["below", "above", "zero", "negative"])
def test_integers_outside_bounds_are_rejected(
    section: type, name: str, low: float, high: float, pick: str
) -> None:
    value = {"below": int(low) - 1, "above": int(high) + 1, "zero": 0, "negative": -int(low)}[pick]

    with pytest.raises(ConfigError, match=f"{name} must be between"):
        section(**{name: value})


@pytest.mark.parametrize(("section", "name", "low", "high"), NUMBER_FIELDS)
@pytest.mark.parametrize("pick", ["below", "above", "zero", "negative", "inf", "-inf", "nan"])
def test_numbers_outside_bounds_are_rejected(
    section: type, name: str, low: float, high: float, pick: str
) -> None:
    value = {
        "below": low - 0.001,
        "above": high + 0.001,
        "zero": 0.0,
        "negative": -low,
        "inf": float("inf"),
        "-inf": float("-inf"),
        "nan": float("nan"),
    }[pick]

    with pytest.raises(ConfigError, match=f"{name} must be between"):
        section(**{name: value})


@pytest.mark.parametrize(("section", "name", "low", "high"), INTEGER_FIELDS)
@pytest.mark.parametrize("value", [True, False, "11434", 11434.0, None, [11434]])
def test_integer_settings_reject_other_types(
    section: type, name: str, low: float, high: float, value: Any
) -> None:
    with pytest.raises(ConfigError, match=f"{name} must be a whole number"):
        section(**{name: value})


@pytest.mark.parametrize(("section", "name", "low", "high"), NUMBER_FIELDS)
@pytest.mark.parametrize("value", [True, False, "60", None, [60.0], 60 + 0j])
def test_number_settings_reject_other_types(
    section: type, name: str, low: float, high: float, value: Any
) -> None:
    with pytest.raises(ConfigError, match=f"{name} must be a number"):
        section(**{name: value})


def test_whole_numbers_are_accepted_where_a_number_is_expected() -> None:
    assert OllamaSettings(request_timeout_seconds=90).request_timeout_seconds == 90


# --- Parsing a settings file --------------------------------------------------


def test_empty_text_gives_the_defaults() -> None:
    assert parse_settings("") == Settings()


def test_a_comment_only_file_gives_the_defaults() -> None:
    assert parse_settings("# nothing set\n") == Settings()


def test_a_file_overrides_only_what_it_mentions() -> None:
    settings = parse_settings(
        """
        [ollama]
        host = "::1"
        request_timeout_seconds = 120

        [security]
        approval_lifetime_seconds = 10.5
        """
    )

    assert settings.ollama.host == "::1"
    assert settings.ollama.base_url == "http://[::1]:11434"
    assert settings.ollama.request_timeout_seconds == 120
    assert settings.ollama.model == Settings().ollama.model
    assert settings.assistant == AssistantSettings()
    assert settings.security.approval_lifetime_seconds == 10.5


@pytest.mark.parametrize(
    "text",
    [
        '[ollama]\nhost = "0.0.0.0"',
        '[ollama]\nhost = "192.168.1.10"',
        '[ollama]\nhost = "localhost"',
        "[ollama]\nhost = 2130706433",
        '[ollama]\nmodel = "gpt-oss:120b-cloud"',
        "[ollama]\nport = 80",
        '[ollama]\nport = "11434"',
        "[ollama]\nport = true",
        "[ollama]\nrequest_timeout_seconds = inf",
        "[ollama]\nrequest_timeout_seconds = nan",
        "[ollama]\ncontext_length = 1e4",
        "[assistant]\nidle_timeout_seconds = 0",
        "[assistant]\nidle_timeout_seconds = 1979-05-27",
        "[security]\napproval_lifetime_seconds = 86400",
        "[security]\napproval_lifetime_seconds = [30]",
    ],
)
def test_a_file_cannot_set_a_disallowed_value(text: str) -> None:
    with pytest.raises(ConfigError):
        parse_settings(text)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[network]\nlisten = true", "unknown section"),
        ("top_level = 1", "unknown section"),
        ("[ollama]\nurl = 'http://example.com'", r"unknown setting in \[ollama\]"),
        ("[ollama]\nHost = '127.0.0.1'", r"unknown setting in \[ollama\]"),
        ("[ollama.host]\nvalue = '127.0.0.1'", r"ollama\.host"),
        ("[security]\nallowed_tools = ['shell']", r"unknown setting in \[security\]"),
        ("[security]\nrequire_approval = false", r"unknown setting in \[security\]"),
        ("ollama = 5", r"\[ollama\] must be a table"),
        ("ollama = 'x'", r"\[ollama\] must be a table"),
        ("ollama = []", r"\[ollama\] must be a table"),
        ("[[ollama]]\nhost = '127.0.0.1'", r"\[ollama\] must be a table"),
    ],
)
def test_unknown_or_misshapen_entries_are_errors_not_ignored(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_settings(text)


@pytest.mark.parametrize(
    "text",
    [
        "[ollama",
        "host = ",
        "[ollama]\nport = 11434\nport = 11435",
        "\x00",
        "= 1",
    ],
)
def test_invalid_toml_is_a_config_error(text: str) -> None:
    with pytest.raises(ConfigError, match="not valid TOML"):
        parse_settings(text)


def test_deeply_nested_input_is_rejected_cleanly() -> None:
    with pytest.raises(ConfigError, match="nested too deeply"):
        parse_settings("[ollama]\nport = " + "[" * 5000)


def test_oversized_input_is_rejected_before_parsing() -> None:
    with pytest.raises(ConfigError, match="too large"):
        parse_settings("#" * (MAX_SETTINGS_CHARACTERS + 1))


# --- Error messages do not repeat what was rejected (T-DATA-1) ----------------

CANARY = "hunter2-canary-value"


@pytest.mark.parametrize(
    "text",
    [
        f'[ollama]\nhost = "{CANARY}"',
        f'[ollama]\nmodel = "{CANARY}"',
        f'[ollama]\nport = "{CANARY}"',
        f'[ollama]\n"{CANARY}" = 1',
        f'["{CANARY}"]\nx = 1',
        f'[assistant]\nidle_timeout_seconds = "{CANARY}"',
        f'ollama = "{CANARY}"',
        f'[ollama]\nhost = "{CANARY}',
    ],
)
def test_error_messages_never_echo_the_rejected_value(text: str) -> None:
    with pytest.raises(ConfigError) as raised:
        parse_settings(text)

    assert CANARY not in str(raised.value)
    assert CANARY not in repr(raised.value)
    # No other exception, which might quote the value, is attached to it.
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_a_syntax_error_reports_where_it_is() -> None:
    with pytest.raises(ConfigError, match=r"not valid TOML \(line 2, column \d+\)"):
        parse_settings("[ollama]\nhost = = 1\n")
