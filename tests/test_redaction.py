"""Tests for removing secrets from text (T-DATA-1 in docs/threat_model.md).

The values here are obviously fake and are built at run time, so that no
secret scanner mistakes this file for a leak.
"""

import time
from typing import Any

import pytest

from potato.security.redaction import MIN_SECRET_LENGTH, REDACTED, Redactor, is_secret_name

FAKE = "-".join(["potato", "fake", "value", "0001"])
OTHER = "-".join(["second", "fake", "value", "0002"])


@pytest.fixture
def redactor() -> Redactor:
    return Redactor()


# --- Layer 1: registered values ----------------------------------------------


def test_a_registered_secret_is_removed_wherever_it_appears(redactor: Redactor) -> None:
    redactor.register_secret(FAKE)

    cleaned = redactor.redact(f"start {FAKE} middle<{FAKE}>end\n{FAKE}")

    assert FAKE not in cleaned
    assert cleaned == f"start {REDACTED} middle<{REDACTED}>end\n{REDACTED}"


def test_several_secrets_are_all_removed(redactor: Redactor) -> None:
    redactor.register_secret(FAKE)
    redactor.register_secret(OTHER)

    cleaned = redactor.redact(f"{OTHER} and {FAKE}")

    assert FAKE not in cleaned
    assert OTHER not in cleaned


def test_a_secret_inside_a_longer_secret_leaves_nothing_behind(redactor: Redactor) -> None:
    longer = FAKE + "-with-a-tail"
    redactor.register_secret(FAKE)
    redactor.register_secret(longer)

    assert redactor.redact(f"x {longer} y") == f"x {REDACTED} y"


def test_a_secret_is_also_removed_in_its_web_address_form(redactor: Redactor) -> None:
    value = "fake value/with+odd&chars=1"
    redactor.register_secret(value)

    cleaned = redactor.redact(
        "https://example.invalid/?q=fake%20value%2Fwith%2Bodd%26chars%3D1"
        " and https://example.invalid/?q=fake+value%2Fwith%2Bodd%26chars%3D1"
    )

    assert "fake" not in cleaned
    assert cleaned.count(REDACTED) == 2


def test_registering_the_same_secret_twice_is_harmless(redactor: Redactor) -> None:
    redactor.register_secret(FAKE)
    redactor.register_secret(FAKE)

    assert redactor.redact(FAKE) == REDACTED


@pytest.mark.parametrize(
    "secret", ["", "short", "x" * (MIN_SECRET_LENGTH - 1), None, 12345678, b"12345678"]
)
def test_values_that_cannot_be_redacted_safely_are_refused(redactor: Redactor, secret: Any) -> None:
    with pytest.raises(ValueError, match="at least") as raised:
        redactor.register_secret(secret)

    if secret:
        assert str(secret) not in str(raised.value)


# --- Layers 2 and 3: shapes and names ------------------------------------------

HIDDEN = "zq" + "9" * 6 + "kx"  # stands in for a secret nobody registered


@pytest.mark.parametrize(
    "template",
    [
        "api_key={}",
        "API_KEY={}",
        "apikey: {}",
        "apiKey = {}",
        "X-Api-Key: {}",
        "access_token={}",
        "accessToken={}",
        "refresh-token: {}",
        "token={}",
        "password={}",
        "Password: {}",
        "passwd={}",
        "passphrase = {}",
        "client_secret={}",
        "private_key={}",
        "credentials: {}",
        "settings.api_key={}",
        '"token": "{}"',
        "'token': '{}'",
        '{{"password": "{}", "user": "me"}}',
        "https://example.invalid/quote?symbol=AAPL&apikey={}&x=1",
        "https://example.invalid/quote?token={}",
        "GET https://example.invalid/v1/quote?symbol=AAPL&token={} HTTP/1.1",
        "url=https://example.invalid/?api_key={}",
        "error: request to https://example.invalid/?a=1&password={} failed: timeout",
        "https://user:{}@example.invalid/path",
        "postgres://admin:{}@127.0.0.1:5432/db",
        "Authorization: Bearer {}",
        "authorization: Basic {}",
        "Authorization: {}",
        "'Authorization': 'Bearer {}'",
        "Proxy-Authorization: Bearer {}",
        "curl -H 'Authorization: Bearer {}' https://example.invalid",
    ],
)
def test_an_unregistered_secret_is_removed_by_its_name_or_shape(
    redactor: Redactor, template: str
) -> None:
    cleaned = redactor.redact(template.format(HIDDEN))

    assert HIDDEN not in cleaned
    assert REDACTED in cleaned


def test_a_bearer_token_is_removed_without_a_header_name(redactor: Redactor) -> None:
    token = "abc123" * 4

    assert token not in redactor.redact(f"sent bearer {token} to the server")


def test_a_quoted_secret_containing_spaces_is_removed_whole(redactor: Redactor) -> None:
    cleaned = redactor.redact('{"password": "three separate words"}')

    assert "three" not in cleaned
    assert "words" not in cleaned


def _key_marker(edge: str, kind: str = "") -> str:
    """Build a key-file marker in pieces, so no scanner sees one in this file."""
    return "-" * 5 + f"{edge} {kind}PRIVATE" + " KEY" + "-" * 5


@pytest.mark.parametrize("ending", [_key_marker("END"), _key_marker("END", "RSA "), ""])
def test_a_private_key_block_is_removed_even_if_cut_short(redactor: Redactor, ending: str) -> None:
    body = "FAKEKEYBODY" * 6
    block = _key_marker("BEGIN", "RSA ") + "\n" + body + "\n" + ending

    cleaned = redactor.redact(f"loading key:\n{block}")

    assert body not in cleaned
    assert cleaned.startswith("loading key:\n[REDACTED PRIVATE KEY]")


@pytest.mark.parametrize(
    "text",
    [
        "Potato started in standby",
        "prompt_tokens=512 completion_tokens=40",
        "tokens: 9",
        "used 512 tokens in 1.2 seconds",
        "the token expired, asking for a new one",
        "password reset requested",
        "basic information about the secret santa",
        "bearer of bad news",
        "time: 12:30",
        "state: active -> standby",
        "tool=open_app origin=voice decision=deny reason=UNKNOWN_TOOL",
        "model=qwen3:8b host=127.0.0.1 port=11434",
        "https://example.invalid/quote?symbol=AAPL&x=1",
        "key idea: keep it simple",
        "digest=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "",
    ],
)
def test_ordinary_text_is_left_alone(redactor: Redactor, text: str) -> None:
    assert redactor.redact(text) == text


@pytest.mark.parametrize(
    "text",
    [
        f"api_key={HIDDEN} and Authorization: Bearer {HIDDEN}",
        f'{{"token": "{HIDDEN}"}}',
        f"https://user:{HIDDEN}@example.invalid/?password={HIDDEN}",
        "nothing secret here",
    ],
)
def test_redacting_twice_changes_nothing_more(redactor: Redactor, text: str) -> None:
    once = redactor.redact(text)

    assert redactor.redact(once) == once


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("password", True),
        ("api_key", True),
        ("apiKey", True),
        ("API_KEY", True),
        ("X-Api-Key", True),
        ("accessToken", True),
        ("access_key_id", True),
        ("client_secret", True),
        ("Authorization", True),
        ("token", True),
        ("tokens", False),
        ("prompt_tokens", False),
        ("key", False),
        ("keyboard", False),
        ("monkey", False),
        ("tool", False),
        ("passenger", False),
        ("", False),
    ],
)
def test_secret_looking_names(name: str, expected: bool) -> None:
    assert is_secret_name(name) is expected


# --- Structured data ----------------------------------------------------------


def test_structured_data_is_cleaned_all_the_way_down(redactor: Redactor) -> None:
    redactor.register_secret(FAKE)

    cleaned = redactor.redact_value(
        {
            "tool": "open_app",
            "note": f"contains {FAKE}",
            "api_key": HIDDEN,
            "nested": {"password": ["a", "b"], "list": [FAKE, 3, None, True, 1.5]},
            "tuple": (FAKE, "plain"),
            7: "number as a name",
        }
    )

    assert cleaned == {
        "tool": "open_app",
        "note": f"contains {REDACTED}",
        "api_key": REDACTED,
        "nested": {"password": REDACTED, "list": [REDACTED, 3, None, True, 1.5]},
        "tuple": [REDACTED, "plain"],
        "7": "number as a name",
    }


def test_objects_are_replaced_by_their_type_name(redactor: Redactor) -> None:
    class Holder:
        def __repr__(self) -> str:
            return f"Holder({HIDDEN})"

        __str__ = __repr__

    cleaned = redactor.redact_value({"thing": Holder(), "data": b"raw", Holder(): 1})

    assert cleaned == {"thing": "<Holder>", "data": "<bytes>", "<Holder>": 1}


def test_numbers_that_are_not_valid_json_become_text(redactor: Redactor) -> None:
    assert redactor.redact_value([float("inf"), float("nan")]) == ["inf", "nan"]


def test_data_that_contains_itself_does_not_loop_forever(redactor: Redactor) -> None:
    loop: list[Any] = []
    loop.append(loop)

    assert "[TOO DEEPLY NESTED]" in str(redactor.redact_value(loop))


# --- Hostile input cannot make redaction slow ---------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "a" * 40_000,
        "a." * 20_000,
        "=" * 40_000,
        "x=" * 20_000,
        "http://" * 6_000,
        "x://a:" * 7_000,
        "token" * 8_000,
        "token=" * 7_000,
        '"' * 40_000,
        "'token': '" * 4_000,
        "bearer " * 6_000,
        _key_marker("BEGIN") * 1_500,
        "authorization:" * 3_000,
        ("a" * 50 + ": ") * 800,
    ],
    ids=lambda text: text[:12],
)
def test_long_awkward_text_is_handled_quickly(redactor: Redactor, text: str) -> None:
    redactor.register_secret(FAKE)
    started = time.perf_counter()

    redactor.redact(text)

    # Each pattern must do work in proportion to the length of the text. One
    # that re-reads the text from every position takes about half a minute on
    # these inputs; the real ones take a few thousandths of a second.
    assert time.perf_counter() - started < 2
