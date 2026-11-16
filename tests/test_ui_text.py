"""Tests for making untrusted text safe to show (potato.ui.text)."""

import pytest

from potato.ui.text import CUT, MARKER, MAX_DISPLAY_CHARACTERS, displayable


@pytest.mark.parametrize(
    "text",
    ["Hello", "Line one\nLine two", "a\tb", "Caf\u00e9 \u6f22\u5b57 \U0001f954", "", "  spaced  "],
)
def test_ordinary_text_is_unchanged(text: str) -> None:
    assert displayable(text) == text


@pytest.mark.parametrize(
    "hidden",
    [
        "\u202e",  # right-to-left override: the Trojan Source trick
        "\u202d", "\u2066", "\u2067", "\u2068", "\u2069", "\u200f", "\u061c",
        "\u200b",  # zero-width space
        "\u200d", "\ufeff", "\u2060", "\u00ad",
        "\x00", "\x07", "\x1b", "\r", "\x0b", "\x0c", "\x7f", "\x85",
        "\u2028", "\u2029",
        "\ue000",  # private use
        "\U000e0041",  # tag character
        "\U0010ffff",  # unassigned
    ],
)  # fmt: skip
def test_hidden_characters_become_a_visible_marker(hidden: str) -> None:
    assert displayable(f"a{hidden}b") == f"a{MARKER}b"


def test_a_reversed_reply_cannot_disguise_itself() -> None:
    # Shown without the fix, this reads "your money is safe" backwards.
    shown = displayable("transfer \u202eefas si yenom ruoy\u202c done")
    assert "\u202e" not in shown
    assert "\u202c" not in shown
    assert shown.count(MARKER) == 2


def test_long_text_is_cut_and_says_so() -> None:
    shown = displayable("x" * (MAX_DISPLAY_CHARACTERS + 50))
    assert shown == "x" * MAX_DISPLAY_CHARACTERS + CUT
    assert displayable("x" * MAX_DISPLAY_CHARACTERS) == "x" * MAX_DISPLAY_CHARACTERS


@pytest.mark.parametrize("value", [None, 5, b"bytes", ["a"], {"a": 1}])
def test_anything_but_text_shows_nothing(value: object) -> None:
    assert displayable(value) == ""


def test_the_marker_itself_is_visible() -> None:
    assert MARKER == "\ufffd"
