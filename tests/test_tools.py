"""Tests for tool definitions and strict argument checking (P3, P4, P5)."""

import dataclasses
import re
from collections.abc import Mapping

import pytest

import potato.security.tools as tools_module
from potato.security.tools import (
    ArgumentError,
    ArgumentValue,
    ChoiceField,
    IntegerField,
    RiskLevel,
    TextField,
    ToolDefinition,
)

SYMBOL = TextField(re.compile(r"[A-Z]{1,5}"), max_characters=5)
DAYS = IntegerField(1, 14)
APP = ChoiceField(frozenset({"Safari", "Notes"}))


def _handler(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
    return {}


def _tool(**changes: object) -> ToolDefinition:
    options: dict[str, object] = {
        "name": "example",
        "risk": RiskLevel.LOW,
        "arguments": {"symbol": SYMBOL, "days": DAYS},
        "handler": _handler,
    }
    options.update(changes)
    return ToolDefinition(**options)  # type: ignore[arg-type]


class TextSubclass(str):
    __slots__ = ()


class IntSubclass(int):
    pass


# --- Fields: nothing is guessed or converted ---------------------------------


@pytest.mark.parametrize("value", ["A", "AAPL", "ABCDE"])
def test_text_field_accepts_matching_text(value: str) -> None:
    assert SYMBOL.validate(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "", "aapl", "ABCDEF", "AAPL\n", " AAPL", "AAPL; rm -rf /", "ÅAPL", b"AAPL", 5, None,
        ["AAPL"], {"value": "AAPL"}, True, TextSubclass("AAPL"),
    ],
)  # fmt: skip
def test_text_field_refuses_everything_else(value: object) -> None:
    with pytest.raises(ArgumentError):
        SYMBOL.validate(value)


def test_text_field_checks_length_before_running_the_pattern() -> None:
    # A pattern that would take minutes on a long input is never reached.
    slow = TextField(re.compile(r"(a+)+b"), max_characters=8)
    with pytest.raises(ArgumentError):
        slow.validate("a" * 5000)


@pytest.mark.parametrize("value", [1, 7, 14])
def test_integer_field_accepts_whole_numbers_in_range(value: int) -> None:
    assert DAYS.validate(value) == value


@pytest.mark.parametrize(
    "value",
    [0, 15, -1, 10**30, 3.0, 3.5, "3", True, False, None, [3], float("nan"), IntSubclass(3)],
)
def test_integer_field_refuses_everything_else(value: object) -> None:
    with pytest.raises(ArgumentError):
        DAYS.validate(value)


def test_choice_field_accepts_only_exact_choices() -> None:
    assert APP.validate("Safari") == "Safari"
    for value in ["safari", "Safari ", "Terminal", "", None, 1, ["Safari"], TextSubclass("Notes")]:
        with pytest.raises(ArgumentError):
            APP.validate(value)


def test_an_unhashable_value_is_refused_not_an_error() -> None:
    with pytest.raises(ArgumentError):
        APP.validate({"Safari"})


def test_argument_error_carries_no_detail() -> None:
    with pytest.raises(ArgumentError) as caught:
        SYMBOL.validate("secret-looking-value")
    assert str(caught.value) == ""


@pytest.mark.parametrize(
    "build",
    [
        lambda: TextField("[A-Z]+", 5),  # type: ignore[arg-type]
        lambda: TextField(re.compile(rb"[A-Z]+"), 5),  # type: ignore[arg-type]
        lambda: TextField(re.compile("x"), 0),
        lambda: TextField(re.compile("x"), tools_module.MAX_TEXT_CHARACTERS + 1),
        lambda: TextField(re.compile("x"), True),
        lambda: IntegerField(5, 1),
        lambda: IntegerField(1.0, 5),  # type: ignore[arg-type]
        lambda: IntegerField(False, 5),
        lambda: ChoiceField(frozenset()),
        lambda: ChoiceField({"a"}),  # type: ignore[arg-type]
        lambda: ChoiceField(frozenset({""})),
        lambda: ChoiceField(frozenset({1})),  # type: ignore[arg-type]
        lambda: ChoiceField(frozenset(str(n) for n in range(tools_module.MAX_CHOICES + 1))),
    ],
)
def test_badly_built_fields_are_refused(build: object) -> None:
    with pytest.raises(ValueError):
        build()  # type: ignore[operator]


def test_there_is_no_field_for_free_text_commands_or_paths() -> None:
    # P4: the only text field requires a pattern and a length cap.
    fields = {name for name in vars(tools_module) if name.endswith("Field") and name != "Field"}
    assert fields == {"TextField", "IntegerField", "ChoiceField"}
    required = [f.name for f in dataclasses.fields(TextField) if f.default is dataclasses.MISSING]
    assert required == ["pattern", "max_characters"]


# --- Definitions -------------------------------------------------------------


def test_valid_arguments_come_back_as_a_fresh_dict() -> None:
    given = {"symbol": "AAPL", "days": 3}
    validated = _tool().validate(given)
    assert validated == given
    assert validated is not given


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"symbol": "AAPL"},
        {"symbol": "AAPL", "days": 3, "extra": 1},
        {"symbol": "AAPL", "day": 3},
        {"symbol": "AAPL", "days": "3"},
        {"symbol": "AAPL", "days": None},
        {"symbol": "AAPL", 1: 3},
        {"symbol": "AAPL", "days": 3, "approved": True},
        [("symbol", "AAPL"), ("days", 3)],
        "symbol=AAPL",
        None,
    ],
)
def test_arguments_must_match_exactly(arguments: object) -> None:
    with pytest.raises(ArgumentError):
        _tool().validate(arguments)


def test_a_tool_without_arguments_accepts_only_an_empty_dict() -> None:
    tool = _tool(arguments={})
    assert tool.validate({}) == {}
    with pytest.raises(ArgumentError):
        tool.validate({"anything": 1})


def test_definition_cannot_be_changed_afterwards() -> None:
    source = {"symbol": SYMBOL}
    tool = _tool(arguments=source)
    source["command"] = TextField(re.compile(".*"), 100)
    assert set(tool.arguments) == {"symbol"}
    with pytest.raises(TypeError):
        tool.arguments["command"] = SYMBOL  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        tool.risk = RiskLevel.LOW  # type: ignore[misc]


@pytest.mark.parametrize(
    "changes",
    [
        {"name": ""},
        {"name": "Example"},
        {"name": "has space"},
        {"name": "x" * 33},
        {"name": 5},
        {"risk": "low"},
        {"risk": None},
        {"arguments": {"Bad Name": SYMBOL}},
        {"arguments": {"symbol": str}},
        {"arguments": {"symbol": "text"}},
        {"arguments": [("symbol", SYMBOL)]},
        {"arguments": {f"a{n}": DAYS for n in range(tools_module.MAX_ARGUMENTS + 1)}},
        {"handler": None},
        {"timeout_seconds": 0},
        {"timeout_seconds": -1.0},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": float("inf")},
        {"timeout_seconds": tools_module.MAX_TIMEOUT_SECONDS + 1},
        {"timeout_seconds": True},
        {"max_calls": 0},
        {"max_calls": tools_module.MAX_CALLS_PER_PERIOD + 1},
        {"max_calls": 2.0},
        {"period_seconds": 0},
        {"period_seconds": tools_module.MAX_PERIOD_SECONDS + 1},
    ],
)
def test_badly_built_tools_are_refused(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _tool(**changes)
