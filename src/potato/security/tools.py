"""How a tool is described to the gate: its risk, arguments and limits.

A tool definition is written in code and cannot be changed afterwards (P5 and
R7). The model never supplies any part of it.

Arguments are checked strictly (P3 in ``docs/permissions.md``). Nothing is
guessed or converted from one kind to another: the text ``"3"`` is not the
number 3, ``True`` is not 1, and a whole-number field refuses 3.0. Every
argument is required and unknown ones are refused.

There is on purpose no field type for a command, source code or a file path
(P4). Text must match a pattern chosen by the tool's author.
"""

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Final

MAX_ARGUMENTS: Final = 8
MAX_TEXT_CHARACTERS: Final = 2048
MAX_CHOICES: Final = 64
MAX_TIMEOUT_SECONDS: Final = 120.0
MAX_CALLS_PER_PERIOD: Final = 60
MAX_PERIOD_SECONDS: Final = 3600.0
MAX_DESCRIPTION_CHARACTERS: Final = 200
MAX_DECIMAL_PLACES: Final = 8
# Every whole number up to here is exact as a float, so a JSON number the
# model writes cannot be silently rounded inside these bounds.
MAX_DECIMAL_MAGNITUDE: Final = Decimal(10**12)

_NAME: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")

ArgumentValue = str | int
"""A validated argument. Tools receive only these."""


class RiskLevel(StrEnum):
    """How much harm a tool could do. Decides who may call it."""

    LOW = "low"
    MEDIUM = "medium"
    SENSITIVE = "sensitive"


class ArgumentError(Exception):
    """An argument did not match its field. Carries no detail on purpose."""


@dataclass(frozen=True, slots=True)
class TextField:
    """Text that must match ``pattern`` completely.

    Attributes:
        pattern: The whole value must match this.
        max_characters: Longest text accepted, checked before the pattern.
    """

    pattern: re.Pattern[str]
    max_characters: int

    def __post_init__(self) -> None:
        """Refuse a field that could accept unbounded text."""
        if not isinstance(self.pattern, re.Pattern) or not isinstance(self.pattern.pattern, str):
            raise ValueError("pattern must be a compiled text pattern")
        if type(self.max_characters) is not int:
            raise ValueError("max_characters must be a whole number")
        if not 1 <= self.max_characters <= MAX_TEXT_CHARACTERS:
            raise ValueError(f"max_characters must be from 1 to {MAX_TEXT_CHARACTERS}")

    def validate(self, value: object) -> str:
        """Return ``value`` if it is acceptable text, else raise."""
        if type(value) is not str or len(value) > self.max_characters:
            raise ArgumentError
        if self.pattern.fullmatch(value) is None:
            raise ArgumentError
        return value

    def describe(self) -> dict[str, object]:
        """Describe the field for the model, as JSON Schema."""
        return {
            "type": "string",
            "maxLength": self.max_characters,
            "pattern": self.pattern.pattern,
        }


@dataclass(frozen=True, slots=True)
class IntegerField:
    """A whole number from ``minimum`` to ``maximum``, both included."""

    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        """Refuse bounds that are not whole numbers in order."""
        if type(self.minimum) is not int or type(self.maximum) is not int:
            raise ValueError("bounds must be whole numbers")
        if self.minimum > self.maximum:
            raise ValueError("minimum must not be above maximum")

    def validate(self, value: object) -> int:
        """Return ``value`` if it is a whole number in range, else raise."""
        # type(), not isinstance(): True and False are ints in Python.
        if type(value) is not int or not self.minimum <= value <= self.maximum:
            raise ArgumentError
        return value

    def describe(self) -> dict[str, object]:
        """Describe the field for the model, as JSON Schema."""
        return {"type": "integer", "minimum": self.minimum, "maximum": self.maximum}


@dataclass(frozen=True, slots=True)
class ChoiceField:
    """One of a fixed set of texts, matched exactly."""

    choices: frozenset[str]

    def __post_init__(self) -> None:
        """Refuse an empty, oversized or non-text set of choices."""
        if not isinstance(self.choices, frozenset) or not 1 <= len(self.choices) <= MAX_CHOICES:
            raise ValueError(f"choices must be a frozenset of 1 to {MAX_CHOICES} texts")
        if any(type(choice) is not str or not choice for choice in self.choices):
            raise ValueError("every choice must be non-empty text")

    def validate(self, value: object) -> str:
        """Return ``value`` if it is one of the choices, else raise."""
        if type(value) is not str or value not in self.choices:
            raise ArgumentError
        return value

    def describe(self) -> dict[str, object]:
        """Describe the field for the model, as JSON Schema."""
        return {"type": "string", "enum": sorted(self.choices)}


@dataclass(frozen=True, slots=True)
class DecimalField:
    """A number with up to ``max_places`` decimal places, from ``minimum`` to ``maximum``.

    Accepts a JSON number only: ``2.5`` or ``3``, never the text ``"2.5"``
    and never ``true``. The value is passed on as exact decimal text, such as
    ``"2.5"``, so that no rounding happens later. Tools turn it into a
    ``Decimal`` themselves.

    A number the model writes as ``0.1`` reaches Python as the nearest float.
    It is read back as the shortest text that gives that float, which is
    ``"0.1"`` again, so what the model wrote is what is used.
    """

    minimum: Decimal
    maximum: Decimal
    max_places: int

    def __post_init__(self) -> None:
        """Refuse bounds that are not finite, ordered and within the fixed limits."""
        for bound in (self.minimum, self.maximum):
            if type(bound) is not Decimal or not bound.is_finite():
                raise ValueError("bounds must be finite Decimals")
            if abs(bound) > MAX_DECIMAL_MAGNITUDE:
                raise ValueError(f"bounds must be within {MAX_DECIMAL_MAGNITUDE}")
        if self.minimum > self.maximum:
            raise ValueError("minimum must not be above maximum")
        if type(self.max_places) is not int or not 0 <= self.max_places <= MAX_DECIMAL_PLACES:
            raise ValueError(f"max_places must be from 0 to {MAX_DECIMAL_PLACES}")

    def validate(self, value: object) -> str:
        """Return ``value`` as exact decimal text if it is acceptable, else raise."""
        # type(), not isinstance(): True and False are ints in Python.
        if type(value) is int:
            number = Decimal(value)
        elif type(value) is float and math.isfinite(value):
            number = Decimal(repr(value))
        else:
            raise ArgumentError
        if not self.minimum <= number <= self.maximum:
            raise ArgumentError
        exponent = number.as_tuple().exponent
        if not isinstance(exponent, int) or exponent < -self.max_places:
            raise ArgumentError
        if number == 0:
            # One spelling of zero, never "-0".
            return "0"
        return format(number.normalize(), "f")

    def describe(self) -> dict[str, object]:
        """Describe the field for the model, as JSON Schema."""
        return {
            "type": "number",
            "minimum": float(self.minimum),
            "maximum": float(self.maximum),
        }


Field = TextField | IntegerField | ChoiceField | DecimalField

ToolHandler = Callable[[Mapping[str, ArgumentValue]], Mapping[str, object]]
"""Runs a tool. Receives validated arguments and returns plain data."""


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Everything the gate needs to know about one tool.

    Attributes:
        name: The name the model uses. Lower-case letters, digits and
            underscores.
        risk: Fixed here, in code. A request cannot change it.
        arguments: The argument names and what each accepts. All required.
        handler: The function that does the work.
        timeout_seconds: How long the handler may take.
        max_calls: How many calls are accepted per ``period_seconds``.
        period_seconds: The length of the rate-limit window.
        description: One plain sentence telling the model what the tool
            does. Written in code like the rest; never taken from data.
    """

    name: str
    risk: RiskLevel
    arguments: Mapping[str, Field]
    handler: ToolHandler
    timeout_seconds: float = 10.0
    max_calls: int = 10
    period_seconds: float = 60.0
    description: str = ""

    def __post_init__(self) -> None:
        """Validate the definition and freeze the arguments."""
        if type(self.name) is not str or _NAME.fullmatch(self.name) is None:
            raise ValueError("a tool name must be lower-case letters, digits and underscores")
        if not isinstance(self.risk, RiskLevel):
            raise ValueError("risk must be a RiskLevel")
        if not isinstance(self.arguments, Mapping) or len(self.arguments) > MAX_ARGUMENTS:
            raise ValueError(f"a tool can have at most {MAX_ARGUMENTS} arguments")
        for name, field in self.arguments.items():
            if type(name) is not str or _NAME.fullmatch(name) is None:
                raise ValueError("an argument name must be lower-case letters, digits, underscores")
            if not isinstance(field, TextField | IntegerField | ChoiceField | DecimalField):
                raise ValueError(
                    "an argument must be a TextField, IntegerField, ChoiceField or DecimalField"
                )
        if not callable(self.handler):
            raise ValueError("handler must be callable")
        _require_number("timeout_seconds", self.timeout_seconds, MAX_TIMEOUT_SECONDS)
        _require_number("period_seconds", self.period_seconds, MAX_PERIOD_SECONDS)
        if type(self.max_calls) is not int or not 1 <= self.max_calls <= MAX_CALLS_PER_PERIOD:
            raise ValueError(f"max_calls must be from 1 to {MAX_CALLS_PER_PERIOD}")
        if (
            type(self.description) is not str
            or len(self.description) > MAX_DESCRIPTION_CHARACTERS
            or not (self.description.isprintable() and self.description.isascii())
        ):
            raise ValueError(
                f"description must be plain text of at most {MAX_DESCRIPTION_CHARACTERS} characters"
            )
        # A private, read-only copy: later changes to the caller's dict have
        # no effect on what the gate accepts.
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))

    def describe(self) -> dict[str, object]:
        """Describe the tool for the model, in the format Ollama expects.

        This helps the model ask correctly. It is not a check: the gate
        validates every proposal whatever the model was told.
        """
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        name: field.describe() for name, field in self.arguments.items()
                    },
                    "required": sorted(self.arguments),
                    "additionalProperties": False,
                },
            },
        }

    def validate(self, arguments: object) -> dict[str, ArgumentValue]:
        """Return a fresh dict of validated arguments, else raise.

        Raises:
            ArgumentError: ``arguments`` is not a dict, has a missing or
                unknown name, or a value its field refuses.
        """
        if type(arguments) is not dict or len(arguments) != len(self.arguments):
            raise ArgumentError
        validated: dict[str, ArgumentValue] = {}
        for name, value in arguments.items():
            if type(name) is not str:
                raise ArgumentError
            field = self.arguments.get(name)
            if field is None:
                raise ArgumentError
            validated[name] = field.validate(value)
        return validated


def digest_arguments(arguments: Mapping[str, ArgumentValue]) -> str:
    """Return a SHA-256 digest of validated arguments in a canonical form.

    The audit log stores this instead of the arguments (T-DATA-4).
    """
    canonical = json.dumps(
        dict(arguments), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _require_number(name: str, value: object, maximum: float) -> None:
    """Refuse a limit that is not a number above zero and at most ``maximum``."""
    if type(value) not in (int, float) or not 0 < value <= maximum:  # type: ignore[operator]
        raise ValueError(f"{name} must be above 0 and at most {maximum}")
