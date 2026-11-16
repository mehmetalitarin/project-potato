"""The security posture tool: are this Mac's built-in protections switched on?

One tool, ``security_posture`` (low risk). It reports four settings:

- **Disk encryption** (FileVault): protects files if the Mac is lost.
- **Firewall**: refuses unwanted incoming connections.
- **Gatekeeper**: checks that applications come from known developers.
- **System Integrity Protection**: stops even administrators' programs from
  changing the system itself.

How it works, and why it is safe (T-TOOL-3 in ``docs/threat_model.md``):

- Each setting is read by one of Apple's own status tools, run by
  ``potato.integrations.processes`` from its fixed list. This module cannot
  choose a program or an argument.
- **The tools' output is never passed on.** It is matched against the exact
  lines those tools print and turned into ``on``, ``off`` or ``unknown``.
  Anything unexpected is ``unknown``: Potato never guesses, and never says a
  protection is on unless the tool said exactly that.
- Every sentence in the result is fixed text written here.
- It only reads. Potato has no way to change these settings.

"On" means the setting is switched on, not that the Mac is secure.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from potato.integrations.processes import Probe, run_probe
from potato.security.tools import ArgumentValue, RiskLevel, ToolDefinition


class State(StrEnum):
    """What a status tool reported."""

    ON = "on"
    OFF = "off"
    UNKNOWN = "unknown"


_FILEVAULT: Final = re.compile(r"FileVault is (On|Off)\.")
_FIREWALL: Final = re.compile(r"Firewall is [A-Za-z .\-]{1,80}\(State = ([0-2])\)")
_GATEKEEPER: Final = re.compile(r"assessments (enabled|disabled)")
_SYSTEM_INTEGRITY: Final = re.compile(r"System Integrity Protection status: (enabled|disabled)\.")


def _first_line(output: str) -> str:
    """The first line that is not empty, without surrounding spaces."""
    for line in output.splitlines():
        if line.strip():
            return line.strip()
    return ""


def _parse(pattern: re.Pattern[str], on: frozenset[str], off: frozenset[str]) -> "Parser":
    """Build a parser that accepts only a first line matching ``pattern`` completely."""

    def parse(output: str) -> State:
        found = pattern.fullmatch(_first_line(output))
        if found is None:
            return State.UNKNOWN
        if found.group(1) in on:
            return State.ON
        if found.group(1) in off:
            return State.OFF
        return State.UNKNOWN

    return parse


Parser = Callable[[str], State]


@dataclass(frozen=True, slots=True)
class Check:
    """One protection: how to read it and what to say about it."""

    name: str
    probe: Probe
    parse: Parser
    on: str
    off: str


UNKNOWN_SENTENCE: Final = "Potato could not read this setting."

CHECKS: Final = (
    Check(
        "disk_encryption",
        Probe.FILEVAULT,
        _parse(_FILEVAULT, frozenset({"On"}), frozenset({"Off"})),
        "FileVault is on: the disk is encrypted.",
        "FileVault is off: files on this Mac could be read if it were lost or stolen.",
    ),
    Check(
        "firewall",
        Probe.FIREWALL,
        # State 1 is on; state 2 is on and blocking all incoming connections.
        _parse(_FIREWALL, frozenset({"1", "2"}), frozenset({"0"})),
        "The firewall is on.",
        "The firewall is off: other devices on the network can reach services on this Mac.",
    ),
    Check(
        "gatekeeper",
        Probe.GATEKEEPER,
        _parse(_GATEKEEPER, frozenset({"enabled"}), frozenset({"disabled"})),
        "Gatekeeper is on: applications are checked before they first run.",
        "Gatekeeper is off: applications from unknown developers can run unchecked.",
    ),
    Check(
        "system_integrity_protection",
        Probe.SYSTEM_INTEGRITY,
        _parse(_SYSTEM_INTEGRITY, frozenset({"enabled"}), frozenset({"disabled"})),
        "System Integrity Protection is on.",
        "System Integrity Protection is off: programs could change the system itself.",
    ),
)

SUMMARIES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "all_on": "All four protections are switched on.",
        "some_off": "At least one protection is switched off.",
        "incomplete": "No protection was found switched off, but not all could be read.",
        "unavailable": "None of the settings could be read. These checks need macOS.",
    }
)
NOTE: Final = (
    "Potato only reads these settings and cannot change them. They can be changed in "
    "System Settings. Switched on does not by itself mean this Mac is secure."
)

ProbeRunner = Callable[[Probe], str | None]


def read_posture(runner: ProbeRunner = run_probe) -> dict[str, object]:
    """Run every check and return the result as plain data built from fixed text."""
    checks: list[dict[str, object]] = []
    states: list[State] = []
    for check in CHECKS:
        output = runner(check.probe)
        state = State.UNKNOWN if type(output) is not str else check.parse(output)
        states.append(state)
        sentence = {State.ON: check.on, State.OFF: check.off}.get(state, UNKNOWN_SENTENCE)
        checks.append({"name": check.name, "state": state.value, "explanation": sentence})

    if State.OFF in states:
        summary = "some_off"
    elif all(state is State.ON for state in states):
        summary = "all_on"
    elif all(state is State.UNKNOWN for state in states):
        summary = "unavailable"
    else:
        summary = "incomplete"
    return {"summary": SUMMARIES[summary], "checks": checks, "note": NOTE}


def security_posture_tools(runner: ProbeRunner = run_probe) -> tuple[ToolDefinition, ...]:
    """Return the security posture tool.

    The argument exists for tests, which cannot run Apple's tools.
    """

    def handle(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        return read_posture(runner)

    return (
        ToolDefinition(
            name="security_posture",
            risk=RiskLevel.LOW,
            arguments={},
            handler=handle,
            description=(
                "Report whether this Mac's disk encryption, firewall, Gatekeeper and System "
                "Integrity Protection are switched on."
            ),
            # Four tools, each with a 5-second limit.
            timeout_seconds=30.0,
            max_calls=5,
        ),
    )
