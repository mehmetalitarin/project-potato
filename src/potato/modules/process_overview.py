"""The process overview tool: what is running, and what is using the most.

One tool, ``process_overview`` (low risk). It reports how many programs are
running, who they belong to, and the five using the most processor and the
five using the most memory.

How it works, and why it is safe (T-TOOL-3 and T-TOOL-4 in
``docs/threat_model.md``):

- The list comes from ``ps``, run by ``potato.integrations.processes`` as a
  fixed command. This module cannot choose a program or an argument.
- **No command lines.** Potato asks only for each program's short name,
  number, owner and resource use. Command-line arguments and environment
  variables often hold secrets; they are never requested, so they are never
  seen, stored or passed on.
- **Names are untrusted.** A program chooses its own name. A name is shown
  only if it is short and made of plain characters; anything else is
  replaced by a fixed label. Every other piece of text in the result is
  fixed text written here.
- **An odd name cannot hide a program.** The name is the last thing on each
  line, so whatever it contains, the numbers before it are still read and
  the program is still counted.
- It only reads, and only this Mac.

A name does not prove what a program is: anything can call itself
``Finder``. This overview is a convenience, not evidence.
"""

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from potato.integrations.processes import Probe, run_probe
from potato.security.tools import ArgumentValue, RiskLevel, ToolDefinition

TOP_COUNT: Final = 5
# A share of one processor core, so a busy program on several cores can
# show more than 100.
PROCESSOR_HIGH_PERCENT: Final = 90.0
MEMORY_HIGH_MEGABYTES: Final = 4096
MAX_NAME_CHARACTERS: Final = 32
UNUSUAL_NAME: Final = "(unusual name)"

# macOS numbers people's accounts from 501. Lower numbers, and the account
# "nobody", belong to the system.
_FIRST_PERSON_ACCOUNT: Final = 500
_NOBODY: Final = 4294967294

# Number, processor share, memory in kilobytes, owner's number, then the
# name: everything up to the end of the line, whatever it contains.
_LINE: Final = re.compile(
    r" *([0-9]{1,7}) +([0-9]{1,4}\.[0-9]) +([0-9]{1,12}) +(-?[0-9]{1,10})(?: (.*))?"
)
_PLAIN_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+()\-]{0,31}")

SUMMARIES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "normal": "Nothing is using an unusual amount of processor or memory.",
        "heavy": (
            "At least one program is using a lot of processor or memory. This is often "
            "normal, for example for a browser or the local model."
        ),
        "unavailable": "The list of running programs could not be read.",
    }
)
WARNING_UNUSUAL_NAMES: Final = (
    "Some programs have names with unexpected characters. Those names are not shown."
)
WARNING_UNREADABLE: Final = (
    "Some lines of the list could not be read, so this overview may be incomplete."
)
NOTE: Final = (
    "A program chooses its own name, so a name does not prove what a program is. Potato "
    "does not read command lines. Activity Monitor shows full details."
)


@dataclass(frozen=True, slots=True)
class ProcessRow:
    """One running program, as far as Potato looks at it."""

    pid: int
    processor_percent: float
    memory_kilobytes: int
    owner: str
    name: str
    plain_name: bool


def _owner(number: int, current_user: int) -> str:
    if number == current_user:
        return "you"
    if number < _FIRST_PERSON_ACCOUNT or number == _NOBODY:
        return "system"
    return "another_user"


def parse_listing(output: str, current_user: int) -> tuple[list[ProcessRow], int]:
    """Read the process list. Returns the rows and the number of unreadable lines.

    A line is unreadable only if its numbers are not in the expected form.
    The name cannot make a line unreadable.
    """
    rows: list[ProcessRow] = []
    unreadable = 0
    # Split on the newline only: other separators may appear inside a name.
    for line in output.split("\n"):
        if not line.strip(" "):
            continue
        found = _LINE.fullmatch(line)
        if found is None:
            unreadable += 1
            continue
        name = (found.group(5) or "").strip(" ")
        plain = _PLAIN_NAME.fullmatch(name) is not None
        rows.append(
            ProcessRow(
                pid=int(found.group(1)),
                processor_percent=float(found.group(2)),
                memory_kilobytes=int(found.group(3)),
                owner=_owner(int(found.group(4)), current_user),
                name=name if plain else UNUSUAL_NAME,
                plain_name=plain,
            )
        )
    return rows, unreadable


def _megabytes(row: ProcessRow) -> int:
    return (row.memory_kilobytes + 512) // 1024


def _is_heavy(row: ProcessRow) -> bool:
    return (
        row.processor_percent >= PROCESSOR_HIGH_PERCENT or _megabytes(row) >= MEMORY_HIGH_MEGABYTES
    )


def _entry(row: ProcessRow) -> dict[str, object]:
    return {
        "name": row.name,
        "pid": row.pid,
        "processor_percent": row.processor_percent,
        "memory_megabytes": _megabytes(row),
        "owner": row.owner,
        "heavy": _is_heavy(row),
    }


ProbeRunner = Callable[[Probe], str | None]
CurrentUser = Callable[[], int]


def read_overview(
    runner: ProbeRunner = run_probe, current_user: CurrentUser = os.getuid
) -> dict[str, object]:
    """Read the process list and return an overview as plain data."""
    output = runner(Probe.PROCESSES)
    rows, unreadable = parse_listing(output, current_user()) if type(output) is str else ([], 0)
    if not rows:
        return {"summary": SUMMARIES["unavailable"], "note": NOTE}

    by_processor = sorted(rows, key=lambda row: (-row.processor_percent, row.pid))
    by_memory = sorted(rows, key=lambda row: (-row.memory_kilobytes, row.pid))
    owners = {"you": 0, "system": 0, "another_user": 0}
    for row in rows:
        owners[row.owner] += 1
    unusual = sum(1 for row in rows if not row.plain_name)

    warnings: list[str] = []
    if unusual:
        warnings.append(WARNING_UNUSUAL_NAMES)
    if unreadable:
        warnings.append(WARNING_UNREADABLE)
    heavy = any(_is_heavy(row) for row in rows)
    return {
        "summary": SUMMARIES["heavy" if heavy else "normal"],
        "total": len(rows),
        "owners": owners,
        "top_processor": [_entry(row) for row in by_processor[:TOP_COUNT]],
        "top_memory": [_entry(row) for row in by_memory[:TOP_COUNT]],
        "unusual_names": unusual,
        "unreadable_lines": unreadable,
        "warnings": warnings,
        "note": NOTE,
    }


def process_overview_tools(
    runner: ProbeRunner = run_probe, current_user: CurrentUser = os.getuid
) -> tuple[ToolDefinition, ...]:
    """Return the process overview tool.

    The arguments exist for tests, which supply a prepared list.
    """

    def handle(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        return read_overview(runner, current_user)

    return (
        ToolDefinition(
            name="process_overview",
            risk=RiskLevel.LOW,
            arguments={},
            handler=handle,
            description=(
                "Report how many programs are running on this Mac and which use the most "
                "processor and memory."
            ),
            timeout_seconds=15.0,
            max_calls=5,
        ),
    )
