"""The security update check: does macOS have updates waiting?

One tool, ``check_security_updates`` (medium risk, so it can be typed but not
spoken). It asks Apple's own ``softwareupdate`` tool for its list of
available updates and reports them.

Why it is safe, and why it is medium risk (T-TOOL-3 in
``docs/threat_model.md``):

- ``softwareupdate --list`` only lists. It never downloads or installs, and
  Potato has no tool that does.
- It contacts Apple's update service, through Apple's own tool. Potato's code
  makes no connection. That outside contact, and the time it takes (up to a
  minute and a half), are why it is medium risk and rate-limited hard.
- **The tool's output is never passed on.** Each update's title must be
  short and plain, or it is replaced by a fixed label. Versions and sizes are
  read as numbers. Every sentence is fixed text written here.
- **No false all-clear.** "Up to date" is reported only if the tool said
  exactly that. Anything unexpected is "could not be read".
"""

import re
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final

from potato.integrations.processes import Probe, run_probe
from potato.security.tools import ArgumentValue, RiskLevel, ToolDefinition

MAX_UPDATES: Final = 10
UNUSUAL_TITLE: Final = "(update with an unusual name)"

# "*" marks a recommended update and "-" one that is not.
_LABEL: Final = re.compile(r"[*\-] Label: .{1,200}")
_DETAILS: Final = re.compile(
    r"Title: (?P<title>[^,]{1,200}), Version:(?: (?P<version>[^,]{0,40}))?,"
    r" Size: [0-9]{1,12}(?:K|KiB|M|MiB|G|GiB)?,"
    r"(?: Recommended: (?P<recommended>YES|NO),)?"
    r"(?: Action: (?P<action>[a-z ]{1,20}),)?"
)
_PLAIN_TITLE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .()+\-]{0,79}")
_PLAIN_VERSION: Final = re.compile(r"[0-9A-Za-z][0-9A-Za-z.\-]{0,29}")

_NOTHING_NEW: Final = "No new software available."
_FOUND: Final = "Software Update found the following new or updated software:"
# Lines the tool prints around its answer, which carry no information.
_CHATTER: Final = frozenset({"Software Update Tool", "Finding available software"})

SUMMARIES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "available": "macOS has updates waiting. Install them in System Settings.",
        "up_to_date": "Apple's update tool reported no new updates.",
        "unavailable": "Apple's update tool could not be asked just now.",
    }
)
WARNING_UNREADABLE: Final = (
    "Some details could not be read, so some updates are shown without their names."
)
NOTE: Final = (
    "Potato only lists updates and cannot install them. If this Mac is offline, the "
    "update tool may not find updates that exist."
)


def _title(text: str) -> str:
    title = text.strip(" ")
    return title if _PLAIN_TITLE.fullmatch(title) else UNUSUAL_TITLE


def _unread_update() -> dict[str, object]:
    return {"title": UNUSUAL_TITLE, "version": None, "recommended": None, "needs_restart": None}


def parse_updates(output: str) -> tuple[list[dict[str, object]], int, int] | None:
    """Read ``softwareupdate --list`` output.

    Returns the updates, how many had unusual titles and how many lines could
    not be read, or ``None`` if the output is not one of the two expected
    answers. Once the tool has said updates exist, an unreadable line never
    turns that into "no updates": the update is listed with a fixed label.
    """
    lines = [line.strip() for line in output.split("\n")]
    lines = [line for line in lines if line and line not in _CHATTER]
    if lines == [_NOTHING_NEW]:
        return [], 0, 0
    if not lines or lines[0] != _FOUND:
        return None

    updates: list[dict[str, object]] = []
    unreadable = 0
    current: dict[str, object] | None = None
    for line in lines[1:]:
        if _LABEL.fullmatch(line):
            current = _unread_update()
            updates.append(current)
            continue
        found = _DETAILS.fullmatch(line)
        if current is None or found is None or current["recommended"] is not None:
            unreadable += 1
            continue
        version = (found.group("version") or "").strip(" ")
        current["title"] = _title(found.group("title"))
        current["version"] = version if _PLAIN_VERSION.fullmatch(version) else None
        current["recommended"] = found.group("recommended") == "YES"
        current["needs_restart"] = found.group("action") in ("restart", "shut down")
    unusual = sum(1 for update in updates if update["title"] == UNUSUAL_TITLE)
    if not updates:
        return None
    return updates, unusual, unreadable


def check_updates(runner: Callable[[Probe], str | None] = run_probe) -> dict[str, object]:
    """Ask Apple's tool for updates and return the answer as plain data."""
    output = runner(Probe.SOFTWARE_UPDATES)
    parsed = parse_updates(output) if type(output) is str else None
    if parsed is None:
        return {"summary": SUMMARIES["unavailable"], "note": NOTE}
    updates, unusual, unreadable = parsed
    warnings = [WARNING_UNREADABLE] if unreadable or unusual else []
    return {
        "summary": SUMMARIES["available" if updates else "up_to_date"],
        "updates": updates[:MAX_UPDATES],
        "updates_total": len(updates),
        "warnings": warnings,
        "note": NOTE,
    }


def security_update_tools(
    runner: Callable[[Probe], str | None] = run_probe,
) -> tuple[ToolDefinition, ...]:
    """Return the update check tool. The argument exists for tests."""

    def handle(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        return check_updates(runner)

    return (
        ToolDefinition(
            name="check_security_updates",
            risk=RiskLevel.MEDIUM,
            arguments={},
            handler=handle,
            description=(
                "Ask Apple's update tool whether macOS updates are waiting. Lists only; "
                "never installs."
            ),
            # The probe may take 90 seconds; the gate allows a little more.
            timeout_seconds=110.0,
            max_calls=2,
            period_seconds=600.0,
        ),
    )
