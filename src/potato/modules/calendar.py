"""The calendar tools: upcoming events and homework deadlines. Read-only.

Two tools, both low risk:

- ``calendar_upcoming``: events in the next 1 to 14 days.
- ``homework_deadlines``: events in the next 1 to 60 days whose title says
  something is due, such as "Coursework 2 due" or "Lab report deadline".

Event text is written by whoever created the event, which can be anyone who
sends the user an invitation (T-NET-2, T-LLM-1). So before anything else sees
it:

- control characters are removed, so text cannot hide or reorder itself;
- titles and calendar names are cut to a fixed length;
- the result is filled up to a fixed size, earliest events first, so a flood
  of invitations cannot crowd it out and the model can still read it whole;
- times must be real numbers in a sensible range, and are written out by
  this code.

The text still reaches the model, in the second, tool-free pass of a turn,
where it cannot cause an action (R6). The interface will show the events
themselves next to the model's summary (T-LLM-4).

Deadlines are recognised from a fixed list of words in the title. That is a
heuristic: a deadline whose title uses none of the words is missed.
"""

import json
import re
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Final

from potato.integrations.calendar import (
    CalendarProblem,
    CalendarUnavailableError,
    RawEvent,
    read_events,
)
from potato.security.tools import ArgumentValue, IntegerField, RiskLevel, ToolDefinition

# The largest result, as the gate measures it (JSON with non-ASCII letters
# escaped). Small enough that the model reads it whole: the conversation
# code replaces a result over 4000 characters with a placeholder.
RESULT_BUDGET_CHARACTERS: Final = 3400
MAX_TITLE_CHARACTERS: Final = 120
MAX_CALENDAR_CHARACTERS: Final = 60
UPCOMING_DAYS: Final = IntegerField(1, 14)
DEADLINE_DAYS: Final = IntegerField(1, 60)
# Times outside this range are refused: 2000-01-01 to 2100-01-01.
_EARLIEST: Final = 946_684_800.0
_LATEST: Final = 4_102_444_800.0

_DEADLINE_WORDS: Final = frozenset(
    {
        "due", "deadline", "deadlines", "submit", "submission", "submissions", "hand-in",
        "handin", "coursework", "assignment", "assignments", "homework", "essay", "report",
        "exam", "exams", "test", "quiz", "presentation",
    }
)  # fmt: skip

UNAVAILABLE: Final[Mapping[CalendarProblem, str]] = {
    CalendarProblem.NOT_ON_MACOS: "Apple Calendar is only available on macOS.",
    CalendarProblem.NO_ACCESS: (
        "Potato does not have access to Apple Calendar. It can be allowed in System "
        "Settings, under Privacy & Security, then Calendars."
    ),
    CalendarProblem.FAILED: "Apple Calendar could not be read just now.",
}
TEXT_NOTE: Final = "Event titles and calendar names are shown as their authors wrote them."
NO_TITLE: Final = "(no title)"

Reader = Callable[[float, float], Sequence[RawEvent]]
Clock = Callable[[], float]


def clean_text(value: object, limit: int) -> str | None:
    """Return ``value`` as safe, short, single-line text, or ``None`` if it has none."""
    # PyObjC hands over text as a subclass of str, so isinstance is right here.
    if not isinstance(value, str):
        return None
    kept = "".join(
        " " if unicodedata.category(character).startswith(("C", "Z")) else character
        for character in str(value)
    )
    text = " ".join(kept.split())
    if not text:
        return None
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def _time(value: object) -> float | None:
    """Return a timestamp if it is a real number in a sensible range."""
    if type(value) not in (int, float):
        return None
    number = float(value)  # type: ignore[arg-type]
    if not _EARLIEST <= number <= _LATEST:
        return None
    return number


def _iso(timestamp: float) -> str:
    """Write a time as local ISO 8601 text, to the minute."""
    return datetime.fromtimestamp(timestamp, UTC).astimezone().isoformat(timespec="minutes")


def _is_deadline(title: str) -> bool:
    words = set(re.split(r"[^a-z\-]+", title.lower()))
    return bool(words & _DEADLINE_WORDS)


def _events(
    reader: Reader, clock: Clock, days: int, keep: Callable[[str], bool]
) -> Mapping[str, object]:
    now = clock()
    try:
        raw = reader(now, now + days * 86_400)
    except CalendarUnavailableError as error:
        return {"available": False, "message": UNAVAILABLE[error.problem], "events": []}

    events: list[tuple[float, dict[str, object]]] = []
    for event in raw:
        start, end = _time(event.start), _time(event.end)
        if start is None or end is None or end < start:
            continue
        title = clean_text(event.title, MAX_TITLE_CHARACTERS) or NO_TITLE
        if not keep(title):
            continue
        events.append(
            (
                start,
                {
                    "title": title,
                    "calendar": clean_text(event.calendar, MAX_CALENDAR_CHARACTERS),
                    "start": _iso(start),
                    "end": _iso(end),
                    "all_day": event.all_day is True,
                },
            )
        )
    events.sort(key=lambda pair: pair[0])
    result: dict[str, object] = {
        "available": True,
        "days": days,
        "count": len(events),
        "listed": 0,
        "events": [],
        "note": TEXT_NOTE,
    }
    listed: list[dict[str, object]] = []
    size = len(json.dumps(result))
    for _, entry in events:
        # Each further event adds its own text and a separating ", ".
        cost = len(json.dumps(entry)) + 2
        if size + cost > RESULT_BUDGET_CHARACTERS:
            break
        listed.append(entry)
        size += cost
    result["events"] = listed
    result["listed"] = len(listed)
    return result


def calendar_tools(
    reader: Reader = read_events, clock: Clock = time.time
) -> tuple[ToolDefinition, ...]:
    """Return the two calendar tools.

    The arguments exist for tests, which cannot use a real calendar.
    """

    def upcoming(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        return _events(reader, clock, int(arguments["days"]), lambda title: True)

    def deadlines(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        return _events(reader, clock, int(arguments["days"]), _is_deadline)

    return (
        ToolDefinition(
            name="calendar_upcoming",
            risk=RiskLevel.LOW,
            arguments={"days": UPCOMING_DAYS},
            handler=upcoming,
            description="List the user's calendar events for the next number of days.",
            # The first use may show macOS's permission prompt and wait for it.
            timeout_seconds=120.0,
        ),
        ToolDefinition(
            name="homework_deadlines",
            risk=RiskLevel.LOW,
            arguments={"days": DEADLINE_DAYS},
            handler=deadlines,
            description=(
                "List the user's upcoming deadlines, such as coursework or exams, for the "
                "next number of days."
            ),
            timeout_seconds=120.0,
        ),
    )
