"""Reads events from Apple Calendar, through Apple's EventKit. Read-only.

macOS grants calendar access as all or nothing: an app that may read events
may also change and delete them. Potato only reads, and that is enforced
here, in code (T-TOOL-2 in ``docs/threat_model.md``):

- This module calls EventKit to check access, to ask for it, and to fetch
  the events in a time range. Nothing else. A test reads this file and fails
  if any name in it mentions saving, removing, committing or deleting.
- It is the only module allowed to use PyObjC, the bridge to Apple's
  frameworks, so no other code can reach EventKit (R3 and the import rules in
  ``tests/test_architecture.py``).
- It reads only an event's title, times, all-day flag and calendar name.
  Notes, locations, links and attendees are never read, so they cannot leak
  or carry text aimed at the model.

Everything returned is untrusted: anyone who can send the user an
invitation, or edit a subscribed calendar, chooses the text. The tools in
``potato.modules.calendar`` clean and cap it before anything else sees it.
"""

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

# EventKit's own numbers (EKEntityType and EKAuthorizationStatus).
_EVENTS: Final = 0
_FULL_ACCESS: Final = 3
_NOT_DETERMINED: Final = 0

ACCESS_WAIT_SECONDS: Final = 120.0
MAX_EVENTS_FETCHED: Final = 500


class CalendarProblem(Enum):
    """Why events could not be read."""

    NOT_ON_MACOS = "not_on_macos"
    NO_ACCESS = "no_access"
    FAILED = "failed"


class CalendarUnavailableError(Exception):
    """Events could not be read. Carries a ``CalendarProblem`` and nothing else."""

    def __init__(self, problem: CalendarProblem) -> None:
        """Remember the problem."""
        super().__init__(problem.value)
        self.problem = problem


@dataclass(frozen=True, slots=True)
class RawEvent:
    """One event as EventKit gave it. The text is untrusted and not yet checked.

    Attributes:
        title: The event's title, or ``None``.
        calendar: The name of the calendar it is in, or ``None``.
        start: Seconds since 1970 (UTC).
        end: Seconds since 1970 (UTC).
        all_day: Whether it is an all-day event.
    """

    title: object
    calendar: object
    start: object
    end: object
    all_day: object


def _event_kit() -> Any:
    """Load EventKit, or report that it is not available here."""
    try:
        import EventKit
    except ImportError:
        raise CalendarUnavailableError(CalendarProblem.NOT_ON_MACOS) from None
    return EventKit


def _ensure_access(event_kit: Any, store: Any) -> None:
    """Make sure Potato may read events, asking the user if they have not decided."""
    status = event_kit.EKEventStore.authorizationStatusForEntityType_(_EVENTS)
    if status == _FULL_ACCESS:
        return
    if status != _NOT_DETERMINED:
        raise CalendarUnavailableError(CalendarProblem.NO_ACCESS)

    # macOS shows its own permission prompt. The answer arrives on another
    # thread, so wait for it, but not for ever.
    answered = threading.Event()
    granted: list[bool] = []

    def done(allowed: bool, error: object) -> None:
        granted.append(bool(allowed))
        answered.set()

    store.requestFullAccessToEventsWithCompletion_(done)
    if not answered.wait(ACCESS_WAIT_SECONDS) or not granted or not granted[0]:
        raise CalendarUnavailableError(CalendarProblem.NO_ACCESS)


def read_events(start: float, end: float) -> list[RawEvent]:
    """Return the events between ``start`` and ``end``, in seconds since 1970.

    Raises:
        CalendarUnavailableError: Not on macOS, no permission, or EventKit
            failed. The error carries no text from EventKit.
    """
    event_kit = _event_kit()
    try:
        from Foundation import NSDate

        store = event_kit.EKEventStore.alloc().init()
        _ensure_access(event_kit, store)
        query = store.predicateForEventsWithStartDate_endDate_calendars_(
            NSDate.dateWithTimeIntervalSince1970_(start),
            NSDate.dateWithTimeIntervalSince1970_(end),
            None,
        )
        found = store.eventsMatchingPredicate_(query) or []
        events = []
        for event in list(found)[:MAX_EVENTS_FETCHED]:
            calendar = event.calendar()
            events.append(
                RawEvent(
                    title=event.title(),
                    calendar=None if calendar is None else calendar.title(),
                    start=event.startDate().timeIntervalSince1970(),
                    end=event.endDate().timeIntervalSince1970(),
                    all_day=event.isAllDay(),
                )
            )
    except CalendarUnavailableError:
        raise
    except Exception:
        # EventKit's own error text is not kept.
        raise CalendarUnavailableError(CalendarProblem.FAILED) from None
    return events
