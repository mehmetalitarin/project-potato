"""The assistant's states, and the only rules for moving between them.

Every state says what may run in it: the microphone, the wake-word detector,
speech-to-text and the model. The state manager decides the state. Other
parts (the microphone, the model client) follow it by subscribing to
changes. This module touches no hardware itself.

Three rules matter for security (T-VOICE-1 and T-VOICE-4 in
``docs/threat_model.md``):

- **Voice can only reduce what Potato does.** Voice can wake Potato from
  standby and can put it to sleep. It can never leave Sleeping or Error. Only
  the interface can, after a click or a key press.
- **Opening needs a record, closing does not.** A change that opens the
  microphone or loads the model is written to the audit log first, and is
  refused if that fails. A change that closes things goes ahead even if the
  record cannot be written, because becoming safer must never be blocked.
- **Fail closed.** If a subscriber fails during a change, Potato moves to
  Error, where the microphone is closed.

Potato starts in Sleeping. Nothing listens until the interface wakes it.
"""

import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from potato.security.audit import AuditEvent, AuditLog, AuditLogError

_log = logging.getLogger(__name__)


class AssistantState(StrEnum):
    """What the assistant is doing. "Off" is not a state: the program is not running."""

    SLEEPING = "sleeping"
    STANDBY = "standby"
    ACTIVE = "active"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What may run in a state."""

    microphone_open: bool
    wake_word: bool
    speech_to_text: bool
    model_loaded: bool


CAPABILITIES: Final[Mapping[AssistantState, Capabilities]] = MappingProxyType(
    {
        AssistantState.SLEEPING: Capabilities(False, False, False, False),
        AssistantState.STANDBY: Capabilities(True, True, False, False),
        AssistantState.ACTIVE: Capabilities(True, False, True, True),
        AssistantState.ERROR: Capabilities(False, False, False, False),
    }
)

# How much each state exposes. A change to a higher number opens something.
_EXPOSURE: Final[Mapping[AssistantState, int]] = MappingProxyType(
    {
        AssistantState.SLEEPING: 0,
        AssistantState.ERROR: 0,
        AssistantState.STANDBY: 1,
        AssistantState.ACTIVE: 2,
    }
)


class Origin(StrEnum):
    """Where a request to change state came from."""

    VOICE = "voice"
    INTERFACE = "interface"
    SYSTEM = "system"


class Event(StrEnum):
    """Something that asks for a change of state."""

    # Voice
    WAKE_WORD_HEARD = "wake_word_heard"
    VOICE_SLEEP = "voice_sleep"
    # The interface, from a click or key press
    INTERFACE_WAKE = "interface_wake"
    INTERFACE_TALK = "interface_talk"
    INTERFACE_SLEEP = "interface_sleep"
    # Potato itself
    IDLE_TIMEOUT = "idle_timeout"
    FAILURE = "failure"


ORIGINS: Final[Mapping[Event, Origin]] = MappingProxyType(
    {
        Event.WAKE_WORD_HEARD: Origin.VOICE,
        Event.VOICE_SLEEP: Origin.VOICE,
        Event.INTERFACE_WAKE: Origin.INTERFACE,
        Event.INTERFACE_TALK: Origin.INTERFACE,
        Event.INTERFACE_SLEEP: Origin.INTERFACE,
        Event.IDLE_TIMEOUT: Origin.SYSTEM,
        Event.FAILURE: Origin.SYSTEM,
    }
)

_S = AssistantState

# Every allowed change. Anything not listed is refused.
TRANSITIONS: Final[Mapping[tuple[AssistantState, Event], AssistantState]] = MappingProxyType(
    {
        # Leaving Sleeping or Error needs the interface.
        (_S.SLEEPING, Event.INTERFACE_WAKE): _S.STANDBY,
        (_S.SLEEPING, Event.INTERFACE_TALK): _S.ACTIVE,
        (_S.ERROR, Event.INTERFACE_WAKE): _S.STANDBY,
        (_S.ERROR, Event.INTERFACE_SLEEP): _S.SLEEPING,
        # Standby
        (_S.STANDBY, Event.WAKE_WORD_HEARD): _S.ACTIVE,
        (_S.STANDBY, Event.INTERFACE_TALK): _S.ACTIVE,
        (_S.STANDBY, Event.VOICE_SLEEP): _S.SLEEPING,
        (_S.STANDBY, Event.INTERFACE_SLEEP): _S.SLEEPING,
        # Active
        (_S.ACTIVE, Event.IDLE_TIMEOUT): _S.STANDBY,
        (_S.ACTIVE, Event.VOICE_SLEEP): _S.SLEEPING,
        (_S.ACTIVE, Event.INTERFACE_SLEEP): _S.SLEEPING,
        # Anything can fail.
        (_S.SLEEPING, Event.FAILURE): _S.ERROR,
        (_S.STANDBY, Event.FAILURE): _S.ERROR,
        (_S.ACTIVE, Event.FAILURE): _S.ERROR,
        (_S.ERROR, Event.FAILURE): _S.ERROR,
    }
)

INITIAL_STATE: Final = AssistantState.SLEEPING

Listener = Callable[[AssistantState, AssistantState], None]
"""Called with the old and new state after every change."""


class StateTransitionError(Exception):
    """A change of state was refused. The state is unchanged."""


class StateManager:
    """Holds the current state and applies the transition rules.

    Thread-safe. Listeners run in the thread that asked for the change, one
    after another, and must not ask for another change themselves: a
    listener that cannot follow a change should raise, and Potato then moves
    to Error.
    """

    def __init__(
        self,
        idle_timeout_seconds: float,
        audit: AuditLog | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Start in Sleeping.

        Args:
            idle_timeout_seconds: Time in Active without activity before
                Potato returns to standby. Validated by the settings.
            audit: Where changes are recorded. ``None`` only in tests and
                tools that run without an audit log.
            clock: Returns seconds from a monotonic clock. Tests replace it.

        Raises:
            ValueError: ``idle_timeout_seconds`` is not above zero.
        """
        if not idle_timeout_seconds > 0:
            raise ValueError("idle_timeout_seconds must be above zero")
        self._idle_timeout = idle_timeout_seconds
        self._audit = audit
        self._clock = clock
        self._state = INITIAL_STATE
        self._last_activity = clock()
        self._listeners: list[Listener] = []
        self._lock = threading.RLock()
        self._changing = False

    @property
    def state(self) -> AssistantState:
        """The current state."""
        return self._state

    @property
    def capabilities(self) -> Capabilities:
        """What may run in the current state."""
        return CAPABILITIES[self._state]

    def subscribe(self, listener: Listener) -> None:
        """Call ``listener`` after every change of state."""
        with self._lock:
            self._listeners.append(listener)

    def handle(self, event: Event) -> AssistantState:
        """Apply ``event`` and return the new state.

        Raises:
            StateTransitionError: The rules do not allow ``event`` in the
                current state, a listener asked for a change during another
                change, or the change opens something and could not be
                recorded. The state is unchanged.
        """
        if not isinstance(event, Event):
            raise StateTransitionError("unknown event")
        with self._lock:
            if self._changing:
                raise StateTransitionError("a change of state is already in progress")
            old = self._state
            new = TRANSITIONS.get((old, event))
            if new is None:
                raise StateTransitionError(f"{event} is not allowed in {old}")
            self._record(old, new, event)
            self._apply(old, new)
            return self._state

    def fail(self) -> None:
        """Move to Error from any state, which closes everything.

        For the application's own error handling. A listener that cannot
        follow a change should raise instead.

        Raises:
            StateTransitionError: Called by a listener during a change.
        """
        with self._lock:
            if self._changing:
                raise StateTransitionError("a change of state is already in progress")
            old = self._state
            self._record(old, AssistantState.ERROR, Event.FAILURE)
            self._apply(old, AssistantState.ERROR)

    def record_activity(self) -> None:
        """Note that the user did something, which restarts the idle timer."""
        with self._lock:
            self._last_activity = self._clock()

    def check_idle(self) -> bool:
        """Return to standby if Active has been idle for too long.

        Called regularly by the application.

        Returns:
            ``True`` if Potato went back to standby.
        """
        with self._lock:
            if self._state is not AssistantState.ACTIVE:
                return False
            if self._clock() - self._last_activity < self._idle_timeout:
                return False
            self.handle(Event.IDLE_TIMEOUT)
            return True

    def _record(self, old: AssistantState, new: AssistantState, event: Event) -> None:
        """Write the change to the audit log, refusing an opening that cannot be recorded."""
        if self._audit is None:
            return
        try:
            self._audit.append(
                AuditEvent.STATE_CHANGED,
                from_state=old.value,
                to_state=new.value,
                trigger=event.value,
                origin=ORIGINS[event].value,
            )
        except AuditLogError:
            if _EXPOSURE[new] > _EXPOSURE[old]:
                raise StateTransitionError(
                    "the change could not be recorded, so it was refused"
                ) from None
            _log.warning("A change to a safer state could not be recorded")

    def _apply(self, old: AssistantState, new: AssistantState) -> None:
        """Set the state, tell the listeners, and fall to Error if one fails."""
        self._state = new
        if new is AssistantState.ACTIVE:
            self._last_activity = self._clock()
        if self._notify(old, new) or new is AssistantState.ERROR:
            return
        # A listener could not follow. Close everything.
        self._record(new, AssistantState.ERROR, Event.FAILURE)
        self._state = AssistantState.ERROR
        _log.error("A component failed to follow a change of state; moved to error")
        self._notify(new, AssistantState.ERROR)

    def _notify(self, old: AssistantState, new: AssistantState) -> bool:
        """Call every listener, even after one fails. Return ``True`` if none failed."""
        self._changing = True
        succeeded = True
        try:
            for listener in list(self._listeners):
                try:
                    listener(old, new)
                except Exception:
                    # The details are dropped on purpose: a listener's error
                    # text is not checked for private content.
                    _log.error("A state listener failed")
                    succeeded = False
        finally:
            self._changing = False
        return succeeded
