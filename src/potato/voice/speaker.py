"""Reading Potato's replies aloud.

The speaker decides *what* may be said and *when*; starting the voice itself
is handed in (``start``), so this package never starts a program. In the
application, ``start`` is ``start_speaking`` from the processes integration.

The rules:

- **Only while active.** Nothing is said unless Potato is active, and
  anything being said stops the moment Potato leaves the active state, for
  any reason (sleep, the idle timer, an error).
- **Show, don't speak.** A reply that used a tool which reads private or
  detailed data (the calendar, the portfolio, this Mac's programs) is not
  read out. A short fixed sentence is said instead, and the detail stays on
  screen. Tools are allowed to be read out one by one; a new tool is
  shown, not spoken, until it is added here.
- **A time limit.** A reply is cut off after ``MAX_SPEECH_SECONDS``.
- **One at a time.** A new reply stops the one before.
"""

import contextlib
import threading
from collections.abc import Callable
from typing import Final, Protocol

from potato.core.state import AssistantState, StateManager
from potato.core.turns import TurnResult, TurnStatus

MAX_SPEECH_SECONDS: Final = 45.0
TEXT_ON_SCREEN: Final = "Here it is, on screen."

# Tools whose replies may be read aloud. Everything else is shown only.
SPEAKABLE_TOOLS: Final = frozenset({"open_app"})


class Speech(Protocol):
    """Something being said."""

    def wait(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds; whether it has finished."""
        ...

    def stop(self) -> None:
        """Stop now."""
        ...


StartSpeech = Callable[[str], Speech | None]
Starter = Callable[[Callable[[], None]], None]


def _start_thread(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="potato-speech", daemon=True).start()


def what_to_say(result: object) -> str:
    """The words to say for ``result``. ``""`` means say nothing."""
    if not isinstance(result, TurnResult):
        return ""
    if result.status is not TurnStatus.ANSWERED:
        # A fixed sentence written in Potato's code.
        return result.text
    if any(outcome.tool not in SPEAKABLE_TOOLS for outcome in result.outcomes):
        return TEXT_ON_SCREEN
    return result.text


class Speaker:
    """Reads replies aloud, only while Potato is active."""

    def __init__(
        self,
        state: StateManager,
        start: StartSpeech,
        *,
        run: Starter = _start_thread,
        max_seconds: float = MAX_SPEECH_SECONDS,
    ) -> None:
        """Build the speaker and attach it to ``state``. Says nothing yet."""
        self._state = state
        self._start = start
        self._run = run
        self._max_seconds = max_seconds
        self._lock = threading.Lock()
        self._current: Speech | None = None
        self._listeners: list[Callable[[bool], None]] = []
        state.subscribe(self._on_state_change)

    def on_speaking(self, listener: Callable[[bool], None]) -> None:
        """Call ``listener`` with ``True`` when speech starts and ``False`` when it ends."""
        with self._lock:
            self._listeners.append(listener)

    @property
    def speaking(self) -> bool:
        """Whether something is being said."""
        with self._lock:
            return self._current is not None

    def reply(self, result: object) -> bool:
        """Read out the right words for a turn's result. Whether it started."""
        return self.say(what_to_say(result))

    def say(self, text: str) -> bool:
        """Say ``text`` if Potato is active. Whether it started."""
        self.stop()
        if not text or not self._active():
            return False
        speech = self._start(text)
        if speech is None:
            return False
        with self._lock:
            # Potato may have left the active state while ``say`` started.
            if not self._active():
                speech.stop()
                return False
            self._current = speech
        self._tell(True)
        self._run(lambda: self._watch(speech))
        return True

    def _active(self) -> bool:
        return self._state.state is AssistantState.ACTIVE

    def stop(self) -> None:
        """Stop anything being said. Safe from any thread."""
        with self._lock:
            speech, self._current = self._current, None
        if speech is not None:
            speech.stop()
            self._tell(False)

    def _watch(self, speech: Speech) -> None:
        finished = speech.wait(self._max_seconds)
        if not finished:
            speech.stop()
        with self._lock:
            if self._current is not speech:
                return  # Already stopped, or replaced by a newer reply.
            self._current = None
        self._tell(False)

    def _tell(self, speaking: bool) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            # A broken listener must never stop the speech from stopping.
            with contextlib.suppress(Exception):
                listener(speaking)

    def _on_state_change(self, old: AssistantState, new: AssistantState) -> None:
        # If the speech cannot be stopped, this raises, and the state manager
        # moves Potato to Error, which closes everything else.
        if new is not AssistantState.ACTIVE:
            self.stop()
