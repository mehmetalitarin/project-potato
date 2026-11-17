"""Push-to-talk: the microphone follows Potato's state (T-VOICE-4).

The rules:

- **Only while active.** The microphone opens only if Potato is active,
  and only when asked (the user holding "Hold to talk"). It never opens by
  itself.
- **Closed the moment Potato leaves Active.** Sleep, the idle timer and an
  error all close it at once, and the audio recorded so far is thrown away.
  If it cannot be closed, this raises inside the state change, so the state
  manager moves Potato to Error.
- **Audio stays in memory.** It is handed straight to the transcriber and
  never written anywhere.

This module cannot approve anything and cannot reach the tools: what was
heard goes to the turn engine as ``RequestOrigin.VOICE``, which the gate
limits to low-risk tools (P6).
"""

import contextlib
import threading
from collections.abc import Callable

from potato.core.state import AssistantState, StateManager
from potato.voice.microphone import Microphone, MicrophoneError

Transcriber = Callable[[bytes], str]


class Ears:
    """The microphone and speech-to-text, tied to Potato's state."""

    def __init__(self, state: StateManager, microphone: Microphone, transcriber: Transcriber):
        """Attach to ``state``. The microphone stays closed."""
        self._state = state
        self._microphone = microphone
        self._transcriber = transcriber
        # Re-entrant: a change of state may arrive while the microphone opens.
        self._lock = threading.RLock()
        self._level_listeners: list[Callable[[float], None]] = []
        state.subscribe(self._on_state_change)

    @property
    def listening(self) -> bool:
        """Whether the microphone is open."""
        return self._microphone.is_open

    def on_level(self, listener: Callable[[float], None]) -> None:
        """Call ``listener`` with the loudness, 0 to 1, while recording."""
        with self._lock:
            self._level_listeners.append(listener)

    def _level(self, level: float) -> None:
        with self._lock:
            listeners = list(self._level_listeners)
        for listener in listeners:
            with contextlib.suppress(Exception):
                listener(level)

    def start(self) -> bool:
        """Open the microphone, only if Potato is active. Whether it opened."""
        with self._lock:
            if not self._active():
                return False
            try:
                self._microphone.open(self._level)
            except MicrophoneError:
                return False
        # Potato may have left the active state while the microphone opened.
        if not self._active():
            self.discard()
            return False
        return True

    def _active(self) -> bool:
        return self._state.state is AssistantState.ACTIVE

    def stop(self) -> bytes:
        """Close the microphone and hand back what was recorded.

        Gives ``b""`` if Potato is no longer active, so nothing recorded
        across a change of state is ever used.
        """
        with self._lock:
            audio = self._microphone.close()
            if not self._active():
                return b""
            return audio

    def discard(self) -> None:
        """Close the microphone and throw the audio away.

        Raises:
            MicrophoneError: The microphone could not be closed.
        """
        with self._lock:
            self._microphone.close()

    def transcribe(self, audio: bytes) -> str:
        """Turn audio into text. May be slow: call it off the main thread."""
        if not audio:
            return ""
        return self._transcriber(audio)

    def _on_state_change(self, old: AssistantState, new: AssistantState) -> None:
        # Raising here makes the state manager move Potato to Error.
        if new is not AssistantState.ACTIVE:
            self.discard()
