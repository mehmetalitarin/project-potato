"""The main window: a conversation by typing, and what state Potato is in.

What the window guarantees (``docs/architecture.md``, "The interface"):

- **Plain text only.** Every piece of text is shown as plain text, never as
  rich text or HTML, so a reply cannot draw buttons, fake a warning, load an
  image or contain a link. Hidden and direction-changing characters are
  replaced first (``potato.ui.text``).
- **The window states the origin.** Typed words are sent as
  ``RequestOrigin.TYPED``. The words cannot change that.
- **One turn at a time, off the main thread.** The window stays responsive
  while the model thinks, and the input is disabled until the turn ends.
- **Errors are fixed sentences.** If a turn fails unexpectedly, the window
  shows a fixed sentence, never the error's own text.
- **Closing puts Potato to sleep.** The microphone and the model are released
  when the window closes.
- **Nothing is logged here.** The conversation is shown, not stored
  (T-DATA-4).

Approvals for sensitive actions are not part of this window yet. Until the
approval dialog exists, such an action is reported and not run.
"""

import threading
from collections.abc import Callable
from typing import Final, Protocol

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from potato.core.state import AssistantState, Event, StateManager, StateTransitionError
from potato.core.turns import MAX_USER_CHARACTERS, TurnResult, TurnStatus
from potato.security.gate import RequestOrigin
from potato.ui.text import displayable

TITLE: Final = "Potato"
MAX_TRANSCRIPT_LINES: Final = 2000

STATE_TEXT: Final = {
    AssistantState.SLEEPING: "Sleeping: not listening, model not loaded.",
    AssistantState.STANDBY: "Standby: listening for the wake word only.",
    AssistantState.ACTIVE: "Active: ready for a request.",
    AssistantState.ERROR: "Something went wrong, so everything was closed. Wake Potato to retry.",
}
TEXT_THINKING: Final = "Thinking..."
TEXT_TURN_FAILED: Final = "Something went wrong with that request. Nothing was run."
TEXT_CANNOT_WAKE: Final = "Potato could not wake up just now."
TEXT_NEEDS_APPROVAL: Final = (
    "An action needed your approval. Approvals are not available yet, so it was not run."
)
YOU: Final = "You"
POTATO: Final = "Potato"


class Conversation(Protocol):
    """The part of the turn engine the window needs."""

    def run(self, words: str, origin: RequestOrigin) -> TurnResult:
        """Run one turn and return the reply."""
        ...


class _Bridge(QObject):
    """Carries results from other threads to the window, safely.

    A signal sent from another thread is delivered on the window's own
    thread, which is the only thread allowed to touch the widgets.
    """

    turn_finished = Signal(object)
    state_changed = Signal(object)


Starter = Callable[[Callable[[], None]], None]


def _start_thread(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="potato-turn", daemon=True).start()


class PotatoWindow(QMainWindow):
    """Potato's main window."""

    def __init__(
        self,
        conversation: Conversation,
        state: StateManager,
        *,
        start: Starter = _start_thread,
    ) -> None:
        """Build the window. Nothing runs until the user acts.

        Args:
            conversation: Runs turns. Called from a worker thread.
            state: Potato's state. The window may wake Potato, because a click
                is a physical action (``Event.INTERFACE_*``).
            start: How a turn is started in the background. Tests replace it.
        """
        super().__init__()
        self._conversation = conversation
        self._state = state
        self._start = start
        self._busy = False
        self._bridge = _Bridge()
        self._bridge.turn_finished.connect(self._show_result)
        self._bridge.state_changed.connect(self._show_state)

        self.setWindowTitle(TITLE)
        self.status = self._plain_label("")
        self.wake_button = QPushButton("Wake")
        self.sleep_button = QPushButton("Sleep")
        self.wake_button.clicked.connect(self._wake)
        self.sleep_button.clicked.connect(self._sleep)

        self.transcript = QPlainTextEdit()
        self.transcript.setReadOnly(True)
        self.transcript.setMaximumBlockCount(MAX_TRANSCRIPT_LINES)
        self.transcript.setUndoRedoEnabled(False)

        self.entry = QLineEdit()
        self.entry.setMaxLength(MAX_USER_CHARACTERS)
        self.entry.setPlaceholderText("Type a request and press Return")
        self.entry.returnPressed.connect(self.send)
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send)

        top = QHBoxLayout()
        top.addWidget(self.status, 1)
        top.addWidget(self.wake_button)
        top.addWidget(self.sleep_button)
        bottom = QHBoxLayout()
        bottom.addWidget(self.entry, 1)
        bottom.addWidget(self.send_button)
        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(self.transcript, 1)
        layout.addLayout(bottom)
        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)
        self.resize(640, 480)

        state.subscribe(self._on_state_change)
        self._show_state(state.state)

    # --- Building blocks ----------------------------------------------------

    @staticmethod
    def _plain_label(text: str) -> QLabel:
        label = QLabel(text)
        # A label guesses whether text is rich text unless told. Never guess.
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        label.setOpenExternalLinks(False)
        label.setWordWrap(True)
        return label

    def _say(self, who: str, text: str) -> None:
        self.transcript.appendPlainText(f"{who}: {displayable(text)}")

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.entry.setEnabled(not busy)
        self.send_button.setEnabled(not busy)

    # --- State --------------------------------------------------------------

    def _on_state_change(self, old: AssistantState, new: AssistantState) -> None:
        # May be called from any thread. Never raises, so it never blocks a
        # change of state that closes something.
        self._bridge.state_changed.emit(new)

    def _show_state(self, state: object) -> None:
        if isinstance(state, AssistantState):
            self.status.setText(STATE_TEXT[state])

    def _wake(self) -> None:
        try:
            self._state.handle(Event.INTERFACE_WAKE)
        except StateTransitionError:
            self._say(POTATO, TEXT_CANNOT_WAKE)

    def _sleep(self) -> None:
        # Refused only if Potato is already asleep, which is the goal anyway.
        try:
            self._state.handle(Event.INTERFACE_SLEEP)
        except StateTransitionError:
            return

    # --- Turns --------------------------------------------------------------

    def send(self) -> None:
        """Send what is in the input box as one typed request."""
        if self._busy:
            return
        words = self.entry.text()
        if not words.strip():
            return
        if self._state.state is not AssistantState.ACTIVE:
            try:
                self._state.handle(Event.INTERFACE_TALK)
            except StateTransitionError:
                self._say(POTATO, TEXT_CANNOT_WAKE)
                return
        self._state.record_activity()
        self.entry.clear()
        self._say(YOU, words)
        self._set_busy(True)
        self.status.setText(TEXT_THINKING)
        self._start(lambda: self._run_turn(words))

    def _run_turn(self, words: str) -> None:
        # Runs on a worker thread: touches no widget.
        try:
            result: object = self._conversation.run(words, RequestOrigin.TYPED)
        except Exception:
            result = None
        self._bridge.turn_finished.emit(result)

    def _show_result(self, result: object) -> None:
        self._set_busy(False)
        self._show_state(self._state.state)
        if not isinstance(result, TurnResult):
            self._say(POTATO, TEXT_TURN_FAILED)
            return
        if any(outcome.pending is not None for outcome in result.outcomes):
            self._say(POTATO, TEXT_NEEDS_APPROVAL)
        if result.text or result.status is not TurnStatus.ANSWERED:
            self._say(POTATO, result.text or TEXT_TURN_FAILED)
        self.entry.setFocus()

    # --- Closing ------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt's name
        """Put Potato to sleep before the window goes away."""
        self._sleep()
        event.accept()
