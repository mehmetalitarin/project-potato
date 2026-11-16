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

Sensitive actions (``potato.ui.approval`` has the dialog's own guarantees):

- The window asks about an action only if the gate itself said it is waiting
  for approval, and shows only the gate's validated copy of it.
- An approval is made inside the handler of the user's real press on
  Approve, for exactly the action that was shown, and only while Potato is
  active. It is handed straight to the gate, used once and never stored.
- The action is sent back with the same origin as the turn it came from
  (``typed``). Approving never upgrades where a request came from.
- If the window was built without the means to approve, a sensitive action
  is reported and not run.
"""

import threading
from collections.abc import Callable, Mapping
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
from potato.security.approvals import Approval, ApprovalError, ApprovalIssuer, ApprovalRequest
from potato.security.gate import MESSAGES, GateResult, RequestOrigin
from potato.ui.approval import (
    APPROVE_DELAY_MS,
    DIALOG_TIMEOUT_MS,
    ApprovalDialog,
    describe_action,
)
from potato.ui.orb import Orb, OrbBubble, mode_for
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
    "An action needed your approval. Approvals are not available, so it was not run."
)
TEXT_WORKING: Final = "Working..."
TEXT_APPROVED: Final = "Approved. Running it now."
TEXT_DENIED: Final = "Denied. Nothing was run."
TEXT_DONE: Final = "Done."
TEXT_CANNOT_SHOW: Final = (
    "An action could not be shown exactly, so it cannot be approved. Nothing was run."
)
TEXT_NOT_ACTIVE: Final = "Potato is no longer active, so the action was not run."
TEXT_APPROVAL_FAILED: Final = "The approval could not be recorded, so nothing was run."
TEXT_ACTION_FAILED: Final = "Something went wrong with that action."

# How this window's requests arrive. Used for the turn and again when an
# approved action goes back to the gate: approving never changes the origin.
ORIGIN: Final = RequestOrigin.TYPED
YOU: Final = "You"
POTATO: Final = "Potato"


class Conversation(Protocol):
    """The part of the turn engine the window needs."""

    def run(self, words: str, origin: RequestOrigin) -> TurnResult:
        """Run one turn and return the reply."""
        ...


class ActionGate(Protocol):
    """The part of the gate the window needs to run an approved action."""

    def submit(
        self, proposal: object, origin: RequestOrigin, approval: object = None
    ) -> GateResult:
        """Check a proposal and, if every check passes, run the tool."""
        ...


class _Bridge(QObject):
    """Carries results from other threads to the window, safely.

    A signal sent from another thread is delivered on the window's own
    thread, which is the only thread allowed to touch the widgets.
    """

    turn_finished = Signal(object)
    action_finished = Signal(object)
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
        issuer: ApprovalIssuer | None = None,
        gate: ActionGate | None = None,
        descriptions: Mapping[str, str] | None = None,
        start: Starter = _start_thread,
        approve_delay_ms: int = APPROVE_DELAY_MS,
        approval_timeout_ms: int = DIALOG_TIMEOUT_MS,
    ) -> None:
        """Build the window. Nothing runs until the user acts.

        Args:
            conversation: Runs turns. Called from a worker thread.
            state: Potato's state. The window may wake Potato, because a click
                is a physical action (``Event.INTERFACE_*``).
            issuer: Makes approvals. Only this window holds it (R4).
            gate: Runs an approved action. Needed together with ``issuer``;
                without both, sensitive actions are reported and not run.
            descriptions: A fixed sentence for each tool, written by Potato's
                code, to show in the approval dialog.
            start: How work is started in the background. Tests replace it.
            approve_delay_ms: How long Approve stays disabled after the
                dialog appears. Tests shorten it.
            approval_timeout_ms: How long the dialog waits before it denies.
        """
        super().__init__()
        self._conversation = conversation
        self._state = state
        self._issuer = issuer
        self._gate = gate
        self._descriptions = dict(descriptions or {})
        self._start = start
        self._approve_delay_ms = approve_delay_ms
        self._approval_timeout_ms = approval_timeout_ms
        self._busy = False
        # Actions waiting to be asked about, each with the proposal to hand
        # back to the gate, and the one being asked about now.
        self._waiting: list[tuple[object, object]] = []
        self._asking: tuple[ApprovalDialog, object] | None = None
        self._bridge = _Bridge()
        self._bridge.turn_finished.connect(self._show_result)
        self._bridge.action_finished.connect(self._show_action_result)
        self._bridge.state_changed.connect(self._show_state)

        self.setWindowTitle(TITLE)
        self.orb = Orb()
        self.orb.setFixedHeight(180)
        self.bubble = OrbBubble(self.show_from_bubble)
        self.status = self._plain_label("")
        self.wake_button = QPushButton("Wake")
        self.sleep_button = QPushButton("Sleep")
        self.mini_button = QPushButton("Mini")
        self.wake_button.clicked.connect(self._wake)
        self.sleep_button.clicked.connect(self._sleep)
        self.mini_button.clicked.connect(self.show_bubble)

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
        top.addWidget(self.mini_button)
        bottom = QHBoxLayout()
        bottom.addWidget(self.entry, 1)
        bottom.addWidget(self.send_button)
        layout = QVBoxLayout()
        layout.addWidget(self.orb)
        layout.addLayout(top)
        layout.addWidget(self.transcript, 1)
        layout.addLayout(bottom)
        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)
        self.resize(640, 620)

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

    @property
    def busy(self) -> bool:
        """Whether a request or an approval is in progress."""
        return self._busy

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.entry.setEnabled(not busy)
        self.send_button.setEnabled(not busy)
        self._update_orbs()

    def _update_orbs(self) -> None:
        # Thinking shows only while a request is with the model, not while an
        # approval dialog waits for the user.
        thinking = self._busy and self._asking is None
        mode = mode_for(self._state.state, busy=thinking)
        self.orb.set_mode(mode)
        self.bubble.orb.set_mode(mode)

    # --- The floating bubble ------------------------------------------------

    def show_bubble(self) -> None:
        """Shrink Potato into the floating bubble."""
        self.bubble.show()
        self.hide()

    def show_from_bubble(self) -> None:
        """Bring back the main window from the bubble."""
        self.bubble.hide()
        self.show()
        self.raise_()
        self.activateWindow()

    # --- State --------------------------------------------------------------

    def _on_state_change(self, old: AssistantState, new: AssistantState) -> None:
        # May be called from any thread. Never raises, so it never blocks a
        # change of state that closes something.
        self._bridge.state_changed.emit(new)

    def _show_state(self, state: object) -> None:
        if not isinstance(state, AssistantState):
            return
        self.status.setText(STATE_TEXT[state])
        self._update_orbs()
        if state is not AssistantState.ACTIVE and self._asking is not None:
            # Potato went to sleep or failed while asking. That is a "no".
            self._asking[0].reject()

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
            result: object = self._conversation.run(words, ORIGIN)
        except Exception:
            result = None
        self._bridge.turn_finished.emit(result)

    def _show_result(self, result: object) -> None:
        # The reply has just arrived: the idle timer starts from now, so
        # there is time to read it.
        self._state.record_activity()
        self._set_busy(False)
        self._show_state(self._state.state)
        if not isinstance(result, TurnResult):
            self._say(POTATO, TEXT_TURN_FAILED)
            return
        pending = [
            (outcome.pending, outcome.proposal)
            for outcome in result.outcomes
            if outcome.pending is not None
        ]
        can_approve = self._issuer is not None and self._gate is not None
        if pending and not can_approve:
            self._say(POTATO, TEXT_NEEDS_APPROVAL)
        if result.text or result.status is not TurnStatus.ANSWERED:
            self._say(POTATO, result.text or TEXT_TURN_FAILED)
        if pending and can_approve:
            self._waiting.extend(pending)
            self._ask_next()
        else:
            self.entry.setFocus()

    # --- Approvals ----------------------------------------------------------

    def _record_denial(self, request: object) -> None:
        # Never raises: a denial that cannot be recorded is still a denial.
        if self._issuer is not None and type(request) is ApprovalRequest:
            self._issuer.deny(request)

    def _ask_next(self) -> None:
        """Ask about the next waiting action, or hand the input back."""
        while self._waiting:
            request, proposal = self._waiting.pop(0)
            action = describe_action(request, self._descriptions)
            if action is None:
                self._record_denial(request)
                self._say(POTATO, TEXT_CANNOT_SHOW)
                continue
            if self._state.state is not AssistantState.ACTIVE:
                self._record_denial(request)
                self._say(POTATO, TEXT_NOT_ACTIVE)
                continue
            dialog = ApprovalDialog(
                action,
                self,
                approve_delay_ms=self._approve_delay_ms,
                timeout_ms=self._approval_timeout_ms,
            )
            self._asking = (dialog, proposal)
            dialog.finished.connect(self._decided)
            self._set_busy(True)
            self._update_orbs()
            self._state.record_activity()
            dialog.open()
            return
        self._set_busy(False)
        self._show_state(self._state.state)
        self.entry.setFocus()

    def _decided(self, code: int) -> None:
        """Act on the user's answer. Runs inside the handler of their press."""
        asking, self._asking = self._asking, None
        if asking is None or self._issuer is None or self._gate is None:
            return
        dialog, proposal = asking
        dialog.deleteLater()
        request = dialog.action.request
        active = self._state.state is AssistantState.ACTIVE
        # The dialog's own record of a real press decides, not the code.
        if not dialog.approved or not active:
            self._record_denial(request)
            self._say(POTATO, TEXT_DENIED if active else TEXT_NOT_ACTIVE)
            self._ask_next()
            return
        try:
            approval = self._issuer.approve(request)
        except ApprovalError:
            self._say(POTATO, TEXT_APPROVAL_FAILED)
            self._ask_next()
            return
        self._state.record_activity()
        self._say(POTATO, TEXT_APPROVED)
        self.status.setText(TEXT_WORKING)
        gate = self._gate
        self._start(lambda: self._run_approved(gate, proposal, approval))

    def _run_approved(self, gate: ActionGate, proposal: object, approval: Approval) -> None:
        # Runs on a worker thread: touches no widget. The gate checks the
        # proposal again from the start; the approval fits only if that
        # gives exactly the action the user was shown.
        try:
            result: object = gate.submit(proposal, ORIGIN, approval)
        except Exception:
            result = None
        self._bridge.action_finished.emit(result)

    def _show_action_result(self, result: object) -> None:
        if isinstance(result, GateResult) and result.ok is True:
            self._say(POTATO, TEXT_DONE)
        elif isinstance(result, GateResult) and result.reason is not None:
            self._say(POTATO, MESSAGES.get(result.reason, TEXT_ACTION_FAILED))
        else:
            self._say(POTATO, TEXT_ACTION_FAILED)
        self._state.record_activity()
        self._ask_next()

    # --- Closing ------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt's name
        """Deny anything still waiting, then put Potato to sleep."""
        self.bubble.close()
        for request, _ in self._waiting:
            self._record_denial(request)
        self._waiting.clear()
        if self._asking is not None:
            self._asking[0].reject()
        self._sleep()
        event.accept()
