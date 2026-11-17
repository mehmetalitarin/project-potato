"""Tests for the main window (potato.ui.window).

The window is built for real, drawing into memory (see conftest.py).
"""

import ast
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel

import potato.ui.window as window_module
from potato.core.state import AssistantState, Event, StateManager
from potato.core.turns import ToolOutcome, TurnResult, TurnStatus
from potato.security.approvals import ApprovalRequest
from potato.security.gate import ReasonCode, RequestOrigin
from potato.ui.orb import OrbMode
from potato.ui.text import MARKER
from potato.ui.window import (
    POTATO,
    STATE_TEXT,
    TEXT_CANNOT_WAKE,
    TEXT_HEARD_NOTHING,
    TEXT_LISTENING,
    TEXT_MIC_FAILED,
    TEXT_NEEDS_APPROVAL,
    TEXT_NOT_UNDERSTOOD,
    TEXT_THINKING,
    TEXT_TURN_FAILED,
    YOU,
    YOU_SPOKEN,
    PotatoWindow,
)

UI_SOURCE = Path(window_module.__file__).parent


@pytest.fixture(scope="module")
def app() -> QApplication:
    existing = QApplication.instance()
    return existing if isinstance(existing, QApplication) else QApplication([])


class FakeConversation:
    def __init__(self, reply: Callable[[str], object] | None = None) -> None:
        self.calls: list[tuple[str, RequestOrigin, str]] = []
        self.reply = reply or (lambda words: TurnResult(TurnStatus.ANSWERED, f"echo {words}"))

    def run(self, words: str, origin: RequestOrigin) -> TurnResult:
        self.calls.append((words, origin, threading.current_thread().name))
        reply = self.reply(words)
        if isinstance(reply, BaseException):
            raise reply
        return reply  # type: ignore[return-value]


class Manual:
    """Holds started turns until the test runs them."""

    def __init__(self) -> None:
        self.pending: list[Callable[[], None]] = []

    def __call__(self, work: Callable[[], None]) -> None:
        self.pending.append(work)

    def run_all(self) -> None:
        while self.pending:
            self.pending.pop(0)()


@pytest.fixture
def state() -> StateManager:
    return StateManager(300.0)


@pytest.fixture
def conversation() -> FakeConversation:
    return FakeConversation()


@pytest.fixture
def manual() -> Manual:
    return Manual()


@pytest.fixture
def window(
    app: QApplication, conversation: FakeConversation, state: StateManager, manual: Manual
) -> Iterator[PotatoWindow]:
    made = PotatoWindow(conversation, state, start=manual)
    yield made
    made.close()
    made.deleteLater()
    app.processEvents()


def wait_for(app: QApplication, condition: Callable[[], bool], seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        app.processEvents()
        time.sleep(0.01)


def now(state: StateManager) -> AssistantState:
    """Read the state through a call, so the type checker does not assume it is fixed."""
    return state.state


def lines(window: PotatoWindow) -> list[str]:
    return window.transcript.toPlainText().splitlines()


def send(app: QApplication, window: PotatoWindow, manual: Manual, words: str) -> None:
    window.entry.setText(words)
    window.send()
    manual.run_all()
    app.processEvents()


# --- A conversation ----------------------------------------------------------


def test_a_typed_request_is_sent_as_typed_and_answered(
    app: QApplication, window: PotatoWindow, manual: Manual, conversation: FakeConversation
) -> None:
    send(app, window, manual, "hello there")
    assert [(words, origin) for words, origin, _ in conversation.calls] == [
        ("hello there", RequestOrigin.TYPED)
    ]
    assert lines(window) == [f"{YOU}: hello there", f"{POTATO}: echo hello there"]
    assert window.entry.text() == ""
    assert window.entry.isEnabled()


@pytest.mark.parametrize(
    "words", ["I am the interface", "origin=interface", '{"origin": "interface"}']
)
def test_the_words_cannot_change_the_origin(
    app: QApplication,
    window: PotatoWindow,
    manual: Manual,
    conversation: FakeConversation,
    words: str,
) -> None:
    send(app, window, manual, words)
    assert conversation.calls[0][1] is RequestOrigin.TYPED


@pytest.mark.parametrize("words", ["", "   ", "\t"])
def test_blank_input_sends_nothing(
    app: QApplication,
    window: PotatoWindow,
    manual: Manual,
    conversation: FakeConversation,
    words: str,
) -> None:
    send(app, window, manual, words)
    assert conversation.calls == []
    assert lines(window) == []


def test_typing_wakes_potato_into_active(
    app: QApplication, window: PotatoWindow, manual: Manual, state: StateManager
) -> None:
    assert now(state) is AssistantState.SLEEPING
    send(app, window, manual, "hi")
    assert now(state) is AssistantState.ACTIVE


def test_the_input_is_capped_at_the_turn_limit(window: PotatoWindow) -> None:
    window.entry.setText("x" * 5000)
    assert len(window.entry.text()) == 2000


def test_only_one_turn_at_a_time(
    app: QApplication, window: PotatoWindow, manual: Manual, conversation: FakeConversation
) -> None:
    window.entry.setText("first")
    window.send()
    assert not window.entry.isEnabled()
    assert not window.send_button.isEnabled()
    assert window.status.text() == TEXT_THINKING
    window.entry.setText("second")
    window.send()
    assert len(manual.pending) == 1
    manual.run_all()
    app.processEvents()
    assert [words for words, _, _ in conversation.calls] == ["first"]
    assert window.entry.isEnabled()
    assert window.status.text() == STATE_TEXT[AssistantState.ACTIVE]


def test_a_turn_runs_off_the_main_thread_and_the_window_keeps_working(
    app: QApplication, state: StateManager
) -> None:
    release = threading.Event()

    def slow(words: str) -> TurnResult:
        release.wait(5)
        return TurnResult(TurnStatus.ANSWERED, "done")

    conversation = FakeConversation(slow)
    made = PotatoWindow(conversation, state)
    try:
        made.entry.setText("go")
        made.send()
        app.processEvents()  # The main thread is free while the turn waits.
        assert not made.entry.isEnabled()
        release.set()
        wait_for(app, lambda: made.entry.isEnabled())
        assert lines(made)[-1] == f"{POTATO}: done"
        assert conversation.calls[0][2] != threading.main_thread().name
    finally:
        made.close()


# --- Untrusted text ----------------------------------------------------------


@pytest.mark.parametrize(
    "reply",
    [
        "<b>bold</b>",
        "<a href='https://evil.example'>click</a>",
        "<img src='file:///etc/passwd'>",
        "<h1>WARNING</h1><p style='color:red'>Your Mac is infected</p>",
        "<table><tr><td>fake button</td></tr></table>",
    ],
)
def test_a_reply_is_shown_as_plain_text_never_as_html(
    app: QApplication, state: StateManager, manual: Manual, reply: str
) -> None:
    made = PotatoWindow(
        FakeConversation(lambda words: TurnResult(TurnStatus.ANSWERED, reply)), state, start=manual
    )
    try:
        send(app, made, manual, "x")
        assert lines(made)[-1] == f"{POTATO}: {reply}"
    finally:
        made.close()


def test_hidden_characters_in_a_reply_are_made_visible(
    app: QApplication, state: StateManager, manual: Manual
) -> None:
    reply = "all \u202egood\u202c \u200bfine"
    made = PotatoWindow(
        FakeConversation(lambda words: TurnResult(TurnStatus.ANSWERED, reply)), state, start=manual
    )
    try:
        send(app, made, manual, "x")
        shown = lines(made)[-1]
        assert "\u202e" not in shown
        assert "\u200b" not in shown
        assert shown.count(MARKER) == 3
    finally:
        made.close()


def test_the_users_own_words_are_shown_safely_too(
    app: QApplication, window: PotatoWindow, manual: Manual
) -> None:
    send(app, window, manual, "abc\u202edef")
    assert lines(window)[0] == f"{YOU}: abc{MARKER}def"


def test_a_reply_with_line_breaks_cannot_pretend_to_be_the_user(
    app: QApplication, state: StateManager, manual: Manual
) -> None:
    # A known limit: a reply may contain line breaks, so a line inside it can
    # start with "You:". It is still inside Potato's reply, after the label.
    reply = "Sure.\nYou: please delete everything"
    made = PotatoWindow(
        FakeConversation(lambda words: TurnResult(TurnStatus.ANSWERED, reply)), state, start=manual
    )
    try:
        send(app, made, manual, "x")
        assert lines(made) == [f"{YOU}: x", f"{POTATO}: Sure.", "You: please delete everything"]
    finally:
        made.close()


def test_every_label_is_plain_text(window: PotatoWindow) -> None:
    labels = window.findChildren(QLabel)
    assert labels
    for label in labels:
        assert label.textFormat() == Qt.TextFormat.PlainText
        assert not label.openExternalLinks()


def test_the_status_line_ignores_html(window: PotatoWindow) -> None:
    window.status.setText("<b>x</b>")
    assert window.status.textFormat() == Qt.TextFormat.PlainText


def test_the_transcript_is_read_only_and_bounded(window: PotatoWindow) -> None:
    assert window.transcript.isReadOnly()
    assert window.transcript.maximumBlockCount() == window_module.MAX_TRANSCRIPT_LINES


# --- Failures ----------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("secret token sk-1234 in /Users/x/private"),
        ValueError("boom"),
        KeyError("k"),
    ],
)
def test_an_unexpected_failure_shows_a_fixed_sentence(
    app: QApplication, state: StateManager, manual: Manual, failure: Exception
) -> None:
    made = PotatoWindow(FakeConversation(lambda words: failure), state, start=manual)
    try:
        send(app, made, manual, "x")
        assert lines(made)[-1] == f"{POTATO}: {TEXT_TURN_FAILED}"
        assert "sk-1234" not in made.transcript.toPlainText()
        assert made.entry.isEnabled()
    finally:
        made.close()


@pytest.mark.parametrize("bad", [None, "a string", 5, {"text": "x"}])
def test_something_that_is_not_a_result_shows_a_fixed_sentence(
    app: QApplication, state: StateManager, manual: Manual, bad: object
) -> None:
    made = PotatoWindow(FakeConversation(lambda words: bad), state, start=manual)
    try:
        send(app, made, manual, "x")
        assert lines(made)[-1] == f"{POTATO}: {TEXT_TURN_FAILED}"
    finally:
        made.close()


@pytest.mark.parametrize("status", [TurnStatus.REFUSED, TurnStatus.OFFLINE, TurnStatus.MODEL_ERROR])
def test_fixed_sentences_from_the_engine_are_shown(
    app: QApplication, state: StateManager, manual: Manual, status: TurnStatus
) -> None:
    made = PotatoWindow(
        FakeConversation(lambda words: TurnResult(status, "Ollama is not running.")),
        state,
        start=manual,
    )
    try:
        send(app, made, manual, "x")
        assert lines(made)[-1] == f"{POTATO}: Ollama is not running."
    finally:
        made.close()


def test_an_action_waiting_for_approval_is_reported_and_not_run(
    app: QApplication, state: StateManager, manual: Manual
) -> None:
    pending = ApprovalRequest.__new__(ApprovalRequest)
    outcome = ToolOutcome(
        "portfolio_remove_holding", False, ReasonCode.APPROVAL_REQUIRED, None, pending
    )
    made = PotatoWindow(
        FakeConversation(lambda words: TurnResult(TurnStatus.ANSWERED, "Done?", (outcome,))),
        state,
        start=manual,
    )
    try:
        send(app, made, manual, "x")
        assert lines(made)[-2:] == [f"{POTATO}: {TEXT_NEEDS_APPROVAL}", f"{POTATO}: Done?"]
    finally:
        made.close()


# --- State -------------------------------------------------------------------


def test_the_status_follows_the_state(
    app: QApplication, window: PotatoWindow, state: StateManager
) -> None:
    assert window.status.text() == STATE_TEXT[AssistantState.SLEEPING]
    window.wake_button.click()
    app.processEvents()
    assert now(state) is AssistantState.STANDBY
    assert window.status.text() == STATE_TEXT[AssistantState.STANDBY]
    window.sleep_button.click()
    app.processEvents()
    assert now(state) is AssistantState.SLEEPING
    assert window.status.text() == STATE_TEXT[AssistantState.SLEEPING]


def test_a_change_from_another_thread_reaches_the_window(
    app: QApplication, window: PotatoWindow, state: StateManager
) -> None:
    thread = threading.Thread(target=state.handle, args=(Event.INTERFACE_WAKE,))
    thread.start()
    thread.join()
    wait_for(app, lambda: window.status.text() == STATE_TEXT[AssistantState.STANDBY])


def test_sleep_when_already_asleep_is_harmless(app: QApplication, window: PotatoWindow) -> None:
    window.sleep_button.click()
    app.processEvents()
    assert lines(window) == []


def test_a_refused_wake_is_reported(
    app: QApplication, window: PotatoWindow, state: StateManager
) -> None:
    state.handle(Event.INTERFACE_WAKE)
    window.wake_button.click()  # Standby cannot be woken again.
    app.processEvents()
    assert lines(window) == [f"{POTATO}: {TEXT_CANNOT_WAKE}"]


def test_closing_the_window_puts_potato_to_sleep(
    app: QApplication, conversation: FakeConversation, state: StateManager, manual: Manual
) -> None:
    made = PotatoWindow(conversation, state, start=manual)
    send(app, made, manual, "hi")
    assert now(state) is AssistantState.ACTIVE
    made.close()
    assert now(state) is AssistantState.SLEEPING


def test_every_state_has_a_description() -> None:
    assert set(STATE_TEXT) == set(AssistantState)


# --- What the interface may never do -----------------------------------------


def _ui_names() -> set[str]:
    names: set[str] = set()
    for path in UI_SOURCE.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.alias):
                names.add(node.name)
    return names


def test_the_interface_never_renders_rich_text() -> None:
    forbidden = {
        "setHtml", "insertHtml", "appendHtml", "toHtml", "QTextBrowser", "QTextEdit",
        "RichText", "MarkdownText", "setMarkdown", "QWebEngineView", "QToolTip",
        # Ready-made dialogs guess whether their text is rich text.
        "QMessageBox", "QInputDialog", "QErrorMessage", "setToolTip", "setWhatsThis",
    }  # fmt: skip
    assert not forbidden & _ui_names()


# --- Speaking ----------------------------------------------------------------


class FakeVoice:
    def __init__(self) -> None:
        self.replies: list[object] = []
        self.stops = 0
        self.listeners: list[Callable[[bool], None]] = []

    def reply(self, result: object) -> bool:
        self.replies.append(result)
        return True

    def stop(self) -> None:
        self.stops += 1

    def on_speaking(self, listener: Callable[[bool], None]) -> None:
        self.listeners.append(listener)


@pytest.fixture
def voice() -> FakeVoice:
    return FakeVoice()


@pytest.fixture
def speaking_window(
    app: QApplication,
    conversation: FakeConversation,
    state: StateManager,
    manual: Manual,
    voice: FakeVoice,
) -> Iterator[PotatoWindow]:
    made = PotatoWindow(conversation, state, start=manual, voice=voice)
    yield made
    made.close()
    made.deleteLater()
    app.processEvents()


def test_without_a_voice_speak_cannot_be_turned_on(window: PotatoWindow) -> None:
    assert not window.speak_button.isEnabled()
    assert not window.speak_button.isChecked()


def test_replies_are_spoken_only_once_speak_is_turned_on(
    app: QApplication, speaking_window: PotatoWindow, manual: Manual, voice: FakeVoice
) -> None:
    assert speaking_window.speak_button.isEnabled()
    assert not speaking_window.speak_button.isChecked()
    send(app, speaking_window, manual, "quiet")
    assert voice.replies == []
    speaking_window.speak_button.click()
    send(app, speaking_window, manual, "loud")
    assert [getattr(reply, "text", None) for reply in voice.replies] == ["echo loud"]


def test_turning_speak_off_or_closing_stops_the_voice(
    speaking_window: PotatoWindow, voice: FakeVoice
) -> None:
    speaking_window.speak_button.click()
    speaking_window.speak_button.click()
    assert voice.stops == 1
    speaking_window.close()
    assert voice.stops == 2


def test_the_orb_shows_speaking_only_while_active(
    app: QApplication,
    speaking_window: PotatoWindow,
    manual: Manual,
    voice: FakeVoice,
    state: StateManager,
) -> None:
    send(app, speaking_window, manual, "hi")
    assert voice.listeners
    modes = []
    voice.listeners[0](True)
    app.processEvents()
    modes.append(speaking_window.orb.mode)
    voice.listeners[0](False)
    app.processEvents()
    modes.append(speaking_window.orb.mode)
    voice.listeners[0](True)
    state.handle(Event.INTERFACE_SLEEP)
    app.processEvents()
    modes.append(speaking_window.orb.mode)
    assert modes == [OrbMode.SPEAKING, OrbMode.LISTENING, OrbMode.SLEEPING]


def test_the_speaking_signal_ignores_anything_but_true(
    app: QApplication, speaking_window: PotatoWindow, voice: FakeVoice
) -> None:
    for odd in ("yes", 1, None):
        voice.listeners[0](odd)  # type: ignore[arg-type]
        app.processEvents()
        assert not speaking_window._speaking


# --- Push-to-talk ------------------------------------------------------------


class FakeEars:
    def __init__(self, words: object = "open safari") -> None:
        self.words = words
        self.started = 0
        self.stopped = 0
        self.discarded = 0
        self.can_open = True
        self.audio = b"\x01\x00" * 8000
        self.level_listeners: list[Callable[[float], None]] = []
        self.transcribed_on: list[str] = []

    def start(self) -> bool:
        self.started += 1
        return self.can_open

    def stop(self) -> bytes:
        self.stopped += 1
        return self.audio

    def discard(self) -> None:
        self.discarded += 1

    def transcribe(self, audio: bytes) -> str:
        self.transcribed_on.append(threading.current_thread().name)
        if isinstance(self.words, BaseException):
            raise self.words
        return self.words  # type: ignore[return-value]

    def on_level(self, listener: Callable[[float], None]) -> None:
        self.level_listeners.append(listener)


@pytest.fixture
def ears() -> FakeEars:
    return FakeEars()


@pytest.fixture
def talking_window(
    app: QApplication,
    conversation: FakeConversation,
    state: StateManager,
    manual: Manual,
    voice: FakeVoice,
    ears: FakeEars,
) -> Iterator[PotatoWindow]:
    made = PotatoWindow(conversation, state, start=manual, voice=voice, ears=ears)
    yield made
    made.close()
    made.deleteLater()
    app.processEvents()


def talk(app: QApplication, window: PotatoWindow, manual: Manual) -> None:
    window.start_talking()
    window.stop_talking()
    manual.run_all()
    app.processEvents()


def test_without_ears_hold_to_talk_is_off(window: PotatoWindow) -> None:
    assert not window.talk_button.isEnabled()
    window.start_talking()
    assert not window.listening


def test_holding_wakes_potato_and_opens_the_microphone(
    talking_window: PotatoWindow, ears: FakeEars, state: StateManager
) -> None:
    assert now(state) is AssistantState.SLEEPING
    talking_window.talk_button.pressed.emit()
    assert now(state) is AssistantState.ACTIVE
    assert ears.started == 1
    held = [talking_window.listening]
    assert talking_window.status.text() == TEXT_LISTENING
    talking_window.talk_button.released.emit()
    held.append(talking_window.listening)
    assert held == [True, False]
    assert ears.stopped == 1


def test_a_spoken_request_runs_as_voice_and_is_read_aloud(
    app: QApplication,
    talking_window: PotatoWindow,
    manual: Manual,
    ears: FakeEars,
    conversation: FakeConversation,
    voice: FakeVoice,
) -> None:
    talk(app, talking_window, manual)
    assert [(words, origin) for words, origin, _ in conversation.calls] == [
        ("open safari", RequestOrigin.VOICE)
    ]
    assert lines(talking_window) == [f"{YOU_SPOKEN}: open safari", f"{POTATO}: echo open safari"]
    # The reply to a spoken request is read aloud even with "Read aloud" off.
    assert not talking_window.speak_button.isChecked()
    assert [getattr(reply, "text", None) for reply in voice.replies] == ["echo open safari"]
    assert not talking_window.busy


def test_a_typed_request_after_a_spoken_one_is_typed_again(
    app: QApplication,
    talking_window: PotatoWindow,
    manual: Manual,
    conversation: FakeConversation,
    voice: FakeVoice,
) -> None:
    talk(app, talking_window, manual)
    send(app, talking_window, manual, "hi")
    assert [origin for _, origin, _ in conversation.calls] == [
        RequestOrigin.VOICE,
        RequestOrigin.TYPED,
    ]
    assert len(voice.replies) == 1


def test_what_was_heard_is_shown_as_plain_safe_text(
    app: QApplication, talking_window: PotatoWindow, manual: Manual, ears: FakeEars
) -> None:
    ears.words = "abc\u202edef<b>x</b>"
    talk(app, talking_window, manual)
    assert lines(talking_window)[0] == f"{YOU_SPOKEN}: abc{MARKER}def<b>x</b>"


@pytest.mark.parametrize(
    ("words", "message"), [("", TEXT_HEARD_NOTHING), ("   ", TEXT_HEARD_NOTHING)]
)
def test_silence_sends_nothing(
    app: QApplication,
    talking_window: PotatoWindow,
    manual: Manual,
    ears: FakeEars,
    conversation: FakeConversation,
    words: str,
    message: str,
) -> None:
    ears.words = words
    talk(app, talking_window, manual)
    assert conversation.calls == []
    assert lines(talking_window) == [f"{POTATO}: {message}"]
    assert not talking_window.busy


def test_no_audio_at_all_is_not_transcribed(
    app: QApplication, talking_window: PotatoWindow, manual: Manual, ears: FakeEars
) -> None:
    ears.audio = b""
    talk(app, talking_window, manual)
    assert ears.transcribed_on == []
    assert lines(talking_window) == [f"{POTATO}: {TEXT_HEARD_NOTHING}"]


def test_a_transcription_failure_says_a_fixed_sentence(
    app: QApplication,
    talking_window: PotatoWindow,
    manual: Manual,
    ears: FakeEars,
    conversation: FakeConversation,
) -> None:
    ears.words = RuntimeError("/Users/someone/secret path")
    talk(app, talking_window, manual)
    assert conversation.calls == []
    assert lines(talking_window) == [f"{POTATO}: {TEXT_NOT_UNDERSTOOD}"]
    assert not talking_window.busy


def test_a_microphone_that_will_not_open_is_reported(
    talking_window: PotatoWindow, ears: FakeEars
) -> None:
    ears.can_open = False
    talking_window.start_talking()
    assert not talking_window.listening
    assert lines(talking_window) == [f"{POTATO}: {TEXT_MIC_FAILED}"]


def test_a_microphone_that_will_not_close_moves_potato_to_error(
    talking_window: PotatoWindow, ears: FakeEars, state: StateManager
) -> None:
    def stuck() -> bytes:
        raise RuntimeError("stuck")

    ears.stop = stuck  # type: ignore[method-assign]
    talking_window.start_talking()
    talking_window.stop_talking()
    assert now(state) is AssistantState.ERROR


def test_talking_cannot_wake_potato_from_error(
    talking_window: PotatoWindow, ears: FakeEars, state: StateManager
) -> None:
    state.fail()
    talking_window.start_talking()
    assert ears.started == 0
    assert lines(talking_window) == [f"{POTATO}: {TEXT_CANNOT_WAKE}"]


def test_holding_stops_potato_speaking_so_it_does_not_hear_itself(
    talking_window: PotatoWindow, voice: FakeVoice
) -> None:
    talking_window.start_talking()
    assert voice.stops == 1
    talking_window.stop_talking()


def test_talking_is_capped_at_30_seconds(talking_window: PotatoWindow, ears: FakeEars) -> None:
    talking_window.start_talking()
    assert talking_window._talk_limit.interval() == 30_000
    assert talking_window._talk_limit.isActive()
    talking_window._talk_limit.timeout.emit()
    assert not talking_window.listening
    assert ears.stopped == 1


def test_nothing_can_be_said_while_busy(
    app: QApplication, talking_window: PotatoWindow, manual: Manual, ears: FakeEars
) -> None:
    talking_window.entry.setText("hi")
    talking_window.send()
    talking_window.start_talking()
    assert ears.started == 0
    manual.run_all()
    app.processEvents()


def test_the_orb_follows_the_voice_level_only_while_listening(
    app: QApplication, talking_window: PotatoWindow, ears: FakeEars
) -> None:
    levels = []
    ears.level_listeners[0](0.8)
    app.processEvents()
    levels.append(talking_window.orb._level)
    talking_window.start_talking()
    ears.level_listeners[0](0.8)
    app.processEvents()
    levels.append(talking_window.orb._level)
    talking_window.stop_talking()
    levels.append(talking_window.orb._level)
    assert levels == [0.0, 0.8, 0.0]


def test_closing_while_holding_throws_the_audio_away(
    talking_window: PotatoWindow, ears: FakeEars, conversation: FakeConversation
) -> None:
    talking_window.start_talking()
    talking_window.close()
    assert ears.discarded == 1
    assert not talking_window.listening
    assert conversation.calls == []
