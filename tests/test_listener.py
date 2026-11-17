"""Tests for push-to-talk (potato.voice.listener; T-VOICE-4, required test 13).

The microphone follows Potato's state: it opens only while active and
closes, throwing the audio away, the moment Potato leaves the active state.
"""

from collections.abc import Callable

import pytest

from potato.core.state import AssistantState, Event, StateManager
from potato.voice.listener import Ears
from potato.voice.microphone import MicrophoneError

AUDIO = b"\x01\x00" * 8000


class FakeMicrophone:
    def __init__(self, *, fail_open: bool = False, fail_close: bool = False) -> None:
        self.is_open = False
        self.fail_open = fail_open
        self.fail_close = fail_close
        self.opened = 0
        self.closed = 0
        self.on_level: Callable[[float], None] | None = None
        self.while_opening: Callable[[], None] | None = None

    def open(self, on_level: Callable[[float], None]) -> None:
        if self.fail_open:
            raise MicrophoneError("no")
        if self.while_opening is not None:
            self.while_opening()
        self.opened += 1
        self.is_open = True
        self.on_level = on_level

    def close(self) -> bytes:
        self.closed += 1
        was_open, self.is_open = self.is_open, False
        if self.fail_close and was_open:
            raise MicrophoneError("stuck")
        return AUDIO if was_open else b""


class Transcriber:
    def __init__(self, text: str = "open safari") -> None:
        self.text = text
        self.heard: list[bytes] = []

    def __call__(self, audio: bytes) -> str:
        self.heard.append(audio)
        return self.text


def state_in(target: AssistantState) -> StateManager:
    state = StateManager(300.0)
    if target is AssistantState.STANDBY:
        state.handle(Event.INTERFACE_WAKE)
    elif target is AssistantState.ACTIVE:
        state.handle(Event.INTERFACE_TALK)
    elif target is AssistantState.ERROR:
        state.fail()
    assert state.state is target
    return state


def now(state: StateManager) -> AssistantState:
    return state.state


# --- Opening -----------------------------------------------------------------


def test_it_records_while_active() -> None:
    microphone = FakeMicrophone()
    transcriber = Transcriber()
    ears = Ears(state_in(AssistantState.ACTIVE), microphone, transcriber)
    listening = [ears.listening]
    assert ears.start()
    listening.append(ears.listening)
    audio = ears.stop()
    assert audio == AUDIO
    listening.append(ears.listening)
    assert listening == [False, True, False]
    assert ears.transcribe(audio) == "open safari"
    assert transcriber.heard == [AUDIO]


@pytest.mark.parametrize(
    "target", [AssistantState.SLEEPING, AssistantState.STANDBY, AssistantState.ERROR]
)
def test_the_microphone_never_opens_unless_active(target: AssistantState) -> None:
    microphone = FakeMicrophone()
    ears = Ears(state_in(target), microphone, Transcriber())
    assert not ears.start()
    assert microphone.opened == 0
    assert not microphone.is_open


def test_a_microphone_that_cannot_open_is_reported() -> None:
    ears = Ears(state_in(AssistantState.ACTIVE), FakeMicrophone(fail_open=True), Transcriber())
    assert not ears.start()
    assert not ears.listening


def test_leaving_active_while_the_microphone_opens_closes_it() -> None:
    state = state_in(AssistantState.ACTIVE)
    microphone = FakeMicrophone()

    def fall_asleep() -> None:
        state.handle(Event.INTERFACE_SLEEP)

    microphone.while_opening = fall_asleep
    ears = Ears(state, microphone, Transcriber())
    assert not ears.start()
    assert not microphone.is_open


# --- Closing with the state (required test 13) -------------------------------


@pytest.mark.parametrize(
    "leave",
    [
        lambda state: state.handle(Event.INTERFACE_SLEEP),
        lambda state: state.handle(Event.VOICE_SLEEP),
        lambda state: state.handle(Event.IDLE_TIMEOUT),
        lambda state: state.fail(),
    ],
    ids=["sleep", "voice-sleep", "idle", "error"],
)
def test_leaving_active_closes_the_microphone_and_drops_the_audio(
    leave: Callable[[StateManager], None],
) -> None:
    state = state_in(AssistantState.ACTIVE)
    microphone = FakeMicrophone()
    transcriber = Transcriber()
    ears = Ears(state, microphone, transcriber)
    ears.start()
    leave(state)
    assert not microphone.is_open
    assert not ears.listening
    # Releasing the button afterwards hands back nothing.
    assert ears.stop() == b""
    assert ears.transcribe(ears.stop()) == ""
    assert transcriber.heard == []


def test_a_microphone_that_cannot_close_moves_potato_to_error() -> None:
    state = state_in(AssistantState.ACTIVE)
    ears = Ears(state, FakeMicrophone(fail_close=True), Transcriber())
    ears.start()
    state.handle(Event.INTERFACE_SLEEP)
    assert now(state) is AssistantState.ERROR


def test_a_closed_microphone_is_left_alone_on_a_change() -> None:
    state = state_in(AssistantState.ACTIVE)
    microphone = FakeMicrophone(fail_close=True)
    Ears(state, microphone, Transcriber())
    state.handle(Event.INTERFACE_SLEEP)
    assert now(state) is AssistantState.SLEEPING


# --- Loudness ----------------------------------------------------------------


def test_the_loudness_reaches_every_listener_even_after_a_broken_one() -> None:
    microphone = FakeMicrophone()
    ears = Ears(state_in(AssistantState.ACTIVE), microphone, Transcriber())

    def broken(level: float) -> None:
        raise RuntimeError("no")

    heard: list[float] = []
    ears.on_level(broken)
    ears.on_level(heard.append)
    ears.start()
    assert microphone.on_level is not None
    microphone.on_level(0.4)
    assert heard == [0.4]
    ears.stop()


def test_nothing_recorded_is_not_transcribed() -> None:
    transcriber = Transcriber()
    ears = Ears(state_in(AssistantState.ACTIVE), FakeMicrophone(), transcriber)
    assert ears.transcribe(b"") == ""
    assert transcriber.heard == []


def test_audio_is_never_used_after_potato_left_active_even_from_a_faulty_microphone() -> None:
    # A microphone that still hands back audio after being closed: the
    # second lock, in case the first one ever fails.
    class Leaky(FakeMicrophone):
        def close(self) -> bytes:
            super().close()
            return AUDIO

    state = state_in(AssistantState.ACTIVE)
    ears = Ears(state, Leaky(), Transcriber())
    ears.start()
    state.handle(Event.INTERFACE_SLEEP)
    assert ears.stop() == b""
