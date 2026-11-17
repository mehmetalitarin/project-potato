"""Tests for the microphone (potato.voice.microphone)."""

import struct
import sys
from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any

import pytest

from potato.voice.microphone import (
    MAX_RECORD_BYTES,
    MAX_RECORD_SECONDS,
    SAMPLE_RATE,
    Buffer,
    MicrophoneError,
    SoundDeviceMicrophone,
    loudness,
)

DETAIL = "PortAudio says: /Users/someone/private"


def pcm(*samples: int) -> bytes:
    return struct.pack(f"<{len(samples)}h", *samples)


class FakeStream:
    def __init__(self, fail_start: bool = False, fail_stop: bool = False, **options: Any):
        self.options = options
        self.fail_start = fail_start
        self.fail_stop = fail_stop
        self.started = False
        self.closed = False
        self.aborted = False

    def start(self) -> None:
        if self.fail_start:
            raise RuntimeError(DETAIL)
        self.started = True

    def stop(self) -> None:
        if self.fail_stop:
            raise RuntimeError(DETAIL)

    def close(self) -> None:
        self.closed = True

    def abort(self) -> None:
        self.aborted = True

    def feed(self, chunk: bytes) -> None:
        callback: Callable[..., None] = self.options["callback"]
        callback(chunk, len(chunk) // 2, None, None)


class FakeSoundDevice(ModuleType):
    def __init__(self) -> None:
        super().__init__("sounddevice")
        self.streams: list[FakeStream] = []
        self.fail_start = False
        self.fail_stop = False

    def RawInputStream(self, **options: Any) -> FakeStream:  # noqa: N802 - the library's name
        stream = FakeStream(self.fail_start, self.fail_stop, **options)
        self.streams.append(stream)
        return stream


@pytest.fixture
def device(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSoundDevice]:
    fake = FakeSoundDevice()
    monkeypatch.setitem(sys.modules, "sounddevice", fake)
    yield fake


# --- Small pieces ------------------------------------------------------------


def test_the_format_is_16khz_mono_16_bit_capped_at_30_seconds() -> None:
    assert SAMPLE_RATE == 16_000
    assert MAX_RECORD_SECONDS == 30
    assert MAX_RECORD_BYTES == 16_000 * 2 * 30


@pytest.mark.parametrize(
    ("chunk", "low", "high"),
    [
        (b"", 0.0, 0.0),
        (b"\x01", 0.0, 0.0),
        (pcm(0, 0, 0, 0), 0.0, 0.0),
        (pcm(600, -600, 600, -600), 0.05, 0.15),
        (pcm(32767, -32768), 1.0, 1.0),
    ],
)
def test_loudness_is_between_zero_and_one(chunk: bytes, low: float, high: float) -> None:
    assert low <= loudness(chunk) <= high


def test_the_buffer_keeps_at_most_its_limit() -> None:
    buffer = Buffer(limit=5)
    buffer.add(b"abc")
    full = [buffer.full]
    buffer.add(b"defg")
    full.append(buffer.full)
    assert full == [False, True]
    buffer.add(b"more")
    assert buffer.take() == b"abcde"
    assert buffer.take() == b""
    assert not buffer.full


# --- The real microphone, with a fake PortAudio ------------------------------


def test_making_one_touches_no_audio_hardware(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, "sounddevice", raising=False)
    microphone = SoundDeviceMicrophone()
    assert not microphone.is_open
    assert "sounddevice" not in sys.modules
    assert microphone.close() == b""


def test_it_records_16khz_mono_and_reports_the_level(device: FakeSoundDevice) -> None:
    microphone = SoundDeviceMicrophone()
    levels: list[float] = []
    microphone.open(levels.append)
    (stream,) = device.streams
    assert stream.started
    assert {k: v for k, v in stream.options.items() if k != "callback"} == {
        "samplerate": 16_000,
        "channels": 1,
        "dtype": "int16",
    }
    opened = [microphone.is_open]
    stream.feed(pcm(600, -600))
    stream.feed(pcm(0, 0))
    assert microphone.close() == pcm(600, -600, 0, 0)
    assert stream.closed
    opened.append(microphone.is_open)
    assert opened == [True, False]
    assert len(levels) == 2
    assert levels[0] > levels[1] == 0.0


def test_opening_twice_keeps_one_stream(device: FakeSoundDevice) -> None:
    microphone = SoundDeviceMicrophone()
    microphone.open(lambda level: None)
    microphone.open(lambda level: None)
    assert len(device.streams) == 1
    microphone.close()


def test_a_new_recording_starts_empty(device: FakeSoundDevice) -> None:
    microphone = SoundDeviceMicrophone()
    microphone.open(lambda level: None)
    device.streams[0].feed(pcm(1, 2))
    microphone.close()
    microphone.open(lambda level: None)
    assert microphone.close() == b""


def test_a_broken_level_display_does_not_stop_recording(device: FakeSoundDevice) -> None:
    def broken(level: float) -> None:
        raise RuntimeError("no")

    microphone = SoundDeviceMicrophone()
    microphone.open(broken)
    device.streams[0].feed(pcm(5, 5))
    assert microphone.close() == pcm(5, 5)


def test_a_microphone_that_cannot_open_says_so_without_details(device: FakeSoundDevice) -> None:
    device.fail_start = True
    microphone = SoundDeviceMicrophone()
    with pytest.raises(MicrophoneError) as raised:
        microphone.open(lambda level: None)
    assert DETAIL not in str(raised.value)
    assert not microphone.is_open


def test_a_microphone_that_cannot_close_is_aborted_and_reported(device: FakeSoundDevice) -> None:
    device.fail_stop = True
    microphone = SoundDeviceMicrophone()
    microphone.open(lambda level: None)
    device.streams[0].feed(pcm(9, 9))
    with pytest.raises(MicrophoneError) as raised:
        microphone.close()
    assert DETAIL not in str(raised.value)
    assert device.streams[0].aborted
    # The audio is thrown away, not kept for later.
    assert microphone.close() == b""


@pytest.mark.parametrize("name", ["microphone", "listener"])
def test_no_audio_is_written_or_logged(name: str) -> None:
    import ast
    from pathlib import Path

    import potato.voice

    source = Path(potato.voice.__file__).with_name(f"{name}.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "open"
        elif isinstance(node, ast.Attribute):
            assert node.attr not in {"write", "write_bytes", "write_text", "tofile", "save"}
    assert not imported & {"logging", "tempfile", "pathlib", "wave", "pickle", "shelve"}
