"""The microphone.

Audio is kept in memory only, never written to disk and never logged
(T-VOICE-4). A recording is capped at ``MAX_RECORD_SECONDS``; anything after
that is dropped. ``sounddevice`` (PortAudio) is imported only when the
microphone is actually opened, so nothing touches audio hardware until the
user holds "Hold to talk".
"""

import contextlib
import math
import threading
from collections.abc import Callable
from typing import Final, Protocol

SAMPLE_RATE: Final = 16_000
BYTES_PER_SAMPLE: Final = 2  # 16-bit signed, one channel.
MAX_RECORD_SECONDS: Final = 30
MAX_RECORD_BYTES: Final = SAMPLE_RATE * BYTES_PER_SAMPLE * MAX_RECORD_SECONDS

LevelListener = Callable[[float], None]


class MicrophoneError(Exception):
    """The microphone could not be opened or closed. Carries no details."""


class Microphone(Protocol):
    """Something that records 16 kHz, 16-bit, mono audio into memory."""

    @property
    def is_open(self) -> bool:
        """Whether it is recording."""
        ...

    def open(self, on_level: LevelListener) -> None:
        """Start recording. ``on_level`` gets the loudness, 0 to 1, from any thread."""
        ...

    def close(self) -> bytes:
        """Stop recording and hand back the audio. Safe to call when closed."""
        ...


def loudness(chunk: bytes) -> float:
    """How loud a piece of 16-bit audio is, from 0 to 1."""
    count = len(chunk) // BYTES_PER_SAMPLE
    if count == 0:
        return 0.0
    samples = memoryview(chunk[: count * BYTES_PER_SAMPLE]).cast("h")
    mean_square = sum(sample * sample for sample in samples) / count
    # Speech is far below full scale; this makes normal talking reach about 1.
    return min(1.0, math.sqrt(mean_square) / 6000.0)


class Buffer:
    """Audio collected while recording, capped at ``MAX_RECORD_BYTES``."""

    def __init__(self, limit: int = MAX_RECORD_BYTES) -> None:
        """Make an empty buffer that keeps at most ``limit`` bytes."""
        self._limit = limit
        self._data = bytearray()
        self._lock = threading.Lock()

    def add(self, chunk: bytes) -> None:
        """Keep ``chunk``, or as much of it as still fits."""
        with self._lock:
            room = self._limit - len(self._data)
            if room > 0:
                self._data += chunk[:room]

    @property
    def full(self) -> bool:
        """Whether nothing more will be kept."""
        with self._lock:
            return len(self._data) >= self._limit

    def take(self) -> bytes:
        """Hand back everything and empty the buffer."""
        with self._lock:
            data = bytes(self._data)
            self._data = bytearray()
            return data


class SoundDeviceMicrophone:
    """The Mac's default microphone, through PortAudio."""

    def __init__(self) -> None:
        """Make a closed microphone. Touches no audio hardware."""
        self._stream: object | None = None
        self._buffer = Buffer()
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        """Whether it is recording."""
        with self._lock:
            return self._stream is not None

    def open(self, on_level: LevelListener) -> None:
        """Start recording from the default input device.

        Raises:
            MicrophoneError: The microphone could not be opened, for example
                because macOS has not been given permission.
        """
        with self._lock:
            if self._stream is not None:
                return
            self._buffer.take()
            buffer = self._buffer

            def received(data: object, frames: int, time: object, status: object) -> None:
                chunk = bytes(data)  # type: ignore[call-overload]
                buffer.add(chunk)
                # A broken display must not stop the recording.
                with contextlib.suppress(Exception):
                    on_level(loudness(chunk))

            try:
                import sounddevice  # Only when the microphone opens.

                stream = sounddevice.RawInputStream(
                    samplerate=SAMPLE_RATE,
                    channels=1,
                    dtype="int16",
                    callback=received,
                )
                stream.start()
            except Exception as error:
                # PortAudio's own message is not passed on.
                raise MicrophoneError("the microphone could not be opened") from error
            self._stream = stream

    def close(self) -> bytes:
        """Stop recording and hand back the audio.

        Raises:
            MicrophoneError: The stream could not be closed.
        """
        with self._lock:
            stream, self._stream = self._stream, None
        if stream is not None:
            try:
                stream.stop()  # type: ignore[attr-defined]
                stream.close()  # type: ignore[attr-defined]
            except Exception as error:
                self._buffer.take()
                # Last try: abort drops the stream without waiting for it.
                with contextlib.suppress(Exception):
                    stream.abort()  # type: ignore[attr-defined]
                raise MicrophoneError("the microphone could not be closed") from error
        return self._buffer.take()
