"""Speech-to-text on this Mac, with Whisper (faster-whisper).

Potato never downloads the model itself. The user runs
``scripts/download_speech_model.py`` once, which fetches a pinned version.
Before the model is first used, this module checks that its folder holds the
expected files and that ``model.bin`` has the expected SHA-256, so a model
that was swapped or damaged is refused. The Hugging Face library is put in
offline mode before faster-whisper is imported, so it cannot reach the
network either.

The text that comes back is the user's own words as far as Potato can tell,
but it is still untrusted: the interface shows it as plain text, and voice
requests reach low-risk tools only (P6).
"""

import hashlib
import os
import threading
from pathlib import Path
from typing import Final

from potato.voice.microphone import BYTES_PER_SAMPLE

MODEL_REPOSITORY: Final = "Systran/faster-whisper-small.en"
MODEL_REVISION: Final = "d1d751a5f8271d482d14ca55d9e2deeebbae577f"
MODEL_FILES: Final = ("config.json", "model.bin", "tokenizer.json", "vocabulary.txt")
MODEL_SHA256: Final = "62b2a45b05ee59acb4a5341b33ee35e041395d378d418a18acfe4c9e768ee37a"
MODEL_FOLDER_NAME: Final = "faster-whisper-small.en"

MAX_TRANSCRIPT_CHARACTERS: Final = 2000
MIN_AUDIO_SECONDS: Final = 0.3
_SAMPLE_RATE: Final = 16_000


class SpeechModelMissingError(Exception):
    """The speech model has not been downloaded."""


class SpeechModelInvalidError(Exception):
    """The speech model folder is incomplete or its checksum does not match."""


def file_sha256(path: Path) -> str:
    """The SHA-256 of a file, read in pieces."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for piece in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(piece)
    return digest.hexdigest()


def check_model_folder(folder: Path, expected_sha256: str = MODEL_SHA256) -> None:
    """Check that ``folder`` holds the pinned model.

    Raises:
        SpeechModelMissingError: There is no model folder.
        SpeechModelInvalidError: A file is missing, is not a plain file, or
            ``model.bin`` does not match its checksum.
    """
    if not folder.is_dir():
        raise SpeechModelMissingError("the speech model has not been downloaded")
    for name in MODEL_FILES:
        path = folder / name
        if path.is_symlink() or not path.is_file():
            raise SpeechModelInvalidError("the speech model folder is incomplete")
    if file_sha256(folder / "model.bin") != expected_sha256:
        raise SpeechModelInvalidError("the speech model does not match its checksum")


class WhisperTranscriber:
    """Turns 16 kHz, 16-bit mono audio into text."""

    def __init__(self, folder: Path, *, expected_sha256: str = MODEL_SHA256) -> None:
        """Remember where the model is. Loads nothing yet."""
        self._folder = folder
        self._expected = expected_sha256
        self._model: object | None = None
        self._lock = threading.Lock()

    def _load(self) -> object:
        with self._lock:
            if self._model is None:
                check_model_folder(self._folder, self._expected)
                # Before the import: the Hugging Face library reads these once.
                os.environ["HF_HUB_OFFLINE"] = "1"
                os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
                from faster_whisper import WhisperModel  # Heavy: load on use.

                self._model = WhisperModel(str(self._folder), device="cpu", compute_type="int8")
            return self._model

    def __call__(self, audio: bytes) -> str:
        """Transcribe ``audio``. Very short or silent audio gives ``""``.

        Raises:
            SpeechModelMissingError: The model has not been downloaded.
            SpeechModelInvalidError: The model failed its check.
        """
        if len(audio) < MIN_AUDIO_SECONDS * _SAMPLE_RATE * BYTES_PER_SAMPLE:
            return ""
        model = self._load()
        import numpy  # Comes with faster-whisper.

        usable = len(audio) - len(audio) % BYTES_PER_SAMPLE
        samples = numpy.frombuffer(audio[:usable], dtype=numpy.int16).astype(numpy.float32)
        samples /= 32768.0
        segments, _ = model.transcribe(  # type: ignore[attr-defined]
            samples,
            language="en",
            beam_size=1,
            vad_filter=False,
            condition_on_previous_text=False,
        )
        text = " ".join(str(segment.text).strip() for segment in segments)
        return " ".join(text.split())[:MAX_TRANSCRIPT_CHARACTERS]
