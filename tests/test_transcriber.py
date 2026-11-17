"""Tests for speech-to-text (potato.voice.transcriber)."""

import hashlib
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from potato.voice.transcriber import (
    MAX_TRANSCRIPT_CHARACTERS,
    MODEL_FILE_SHA256,
    MODEL_FILES,
    MODEL_REPOSITORY,
    MODEL_REVISION,
    MODEL_SHA256,
    SpeechModelInvalidError,
    SpeechModelMissingError,
    WhisperTranscriber,
    check_model_folder,
    file_sha256,
)

MODEL_BYTES = b"pretend weights"
MODEL_HASH = hashlib.sha256(MODEL_BYTES).hexdigest()
OTHER_HASH = hashlib.sha256(b"{}").hexdigest()
FAKE_FILES = dict.fromkeys(MODEL_FILES, OTHER_HASH)
ONE_SECOND = b"\x10\x00" * 16_000


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    model = tmp_path / "model"
    model.mkdir()
    for name in MODEL_FILES:
        (model / name).write_bytes(MODEL_BYTES if name == "model.bin" else b"{}")
    return model


class FakeWhisper(ModuleType):
    def __init__(self, texts: list[str]) -> None:
        super().__init__("faster_whisper")
        self.texts = texts
        self.loaded: list[tuple[str, dict[str, Any]]] = []
        self.calls: list[tuple[Any, dict[str, Any]]] = []
        self.offline_when_loaded: str | None = None
        fake = self

        class WhisperModel:
            def __init__(self, path: str, **options: Any) -> None:
                fake.loaded.append((path, options))
                fake.offline_when_loaded = os.environ.get("HF_HUB_OFFLINE")

            def transcribe(self, samples: Any, **options: Any) -> tuple[Any, None]:
                fake.calls.append((samples, options))
                return (SimpleNamespace(text=text) for text in fake.texts), None

        self.WhisperModel = WhisperModel


@pytest.fixture
def whisper(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeWhisper]:
    fake = FakeWhisper([" Hello", " there. "])
    monkeypatch.setitem(sys.modules, "faster_whisper", fake)
    monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)
    yield fake


# --- The pinned model --------------------------------------------------------


def test_the_model_is_pinned_to_a_commit_and_a_checksum() -> None:
    assert MODEL_REPOSITORY == "Systran/faster-whisper-small.en"
    assert re.fullmatch(r"[0-9a-f]{40}", MODEL_REVISION)
    assert re.fullmatch(r"[0-9a-f]{64}", MODEL_SHA256)
    assert MODEL_FILES == ("config.json", "model.bin", "tokenizer.json", "vocabulary.txt")


def test_the_download_script_uses_the_pinned_https_address() -> None:
    script = Path(__file__).parent.parent / "scripts" / "download_speech_model.py"
    source = script.read_text(encoding="utf-8")
    assert (
        'BASE_URL = f"https://huggingface.co/{MODEL_REPOSITORY}/resolve/{MODEL_REVISION}/"'
        in source
    )
    assert "MODEL_FILE_SHA256" in source
    assert "http://" not in source


def test_file_sha256(tmp_path: Path) -> None:
    path = tmp_path / "x"
    path.write_bytes(b"abc" * 1_000_000)
    assert file_sha256(path) == hashlib.sha256(b"abc" * 1_000_000).hexdigest()


# --- Checking the folder -----------------------------------------------------


def test_a_good_folder_passes(folder: Path) -> None:
    check_model_folder(folder, MODEL_HASH, FAKE_FILES)


def test_a_missing_folder_is_reported(tmp_path: Path) -> None:
    with pytest.raises(SpeechModelMissingError):
        check_model_folder(tmp_path / "nowhere", MODEL_HASH, FAKE_FILES)


@pytest.mark.parametrize("name", MODEL_FILES)
def test_a_missing_file_is_refused(folder: Path, name: str) -> None:
    (folder / name).unlink()
    with pytest.raises(SpeechModelInvalidError):
        check_model_folder(folder, MODEL_HASH, FAKE_FILES)


def test_a_linked_file_is_refused(folder: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_bytes(b"{}")
    (folder / "config.json").unlink()
    (folder / "config.json").symlink_to(elsewhere)
    with pytest.raises(SpeechModelInvalidError):
        check_model_folder(folder, MODEL_HASH, FAKE_FILES)


def test_a_changed_model_is_refused(folder: Path) -> None:
    (folder / "model.bin").write_bytes(MODEL_BYTES + b"!")
    with pytest.raises(SpeechModelInvalidError):
        check_model_folder(folder, MODEL_HASH, FAKE_FILES)


def test_the_real_checksum_is_checked_by_default(folder: Path) -> None:
    with pytest.raises(SpeechModelInvalidError):
        check_model_folder(folder)


# --- Transcribing ------------------------------------------------------------


def test_it_transcribes_offline_from_the_checked_folder(folder: Path, whisper: FakeWhisper) -> None:
    transcriber = WhisperTranscriber(folder, expected_sha256=MODEL_HASH, expected_files=FAKE_FILES)
    assert transcriber(ONE_SECOND) == "Hello there."
    assert whisper.loaded == [(str(folder), {"device": "cpu", "compute_type": "int8"})]
    assert whisper.offline_when_loaded == "1"
    samples, options = whisper.calls[0]
    assert len(samples) == 16_000
    assert abs(float(samples[0]) - 16 / 32768) < 1e-9
    assert options["language"] == "en"
    assert options["vad_filter"] is False
    # The model is loaded once.
    transcriber(ONE_SECOND)
    assert len(whisper.loaded) == 1


def test_very_short_audio_is_not_transcribed(folder: Path, whisper: FakeWhisper) -> None:
    transcriber = WhisperTranscriber(folder, expected_sha256=MODEL_HASH, expected_files=FAKE_FILES)
    assert transcriber(b"") == ""
    assert transcriber(ONE_SECOND[:1000]) == ""
    assert whisper.loaded == []


def test_a_bad_model_is_refused_before_it_is_loaded(folder: Path, whisper: FakeWhisper) -> None:
    transcriber = WhisperTranscriber(folder)  # The real checksum: the fake fails it.
    with pytest.raises(SpeechModelInvalidError):
        transcriber(ONE_SECOND)
    assert whisper.loaded == []


def test_a_missing_model_is_reported(tmp_path: Path, whisper: FakeWhisper) -> None:
    with pytest.raises(SpeechModelMissingError):
        WhisperTranscriber(tmp_path / "none")(ONE_SECOND)


def test_the_transcript_is_one_line_and_capped(folder: Path, whisper: FakeWhisper) -> None:
    whisper.texts = ["a\n\tb  ", "c" * 5000]
    text = WhisperTranscriber(folder, expected_sha256=MODEL_HASH, expected_files=FAKE_FILES)(
        ONE_SECOND
    )
    assert text.startswith("a b c")
    assert len(text) == MAX_TRANSCRIPT_CHARACTERS
    assert "\n" not in text


def test_an_odd_number_of_bytes_is_fine(folder: Path, whisper: FakeWhisper) -> None:
    WhisperTranscriber(folder, expected_sha256=MODEL_HASH, expected_files=FAKE_FILES)(
        ONE_SECOND + b"\x01"
    )
    assert len(whisper.calls[0][0]) == 16_000


@pytest.mark.parametrize("name", ["config.json", "tokenizer.json", "vocabulary.txt"])
def test_every_file_is_checked_not_just_the_model(folder: Path, name: str) -> None:
    (folder / name).write_bytes(b'{"changed": true}')
    with pytest.raises(SpeechModelInvalidError):
        check_model_folder(folder, MODEL_HASH, FAKE_FILES)


def test_every_pinned_file_has_a_checksum() -> None:
    assert set(MODEL_FILE_SHA256) == set(MODEL_FILES)
    assert MODEL_FILE_SHA256["model.bin"] == MODEL_SHA256
    for value in MODEL_FILE_SHA256.values():
        assert re.fullmatch(r"[0-9a-f]{64}", value)
