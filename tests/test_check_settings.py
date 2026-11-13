"""Tests for ``python -m potato --check-settings``."""

from pathlib import Path

import pytest

from potato.__main__ import main


@pytest.fixture
def settings_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the home folder at a temporary directory, so no real file is touched."""
    monkeypatch.setenv("HOME", str(tmp_path))
    folder = tmp_path / "Library" / "Application Support" / "Potato"
    folder.mkdir(parents=True)
    return folder / "settings.toml"


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def test_without_a_file_the_defaults_are_reported(
    settings_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--check-settings"]) == 0

    output = capsys.readouterr()
    assert "built-in defaults" in output.out
    assert "http://127.0.0.1:11434" in output.out
    assert output.err == ""


def test_a_valid_file_is_reported(settings_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write(settings_path, '[ollama]\nhost = "::1"\nport = 12000\n')

    assert main(["--check-settings"]) == 0

    output = capsys.readouterr()
    assert str(settings_path) in output.out
    assert "http://[::1]:12000" in output.out


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('[ollama]\nhost = "0.0.0.0"', "ollama.host must be a loopback IP address"),
        ('[ollama]\nhost = "192.168.1.10"', "ollama.host must be a loopback IP address"),
        ('[ollama]\nmodel = "gpt-oss:120b-cloud"', "ollama.model must be one of"),
        ("[network]\nlisten = true", "unknown section"),
        ("[ollama", "not valid TOML"),
    ],
)
def test_an_invalid_file_fails_with_a_clear_message(
    settings_path: Path, capsys: pytest.CaptureFixture[str], text: str, expected: str
) -> None:
    _write(settings_path, text)

    assert main(["--check-settings"]) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith("Settings problem: ")
    assert expected in output.err


def test_an_unsafe_file_fails(settings_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write(settings_path, "")
    settings_path.chmod(0o666)

    assert main(["--check-settings"]) == 2
    assert "changed by other users" in capsys.readouterr().err


def test_the_rejected_value_is_not_printed(
    settings_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(settings_path, '[ollama]\nhost = "hunter2-canary-value"')

    assert main(["--check-settings"]) == 2

    output = capsys.readouterr()
    assert "hunter2-canary-value" not in output.out + output.err
