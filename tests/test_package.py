"""Smoke tests for the package and its command line.

These prove the package installs, imports and reports its version correctly.
Starting Potato itself is tested in test_app.py.
"""

import importlib
import inspect
import re
import runpy
import sys
from importlib import metadata, resources
from pathlib import Path

import pytest

import potato
import potato.app
from potato.__main__ import main

SUBPACKAGES = (
    "core",
    "integrations",
    "modules",
    "security",
    "storage",
    "ui",
    "voice",
)


def test_version_is_a_plain_semantic_version() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", potato.__version__)


def test_version_matches_installed_metadata() -> None:
    # Guards the single source of truth: pyproject.toml reads the version
    # from src/potato/__init__.py at build time.
    assert metadata.version("potato-assistant") == potato.__version__


def test_package_declares_type_information() -> None:
    assert resources.files("potato").joinpath("py.typed").is_file()


@pytest.mark.parametrize("name", SUBPACKAGES)
def test_subpackage_imports_and_documents_its_boundary(name: str) -> None:
    module = importlib.import_module(f"potato.{name}")

    assert module.__doc__ is not None
    assert "Boundary:" in module.__doc__


def test_version_flag_prints_version_and_exits_cleanly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"potato {potato.__version__}"


def test_no_arguments_starts_potato_and_passes_on_its_exit_code() -> None:
    started: list[str] = []

    def start() -> int:
        started.append("started")
        return 7

    assert main([], start=start) == 7
    assert started == ["started"]


def test_by_default_no_arguments_starts_the_real_application() -> None:
    assert inspect.signature(main).parameters["start"].default is potato.app.run


def test_reporting_options_do_not_start_potato(monkeypatch: pytest.MonkeyPatch) -> None:
    def start() -> int:
        raise AssertionError("Potato was started")

    with pytest.raises(SystemExit):
        main(["--version"], start=start)
    with pytest.raises(SystemExit):
        main(["--help"], start=start)
    monkeypatch.setattr("potato.__main__.default_settings_path", lambda: Path("/nonexistent/x"))
    assert main(["--check-settings"], start=start) == 0


def test_unknown_argument_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--not-a-real-option"])

    assert excinfo.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_module_entry_point_runs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.argv", ["potato", "--version"])
    # This file already imported potato.__main__; drop it so runpy executes a
    # fresh copy, exactly as ``python -m potato`` would.
    monkeypatch.delitem(sys.modules, "potato.__main__")

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("potato", run_name="__main__")

    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"potato {potato.__version__}"
