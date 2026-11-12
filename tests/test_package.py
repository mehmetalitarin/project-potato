"""Smoke tests for the project scaffold.

These prove the package installs, imports and reports its version correctly.
They do not test any assistant feature, because none exists yet.
"""

import importlib
import re
import runpy
import sys
from importlib import metadata, resources

import pytest

import potato
from potato.__main__ import STATUS_MESSAGE, main

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


def test_default_run_reports_scaffold_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main([])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert STATUS_MESSAGE in output
    assert "No assistant features are implemented yet" in output


def test_unknown_argument_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--not-a-real-option"])

    assert excinfo.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_module_entry_point_runs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.argv", ["potato"])
    # This file already imported potato.__main__; drop it so runpy executes a
    # fresh copy, exactly as ``python -m potato`` would.
    monkeypatch.delitem(sys.modules, "potato.__main__")

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("potato", run_name="__main__")

    assert excinfo.value.code == 0
    assert "project scaffold" in capsys.readouterr().out
