"""Tests for the application launcher and the process runner (T-TOOL-1, T-TOOL-3; R3).

Required test 9: the launcher rejects unknown applications.

Most tests build fake applications in a temporary folder and replace the
step that opens them, so nothing is ever started. On macOS one test also
checks the real Apple applications, without opening them.
"""

import os
import plistlib
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import potato.integrations.processes as processes
from potato.modules.launcher import (
    APPLICATIONS,
    OUTCOMES,
    TRUSTED_FOLDERS,
    Application,
    check_application,
    launcher_tools,
)
from potato.security.audit import AuditLog
from potato.security.gate import Gate, ReasonCode, RequestOrigin
from potato.security.redaction import Redactor

ME = os.getuid()
PERMISSIONS = Path(__file__).parent.parent / "docs" / "permissions.md"


@pytest.fixture(autouse=True)
def usual_umask() -> Iterator[None]:
    previous = os.umask(0o022)
    yield
    os.umask(previous)


def make_app(folder: Path, name: str, bundle_id: str = "com.example.notes") -> Path:
    """Build a minimal application bundle and return its path."""
    app = folder / f"{name}.app"
    contents = app / "Contents"
    contents.mkdir(parents=True)
    info = contents / "Info.plist"
    info.write_bytes(plistlib.dumps({"CFBundleIdentifier": bundle_id}))
    for path in (folder, app, contents):
        path.chmod(0o755)
    info.chmod(0o644)
    return app


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    made = tmp_path / "Applications"
    made.mkdir()
    return made


@pytest.fixture
def notes(folder: Path) -> Application:
    return Application(make_app(folder, "Notes"), "com.example.notes")


def check(application: Application, folder: Path, **options: Any) -> str | None:
    settings: dict[str, Any] = {"trusted_owner": ME, "trusted_folders": frozenset({folder})}
    settings.update(options)
    return check_application(application, **settings)


# --- What counts as genuine --------------------------------------------------


def test_a_genuine_application_passes(notes: Application, folder: Path) -> None:
    assert check(notes, folder) is None


def test_a_missing_application_is_not_installed(folder: Path) -> None:
    assert check(Application(folder / "Gone.app", "com.example.gone"), folder) == "not_installed"


def test_another_owner_is_refused(notes: Application, folder: Path) -> None:
    # Apple's applications belong to root. A copy owned by anyone else is not Apple's.
    assert check(notes, folder, trusted_owner=ME + 1) == "not_genuine"


@pytest.mark.parametrize("part", ["bundle", "info"])
@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777])
def test_an_application_others_can_change_is_refused(
    notes: Application, folder: Path, part: str, mode: int
) -> None:
    target = notes.path if part == "bundle" else notes.path / "Contents" / "Info.plist"
    target.chmod(mode)
    assert check(notes, folder) == "not_genuine"


def test_the_wrong_bundle_identifier_is_refused(folder: Path) -> None:
    fake = make_app(folder, "Notes", bundle_id="com.evil.notes")
    assert check(Application(fake, "com.example.notes"), folder) == "not_genuine"


def test_an_application_outside_the_trusted_folders_is_refused(
    tmp_path: Path, folder: Path
) -> None:
    elsewhere = tmp_path / "Downloads"
    elsewhere.mkdir()
    fake = make_app(elsewhere, "Notes")
    assert check(Application(fake, "com.example.notes"), folder) == "not_genuine"


def test_a_link_to_a_fake_elsewhere_is_refused(tmp_path: Path, folder: Path) -> None:
    elsewhere = tmp_path / "Downloads"
    elsewhere.mkdir()
    fake = make_app(elsewhere, "Notes")
    link = folder / "Notes.app"
    link.symlink_to(fake, target_is_directory=True)
    assert check(Application(link, "com.example.notes"), folder) == "not_genuine"


def test_a_link_to_the_genuine_copy_in_another_trusted_folder_is_allowed(
    tmp_path: Path, folder: Path
) -> None:
    # How recent macOS versions store Safari.
    system = tmp_path / "System"
    system.mkdir()
    real = make_app(system, "Safari", bundle_id="com.example.safari")
    link = folder / "Safari.app"
    link.symlink_to(real, target_is_directory=True)
    trusted = frozenset({folder, system})
    assert check(Application(link, "com.example.safari"), folder, trusted_folders=trusted) is None


def test_a_file_in_place_of_the_application_is_refused(folder: Path) -> None:
    fake = folder / "Notes.app"
    fake.write_bytes(b"not an application")
    assert check(Application(fake, "com.example.notes"), folder) == "not_genuine"


def test_a_target_that_is_not_an_application_is_refused(tmp_path: Path, folder: Path) -> None:
    real = make_app(folder, "Notes")
    renamed = real.with_suffix(".bundle")
    real.rename(renamed)
    link = folder / "Notes.app"
    link.symlink_to(renamed, target_is_directory=True)
    assert check(Application(link, "com.example.notes"), folder) == "not_genuine"


def test_a_linked_description_is_refused(tmp_path: Path, notes: Application, folder: Path) -> None:
    info = notes.path / "Contents" / "Info.plist"
    elsewhere = tmp_path / "other.plist"
    elsewhere.write_bytes(info.read_bytes())
    info.unlink()
    info.symlink_to(elsewhere)
    assert check(notes, folder) == "not_genuine"


def test_a_linked_contents_folder_is_refused(
    tmp_path: Path, notes: Application, folder: Path
) -> None:
    contents = notes.path / "Contents"
    elsewhere = tmp_path / "Contents"
    contents.rename(elsewhere)
    contents.symlink_to(elsewhere, target_is_directory=True)
    assert check(notes, folder) == "not_genuine"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not a property list",
        plistlib.dumps(["com.example.notes"]),
        plistlib.dumps({"CFBundleIdentifier": 5}),
        plistlib.dumps({"CFBundleName": "Notes"}),
        plistlib.dumps({"CFBundleIdentifier": "com.example.notes "}),
        plistlib.dumps({"CFBundleIdentifier": "COM.EXAMPLE.NOTES"}),
    ],
)
def test_an_unusable_description_is_refused(notes: Application, folder: Path, data: bytes) -> None:
    (notes.path / "Contents" / "Info.plist").write_bytes(data)
    assert check(notes, folder) == "not_genuine"


def test_a_binary_description_is_read(folder: Path) -> None:
    app = make_app(folder, "Notes")
    data = plistlib.dumps({"CFBundleIdentifier": "com.example.notes"}, fmt=plistlib.FMT_BINARY)
    (app / "Contents" / "Info.plist").write_bytes(data)
    assert check(Application(app, "com.example.notes"), folder) is None


def test_an_oversized_description_is_refused(notes: Application, folder: Path) -> None:
    padding = "x" * (1024 * 1024)
    data = plistlib.dumps({"CFBundleIdentifier": "com.example.notes", "Padding": padding})
    (notes.path / "Contents" / "Info.plist").write_bytes(data)
    assert check(notes, folder) == "not_genuine"


def test_a_missing_description_is_refused(notes: Application, folder: Path) -> None:
    (notes.path / "Contents" / "Info.plist").unlink()
    assert check(notes, folder) == "not_genuine"


def test_a_named_pipe_as_description_is_refused_without_waiting(
    notes: Application, folder: Path
) -> None:
    info = notes.path / "Contents" / "Info.plist"
    info.unlink()
    os.mkfifo(info, 0o644)
    assert check(notes, folder) == "not_genuine"


# --- The tool, through the gate ----------------------------------------------


class Opener:
    """Stands in for the step that really opens an application."""

    def __init__(self, succeeds: bool = True) -> None:
        self.opened: list[Path] = []
        self.succeeds = succeeds

    def __call__(self, path: Path) -> bool:
        self.opened.append(path)
        return self.succeeds


@pytest.fixture
def opener() -> Opener:
    return Opener()


@pytest.fixture
def gate(tmp_path: Path, folder: Path, notes: Application, opener: Opener) -> Iterator[Gate]:
    applications = {
        "Notes": notes,
        "Calculator": Application(folder / "Calculator.app", "com.example.calculator"),
    }
    tools = launcher_tools(
        applications, trusted_owner=ME, trusted_folders=frozenset({folder}), opener=opener
    )
    with AuditLog(tmp_path / "logs" / "audit.jsonl", Redactor()) as audit:
        yield Gate(tools, audit)


def _open(gate: Gate, name: object, origin: RequestOrigin = RequestOrigin.VOICE) -> Any:
    return gate.submit({"tool": "open_app", "arguments": {"name": name}}, origin)


@pytest.mark.parametrize("origin", list(RequestOrigin))
def test_any_origin_can_open_an_approved_application(
    gate: Gate, opener: Opener, notes: Application, origin: RequestOrigin
) -> None:
    result = _open(gate, "Notes", origin)
    assert result.ok
    assert result.result == {
        "application": "Notes",
        "opened": True,
        "message": OUTCOMES["opened"],
    }
    assert opener.opened == [notes.path]


@pytest.mark.parametrize(
    "name",
    [
        "Terminal", "System Settings", "notes", "NOTES", " Notes", "Notes.app",
        "/System/Applications/Notes.app", "../Notes", "Notes; open -a Terminal", "", None, 5,
        ["Notes"], {"name": "Notes"},
    ],
)  # fmt: skip
def test_unknown_applications_are_refused_and_nothing_opens(
    gate: Gate, opener: Opener, name: object
) -> None:
    # Required test 9.
    assert _open(gate, name).reason is ReasonCode.INVALID_ARGUMENTS
    assert opener.opened == []


def test_extra_arguments_are_refused(gate: Gate, opener: Opener) -> None:
    for extra in ({"file": "/etc/passwd"}, {"url": "https://evil.example"}, {"args": ["-x"]}):
        proposal = {"tool": "open_app", "arguments": {"name": "Notes", **extra}}
        assert gate.submit(proposal, RequestOrigin.TYPED).reason is ReasonCode.INVALID_ARGUMENTS
    assert opener.opened == []


def test_a_missing_application_reports_it_and_opens_nothing(gate: Gate, opener: Opener) -> None:
    result = _open(gate, "Calculator")
    assert result.result == {
        "application": "Calculator",
        "opened": False,
        "message": OUTCOMES["not_installed"],
    }
    assert opener.opened == []


def test_a_fake_application_reports_it_and_opens_nothing(
    gate: Gate, opener: Opener, notes: Application
) -> None:
    (notes.path / "Contents" / "Info.plist").write_bytes(
        plistlib.dumps({"CFBundleIdentifier": "com.evil.notes"})
    )
    result = _open(gate, "Notes")
    assert result.result["opened"] is False
    assert result.result["message"] == OUTCOMES["not_genuine"]
    assert opener.opened == []


def test_macos_refusing_to_open_is_reported(
    tmp_path: Path, folder: Path, notes: Application
) -> None:
    tools = launcher_tools(
        {"Notes": notes},
        trusted_owner=ME,
        trusted_folders=frozenset({folder}),
        opener=Opener(succeeds=False),
    )
    with AuditLog(tmp_path / "audit" / "audit.jsonl", Redactor()) as audit:
        result = _open(Gate(tools, audit), "Notes")
    assert result.result["message"] == OUTCOMES["did_not_open"]
    assert result.result["opened"] is False


def test_opening_is_rate_limited(gate: Gate, opener: Opener) -> None:
    results = [_open(gate, "Notes").ok for _ in range(7)]
    assert results == [True] * 5 + [False] * 2


def test_the_model_is_offered_exactly_the_list() -> None:
    (tool,) = launcher_tools()
    parameters: Any = tool.describe()["function"]
    assert parameters["parameters"]["properties"]["name"]["enum"] == sorted(APPLICATIONS)


# --- The fixed list ------------------------------------------------------------


def test_the_list_holds_apples_applications_only() -> None:
    assert "Terminal" not in APPLICATIONS
    assert "System Settings" not in APPLICATIONS
    for name, application in APPLICATIONS.items():
        assert application.bundle_id.startswith("com.apple."), name
        assert application.path.name == f"{name}.app"
        assert application.path.parent in processes.APPLICATION_FOLDERS, name
        assert application.path.parent in TRUSTED_FOLDERS, name


def test_the_list_cannot_be_changed_at_run_time() -> None:
    with pytest.raises(TypeError):
        APPLICATIONS["Terminal"] = Application(Path("/x.app"), "x")  # type: ignore[index]


@pytest.mark.skipif(sys.platform != "darwin", reason="Apple's applications exist on macOS only")
def test_apples_real_applications_pass_the_checks() -> None:
    # Checks only; nothing is opened.
    installed = {name: app for name, app in APPLICATIONS.items() if app.path.exists()}
    assert "Calculator" in installed
    for name, application in installed.items():
        assert check_application(application) is None, name


# --- The process runner (R3) -------------------------------------------------


class Recorder:
    def __init__(self, returncode: int = 0, raises: BaseException | None = None) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.returncode = returncode
        self.raises = raises

    def __call__(self, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((args, kwargs))
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(args[0], self.returncode)


def test_the_runner_starts_exactly_one_fixed_command(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = Recorder()
    monkeypatch.setattr(subprocess, "run", recorder)
    assert processes.open_application(Path("/System/Applications/Calculator.app")) is True
    ((args, kwargs),) = recorder.calls
    assert args == (["/usr/bin/open", "-a", "/System/Applications/Calculator.app"],)
    assert kwargs == {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        "timeout": 10.0,
        "check": False,
    }


@pytest.mark.parametrize(
    "path",
    [
        Path("Calculator.app"),
        Path("/System/Applications/Calculator"),
        Path("/System/Applications/Calculator.app/Contents/MacOS/Calculator"),
        Path("/tmp/Calculator.app"),  # noqa: S108 - a path that must be refused
        Path("/Users/someone/Applications/Calculator.app"),
        Path("/Applications/Games/Evil.app"),
        Path("/Applications/../tmp/Evil.app"),
        Path("/System/Applications/../../tmp/Evil.app"),
        Path("/Applications/Evil\x00.app"),
        "/System/Applications/Calculator.app",
        None,
    ],
)
def test_the_runner_refuses_anything_but_a_standard_application(
    monkeypatch: pytest.MonkeyPatch, path: Any
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(subprocess, "run", recorder)
    with pytest.raises(ValueError, match="standard folder"):
        processes.open_application(path)
    assert recorder.calls == []


@pytest.mark.parametrize(
    "recorder",
    [
        Recorder(returncode=1),
        Recorder(raises=FileNotFoundError("no open program")),
        Recorder(raises=subprocess.TimeoutExpired("open", 10)),
        Recorder(raises=PermissionError("denied")),
    ],
)
def test_the_runner_reports_failure_without_raising(
    monkeypatch: pytest.MonkeyPatch, recorder: Recorder
) -> None:
    monkeypatch.setattr(subprocess, "run", recorder)
    assert processes.open_application(Path("/Applications/Safari.app")) is False


# --- Documentation -----------------------------------------------------------


def test_the_tool_is_in_the_documented_table_with_the_same_risk() -> None:
    import re

    text = PERMISSIONS.read_text(encoding="utf-8")
    section = text.split("## Planned tools", 1)[1].split("\n## ", 1)[0]
    rows = dict(re.findall(r"^\| `([a-z_]+)` \|.*\| (Low|Medium|Sensitive) \|$", section, re.M))
    for tool in launcher_tools():
        assert rows.get(tool.name, "").lower() == tool.risk.value


def test_changing_the_list_afterwards_has_no_effect(
    tmp_path: Path, folder: Path, notes: Application
) -> None:
    applications = {"Notes": notes}
    opener = Opener()
    tools = launcher_tools(
        applications, trusted_owner=ME, trusted_folders=frozenset({folder}), opener=opener
    )
    # Swapped after the tool was built: the tool must still open the original.
    applications["Notes"] = Application(make_app(folder, "Other"), "com.example.notes")
    with AuditLog(tmp_path / "audit" / "audit.jsonl", Redactor()) as audit:
        assert _open(Gate(tools, audit), "Notes").ok
    assert opener.opened == [notes.path]
