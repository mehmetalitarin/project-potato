"""Tests for the process runner's probes and limits (T-TOOL-3; R3).

The limits are tested with real, harmless programs: short Python snippets
run by the same interpreter that runs the tests.
"""

import ast
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

import potato.integrations.processes as processes
from potato.integrations.processes import (
    MAX_LISTING_OUTPUT_BYTES,
    MAX_NETWORK_OUTPUT_BYTES,
    MAX_PROBE_OUTPUT_BYTES,
    PROBE_TIMEOUT_SECONDS,
    Probe,
    run_probe,
)

SOURCE_FILE = Path(processes.__file__)
SOURCE = SOURCE_FILE.read_text(encoding="utf-8")
SOURCE_TREE = SOURCE_FILE.parent.parent


def python(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def bounded(code: str, **limits: Any) -> bytes | None:
    return processes._run_bounded(python(code), **limits)


# --- The fixed list ----------------------------------------------------------


def test_the_probes_are_exactly_these_commands() -> None:
    assert {probe.name: probe.value for probe in Probe} == {
        "FILEVAULT": ("/usr/bin/fdesetup", "status"),
        "FIREWALL": ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"),
        "GATEKEEPER": ("/usr/sbin/spctl", "--status"),
        "SYSTEM_INTEGRITY": ("/usr/bin/csrutil", "status"),
        "PROCESSES": (
            "/bin/ps", "-ax", "-o", "pid=", "-o", "pcpu=", "-o", "rss=", "-o", "uid=",
            "-o", "ucomm=",
        ),
        "NETWORK": ("/usr/sbin/lsof", "-nP", "-i", "-F", "pcfPnT"),
    }  # fmt: skip


def test_the_network_list_never_looks_anything_up() -> None:
    # "-n" keeps addresses as numbers and "-P" keeps ports as numbers, so
    # lsof never asks a name server. "-i" limits it to network sockets.
    program, *arguments = Probe.NETWORK.value
    assert program == "/usr/sbin/lsof"
    assert arguments[0] == "-nP"
    assert arguments[1] == "-i"
    # Field output only: process, name, socket, protocol, addresses, TCP state.
    assert arguments[2:] == ["-F", "pcfPnT"]


def test_the_process_list_never_asks_for_command_lines() -> None:
    # T-TOOL-4: arguments and environment variables can hold secrets.
    _, *arguments = Probe.PROCESSES.value
    columns = [word.rstrip("=") for word in arguments if word.endswith("=")]
    assert columns == ["pid", "pcpu", "rss", "uid", "ucomm"]
    assert [word for word in arguments if not word.endswith("=")] == ["-ax"] + ["-o"] * 5
    for word in arguments:
        # "-e" and "-E" add the environment; "-w" widens command lines.
        assert word not in ("-e", "-E", "-w", "-ww")
        for column in ("args", "command", "comm=", "env"):
            assert column not in word.replace("ucomm=", "")


def test_every_probe_is_a_system_program_with_read_only_arguments() -> None:
    for probe in Probe:
        program, *arguments = probe.value
        assert program.startswith(("/bin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/")), probe
        assert ".." not in program
        # Words that would change a setting never appear.
        for argument in arguments:
            lowered = argument.lower()
            for word in ("enable", "disable", "set", "add", "remove", "delete", "reset",
                         "master", "install", "sudo", "clear"):  # fmt: skip
                assert word not in lowered.replace("getglobalstate", ""), (probe, argument)


@pytest.mark.parametrize(
    "probe",
    ["FILEVAULT", ("/usr/bin/fdesetup", "status"), ("/bin/sh", "-c", "id"), "/bin/sh", None, 0,
     ["/usr/bin/csrutil", "status"]],
)  # fmt: skip
def test_only_a_listed_probe_can_be_run(monkeypatch: pytest.MonkeyPatch, probe: Any) -> None:
    started: list[object] = []
    monkeypatch.setattr(processes, "_run_bounded", lambda *a, **k: started.append(a))
    with pytest.raises(ValueError, match="listed probe"):
        run_probe(probe)
    assert started == []


@pytest.mark.parametrize("probe", list(Probe))
def test_a_probe_runs_exactly_its_fixed_command(
    monkeypatch: pytest.MonkeyPatch, probe: Probe
) -> None:
    started: list[object] = []

    def record(command: object, **limits: object) -> bytes:
        started.append((command, limits))
        return b"some output\n"

    monkeypatch.setattr(processes, "_run_bounded", record)
    assert run_probe(probe) == "some output\n"
    limit = {
        Probe.PROCESSES: MAX_LISTING_OUTPUT_BYTES,
        Probe.NETWORK: MAX_NETWORK_OUTPUT_BYTES,
    }.get(probe, MAX_PROBE_OUTPUT_BYTES)
    assert started == [(probe.value, {"max_bytes": limit})]


def test_bytes_that_are_not_plain_ascii_become_a_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The marker (U+FFFD) is accepted by no caller's pattern. The rest stays
    # readable, so one odd name cannot hide the whole list of processes.
    output = b"FileVault is On.\xc3\xa9\nnext \xff line\n"
    monkeypatch.setattr(processes, "_run_bounded", lambda *a, **k: output)
    text = run_probe(Probe.FILEVAULT)
    assert text == "FileVault is On.\ufffd\ufffd\nnext \ufffd line\n"
    assert text.isascii() is False


def test_a_failed_probe_gives_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(processes, "_run_bounded", lambda *a, **k: None)
    for probe in Probe:
        assert run_probe(probe) is None


def test_default_limits() -> None:
    assert PROBE_TIMEOUT_SECONDS == 5.0
    assert MAX_PROBE_OUTPUT_BYTES == 4096
    assert MAX_LISTING_OUTPUT_BYTES == 262144
    assert MAX_NETWORK_OUTPUT_BYTES == 1048576


# --- How a program is started ------------------------------------------------


def test_a_program_gets_no_input_and_a_bare_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("POTATO_SECRET_FOR_TEST", "must-not-be-passed-on")
    code = (
        "import os, sys\n"
        "print(sorted(k for k in os.environ if not k.startswith(('__', 'LC_CTYPE'))))\n"
        "print(repr(sys.stdin.read()))\n"
    )
    output = bounded(code)
    assert output is not None
    names, stdin = output.decode().splitlines()
    assert names == "['PATH']"
    assert stdin == "''"
    assert b"must-not-be-passed-on" not in output


def test_the_exit_code_does_not_matter() -> None:
    # Some of Apple's tools exit with an error code to say a setting is off.
    assert bounded("import sys; print('assessments disabled'); sys.exit(1)") == (
        b"assessments disabled\n"
    )


def test_error_output_is_discarded() -> None:
    assert bounded("import sys; sys.stderr.write('noise'); print('answer')") == b"answer\n"


def test_arguments_are_never_read_by_a_shell(tmp_path: Path) -> None:
    marker = tmp_path / "created-by-shell"
    code = "import sys; print(sys.argv[1:])"
    hostile = f"; touch {marker} $(touch {marker}) `touch {marker}` | touch {marker}"
    output = processes._run_bounded([sys.executable, "-c", code, hostile])
    assert output is not None
    assert hostile in output.decode()
    assert not marker.exists()


@pytest.mark.parametrize(
    "command",
    [["/no/such/program"], ["relative-name-that-does-not-exist"], [], ["/etc/hostname"],
     ["bad\x00name"]],
)  # fmt: skip
def test_a_program_that_cannot_start_gives_nothing(command: list[str]) -> None:
    assert processes._run_bounded(command) is None


# --- Limits, enforced while the program runs ---------------------------------


def test_output_at_the_cap_is_returned() -> None:
    output = bounded("import sys; sys.stdout.write('x' * 4096)")
    assert output == b"x" * MAX_PROBE_OUTPUT_BYTES


def test_output_over_the_cap_is_thrown_away() -> None:
    assert bounded("import sys; sys.stdout.write('x' * 4097)") is None


def test_endless_output_is_stopped_quickly() -> None:
    started = time.monotonic()
    code = "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n"
    assert bounded(code, timeout=30.0) is None
    assert time.monotonic() - started < 10


def test_output_that_never_pauses_is_stopped_at_the_time_limit() -> None:
    # With a cap too large to reach, only the clock can stop this program.
    code = "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n"
    started = time.monotonic()
    assert bounded(code, timeout=0.5, max_bytes=10**15) is None
    assert time.monotonic() - started < 10


def test_a_silent_program_is_stopped_at_the_time_limit() -> None:
    started = time.monotonic()
    assert bounded("import time; time.sleep(60)", timeout=0.5) is None
    assert time.monotonic() - started < 10


def test_output_dripped_slowly_is_stopped_at_the_time_limit() -> None:
    code = (
        "import sys, time\n"
        "while True:\n"
        "    sys.stdout.write('x'); sys.stdout.flush(); time.sleep(0.05)\n"
    )
    started = time.monotonic()
    assert bounded(code, timeout=0.5) is None
    assert time.monotonic() - started < 10


def test_a_program_that_closes_its_output_but_keeps_running_is_stopped() -> None:
    code = "import os, time\nprint('early', flush=True)\nos.close(1)\ntime.sleep(60)\n"
    started = time.monotonic()
    assert bounded(code, timeout=0.5) is None
    assert time.monotonic() - started < 10


def _pid_file_code(path: Path, then: str) -> str:
    return f"import os\nopen({str(path)!r}, 'w').write(str(os.getpid()))\n{then}\n"


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.mark.parametrize(
    "then",
    [
        "import time; time.sleep(60)",
        "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)",
        "import os, time; os.close(1); time.sleep(60)",
    ],
    ids=["silent", "endless", "closed-output"],
)
def test_a_stopped_program_is_really_gone(tmp_path: Path, then: str) -> None:
    pid_file = tmp_path / "pid"
    assert bounded(_pid_file_code(pid_file, then), timeout=3.0) is None
    pid = int(pid_file.read_text())
    assert not _is_running(pid)


def test_a_finished_program_leaves_nothing_behind(tmp_path: Path) -> None:
    pid_file = tmp_path / "pid"
    assert bounded(_pid_file_code(pid_file, "print('done')")) == b"done\n"
    assert not _is_running(int(pid_file.read_text()))


def test_no_file_descriptor_is_leaked() -> None:
    before = len(list(Path("/dev/fd").iterdir()))
    for _ in range(20):
        bounded("print('x')")
        bounded("import time; time.sleep(60)", timeout=0.05)
        processes._run_bounded(["/no/such/program"])
    assert len(list(Path("/dev/fd").iterdir())) <= before + 1


# --- The module's shape (R3) -------------------------------------------------


def _subprocess_calls() -> list[ast.Call]:
    return [
        node
        for node in ast.walk(ast.parse(SOURCE))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
    ]


def test_there_are_exactly_two_places_that_start_a_program() -> None:
    names = sorted(call.func.attr for call in _subprocess_calls())  # type: ignore[attr-defined]
    assert names == ["Popen", "run"]
    assert processes.OPEN_PROGRAM == "/usr/bin/open"


def test_neither_place_uses_a_shell_or_inherits_the_environment() -> None:
    for call in _subprocess_calls():
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        assert "shell" not in keywords
        assert "executable" not in keywords
        assert isinstance(keywords["env"], ast.Name)
        assert keywords["env"].id == "_ENVIRONMENT"
        assert ast.unparse(keywords["stdin"]) == "subprocess.DEVNULL"
        assert ast.unparse(keywords["stderr"]) == "subprocess.DEVNULL"
    assert processes._ENVIRONMENT == {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}


def test_the_bounded_runner_is_used_only_by_run_probe() -> None:
    # Inside the module: its definition and the one call in run_probe.
    assert SOURCE.count("_run_bounded(") == 2
    for path in SOURCE_TREE.rglob("*.py"):
        if path != SOURCE_FILE:
            assert "_run_bounded" not in path.read_text(encoding="utf-8"), path.name


def test_only_these_modules_use_the_runner() -> None:
    users = sorted(
        path.relative_to(SOURCE_TREE).as_posix()
        for path in SOURCE_TREE.rglob("*.py")
        if "potato.integrations.processes" in path.read_text(encoding="utf-8")
        or "integrations import processes" in path.read_text(encoding="utf-8")
    )
    assert users == [
        "modules/launcher.py",
        "modules/network_overview.py",
        "modules/process_overview.py",
        "modules/security_posture.py",
    ]
