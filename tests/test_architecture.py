"""Import rules for the source tree (R2, R3, R4, R5 in docs/architecture.md).

These tests read every source file. They run in CI with the rest, so a
change that breaks a rule cannot be merged.
"""

import ast
from pathlib import Path

import pytest

SOURCE = Path(__file__).parent.parent / "src" / "potato"
PACKAGES = ("core", "security", "modules", "integrations", "voice", "storage", "ui")

# Which of Potato's own packages each package may import. Anything not
# listed is forbidden. "security" is the base and imports none of the others.
ALLOWED: dict[str, frozenset[str]] = {
    "security": frozenset(),
    "storage": frozenset({"security"}),
    "integrations": frozenset({"security"}),
    "core": frozenset({"security", "storage", "integrations"}),
    "modules": frozenset({"security", "storage", "integrations"}),
    "voice": frozenset({"security", "core"}),
    "ui": frozenset({"security", "core"}),
}

# R2: the one part of "integrations" the orchestrator may use.
CORE_MAY_IMPORT_FROM_INTEGRATIONS = "potato.integrations.ollama"

# R3: modules allowed to start a process. None exist yet. The single probe
# module in "integrations" is added here in the commit that creates it.
MAY_START_PROCESSES: frozenset[str] = frozenset()

STARTS_PROCESSES = frozenset({"subprocess", "pty", "multiprocessing", "pexpect", "sh"})
RUNS_OR_LOADS_CODE = frozenset(
    {"importlib", "runpy", "code", "codeop", "ctypes", "pickle", "marshal", "shelve", "imp"}
)
NETWORKING = frozenset(
    {
        "socket", "socketserver", "ssl", "http", "urllib.request", "urllib3", "requests",
        "httpx", "aiohttp", "websockets", "ftplib", "smtplib", "telnetlib", "xmlrpc", "asyncio",
    }
)  # fmt: skip
FORBIDDEN_CALLS = frozenset({"eval", "exec", "compile", "__import__", "breakpoint"})
FORBIDDEN_OS_PREFIXES = ("system", "popen", "exec", "spawn", "posix_spawn", "fork", "startfile")


def _source_files() -> list[Path]:
    return sorted(SOURCE.rglob("*.py"))


def _module_name(path: Path) -> str:
    parts = ("potato", *path.relative_to(SOURCE).with_suffix("").parts)
    return ".".join(part for part in parts if part != "__init__")


def _package(path: Path) -> str | None:
    """The top-level package a file belongs to, or ``None`` for ``potato`` itself."""
    first = path.relative_to(SOURCE).parts[0]
    return first if first in PACKAGES else None


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(path: Path) -> list[str]:
    """Every module name a file imports, wherever in the file the import is."""
    names: list[str] = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # "from potato import modules" is recorded as potato.modules.
            names.extend(f"{node.module or ''}.{alias.name}" for alias in node.names)
    return names


def _matches(name: str, banned: frozenset[str]) -> bool:
    return any(name == item or name.startswith(item + ".") for item in banned)


FILES = _source_files()
IDS = [path.relative_to(SOURCE).as_posix() for path in FILES]


def test_the_source_tree_was_found() -> None:
    assert len(FILES) >= 15
    assert {path.relative_to(SOURCE).parts[0] for path in FILES} >= set(PACKAGES)
    assert set(ALLOWED) == set(PACKAGES)


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_no_relative_or_hidden_imports(path: Path) -> None:
    # The rules below read import statements, so every import must be a
    # plain absolute one that they can see.
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"relative import on line {node.lineno}"
            assert all(alias.name != "*" for alias in node.names), f"line {node.lineno}"
    for name in _imports(path):
        assert not _matches(name, RUNS_OR_LOADS_CODE), f"imports {name}"


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_package_imports_follow_the_layers(path: Path) -> None:
    package = _package(path)
    if package is None:
        return  # potato/__main__.py wires the application together.
    for name in _imports(path):
        if not name.startswith("potato."):
            continue
        target = name.split(".")[1]
        if target not in PACKAGES or target == package:
            continue
        assert target in ALLOWED[package], f"{package} must not import {name}"


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_the_orchestrator_cannot_reach_the_tools(path: Path) -> None:
    # R2.
    if _package(path) != "core":
        return
    for name in _imports(path):
        assert not _matches(name, frozenset({"potato.modules"})), f"core imports {name}"
        if _matches(name, frozenset({"potato.integrations"})):
            assert _matches(name, frozenset({CORE_MAY_IMPORT_FROM_INTEGRATIONS})), name


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_voice_cannot_reach_approvals_the_interface_or_the_tools(path: Path) -> None:
    # R4.
    if _package(path) != "voice":
        return
    banned = frozenset({"potato.ui", "potato.modules", "potato.security.approvals"})
    for name in _imports(path):
        assert not _matches(name, banned), f"voice imports {name}"


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_nothing_starts_a_process_or_runs_text_as_code(path: Path) -> None:
    # R3. Ruff's security rules cover much of this too; this is the second lock.
    allowed_here = _module_name(path) in MAY_START_PROCESSES
    for name in _imports(path):
        if _matches(name, STARTS_PROCESSES):
            assert allowed_here, f"imports {name}"
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name):
                assert function.id not in FORBIDDEN_CALLS, f"{function.id}() line {node.lineno}"
            for keyword in node.keywords:
                assert keyword.arg != "shell", f"shell= on line {node.lineno}"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr.startswith(FORBIDDEN_OS_PREFIXES):
                raise AssertionError(f"os.{node.attr} on line {node.lineno}")
            if node.value.id == "builtins":
                assert node.attr not in FORBIDDEN_CALLS, f"builtins.{node.attr}"
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                assert not alias.name.startswith(FORBIDDEN_OS_PREFIXES), (
                    f"from os import {alias.name}"
                )


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_networking_lives_only_in_integrations(path: Path) -> None:
    # R5.
    if _package(path) == "integrations":
        return
    for name in _imports(path):
        assert not _matches(name, NETWORKING), f"imports {name}"


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_nothing_listens_for_connections(path: Path) -> None:
    # R5: no listening socket anywhere, "integrations" included.
    servers = frozenset({"socketserver", "http.server", "xmlrpc.server", "wsgiref"})
    for name in _imports(path):
        assert not _matches(name, servers), f"imports {name}"
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"listen", "create_server", "start_server"}, (
                f".{node.attr} on line {node.lineno}"
            )


# --- The checks themselves are checked ---------------------------------------


def _write(tmp_path: Path, relative: str, text: str) -> Path:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# Short names for the table below.
R2 = test_the_orchestrator_cannot_reach_the_tools
LAYERS = test_package_imports_follow_the_layers
R4 = test_voice_cannot_reach_approvals_the_interface_or_the_tools
HIDDEN = test_no_relative_or_hidden_imports
R3 = test_nothing_starts_a_process_or_runs_text_as_code
R5 = test_networking_lives_only_in_integrations
LISTEN = test_nothing_listens_for_connections


@pytest.mark.parametrize(
    ("relative", "text", "check"),
    [
        ("core/x.py", "import potato.modules.launcher\n", R2),
        ("core/x.py", "from potato import modules\n", R2),
        ("core/x.py", "from potato.modules import launcher\n", LAYERS),
        ("core/x.py", "def f():\n    import potato.modules.a\n", LAYERS),
        ("core/x.py", "import potato.integrations.calendar\n", R2),
        ("core/x.py", "from potato import integrations\n", R2),
        ("security/x.py", "from potato.core import state\n", LAYERS),
        ("security/x.py", "import potato.ui\n", LAYERS),
        ("voice/x.py", "from potato.security.approvals import ApprovalRequest\n", R4),
        ("voice/x.py", "from potato.security import approvals\n", R4),
        ("voice/x.py", "import potato.ui.window\n", R4),
        ("core/x.py", "from . import config\n", HIDDEN),
        ("core/x.py", "from ..modules import launcher\n", HIDDEN),
        ("core/x.py", "from potato.security.gate import *\n", HIDDEN),
        ("core/x.py", "import importlib\n", HIDDEN),
        ("core/x.py", "import pickle\n", HIDDEN),
        ("modules/x.py", "import subprocess\n", R3),
        ("modules/x.py", "from subprocess import run\n", R3),
        ("modules/x.py", "import os\nos.system('ls')\n", R3),
        ("modules/x.py", "import os\nrun = os.popen\n", R3),
        ("modules/x.py", "from os import execv\n", R3),
        ("modules/x.py", "eval('1')\n", R3),
        ("modules/x.py", "exec('pass')\n", R3),
        ("modules/x.py", "__import__('os')\n", R3),
        ("modules/x.py", "import builtins\nbuiltins.eval('1')\n", R3),
        ("modules/x.py", "run(['ls'], shell=True)\n", R3),
        ("modules/x.py", "import socket\n", R5),
        ("core/x.py", "import urllib.request\n", R5),
        ("ui/x.py", "from http import client\n", R5),
        ("integrations/x.py", "import http.server\n", LISTEN),
        ("integrations/x.py", "import socket\ns = socket.socket()\ns.listen()\n", LISTEN),
    ],
)  # fmt: skip
def test_each_rule_catches_a_planted_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str, text: str, check: object
) -> None:
    path = _write(tmp_path, relative, text)
    monkeypatch.setitem(globals(), "SOURCE", tmp_path)
    with pytest.raises(AssertionError):
        check(path)  # type: ignore[operator]


def test_allowed_imports_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(globals(), "SOURCE", tmp_path)
    fine = [
        ("core/x.py", "from potato.security.audit import AuditLog\n"),
        ("core/y.py", "import potato.integrations.ollama\nimport urllib.parse\n"),
        ("core/z.py", "from potato.integrations.ollama.client import Client\n"),
        ("core/w.py", "from potato.integrations import ollama\n"),
        ("integrations/x.py", "import socket\nimport http.client\n"),
        ("voice/x.py", "from potato.core.state import StateManager\nimport os\nos.getuid()\n"),
        ("storage/x.py", "from potato.security.private_files import ensure_private_directory\n"),
    ]  # fmt: skip
    for relative, text in fine:
        path = _write(tmp_path, relative, text)
        test_no_relative_or_hidden_imports(path)
        test_package_imports_follow_the_layers(path)
        test_the_orchestrator_cannot_reach_the_tools(path)
        test_voice_cannot_reach_approvals_the_interface_or_the_tools(path)
        test_nothing_starts_a_process_or_runs_text_as_code(path)
        test_networking_lives_only_in_integrations(path)
        test_nothing_listens_for_connections(path)
