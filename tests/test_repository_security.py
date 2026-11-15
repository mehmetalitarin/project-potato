"""Tests that keep the repository's CI and hook configuration hardened.

These read the configuration files as text, so they need no YAML library.
They fail if a later change quietly weakens the supply-chain protections.
"""

import re
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def _uses_references(text: str) -> list[str]:
    """Return every action reference after ``uses:`` in a workflow."""
    return re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)


def test_at_least_one_workflow_exists() -> None:
    assert WORKFLOWS, "expected a workflow under .github/workflows"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_pins_every_action_to_a_full_commit_sha(workflow: Path) -> None:
    references = _uses_references(workflow.read_text(encoding="utf-8"))

    assert references, f"{workflow.name} uses no actions"
    for reference in references:
        if reference.startswith("./"):
            continue  # a local action lives in this repository
        _, _, ref = reference.partition("@")
        assert FULL_SHA.fullmatch(ref), f"{reference} is not pinned to a commit SHA"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_defaults_to_read_only_permissions(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")

    top_level = re.search(r"^permissions:\s*\n((?:[ \t]+.*\n)+)", text, flags=re.MULTILINE)
    assert top_level, f"{workflow.name} must declare top-level permissions"
    assert top_level.group(1).strip() == "contents: read"
    assert "write" not in text, f"{workflow.name} must not grant write permissions"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_avoids_dangerous_triggers(workflow: Path) -> None:
    # pull_request_target runs with repository secrets on untrusted fork code.
    assert "pull_request_target" not in workflow.read_text(encoding="utf-8")


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_checkout_does_not_persist_credentials(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    checkouts = text.count("uses: actions/checkout@")

    assert checkouts > 0
    assert text.count("persist-credentials: false") == checkouts


def test_pre_commit_hooks_are_pinned_and_include_gitleaks() -> None:
    text = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    revisions = re.findall(r"^\s*rev:\s*(\S+)", text, flags=re.MULTILINE)

    assert revisions
    assert all(FULL_SHA.fullmatch(rev) for rev in revisions)
    assert "id: gitleaks" in text
    assert "id: detect-private-key" in text


def test_dependabot_watches_python_and_actions() -> None:
    text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")

    assert "package-ecosystem: pip" in text
    assert "package-ecosystem: github-actions" in text


# --- Hidden characters (Trojan Source) ---------------------------------------

_TEXT_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml", ".cfg", ".txt"}
_SKIPPED_FOLDERS = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".ruff_cache",
                    ".pytest_cache", "build", "dist", "node_modules"}  # fmt: skip


def _text_files() -> list[Path]:
    """Every text file of the project itself, without tool caches or environments."""
    files = []
    for path in ROOT.rglob("*"):
        parts = set(path.relative_to(ROOT).parts)
        if parts & _SKIPPED_FOLDERS or any(part.endswith(".egg-info") for part in parts):
            continue
        if path.is_file() and (path.suffix in _TEXT_SUFFIXES or path.name == ".gitignore"):
            files.append(path)
    return files


def test_no_file_hides_or_reorders_text() -> None:
    # Invisible and right-to-left control characters can make code read
    # differently from how it runs. Tests write them as escapes instead.
    files = _text_files()
    assert len(files) > 20
    for path in files:
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            for character in line:
                category = unicodedata.category(character)
                assert category not in {"Cf", "Cc", "Co", "Cs"} or character == "\t", (
                    f"{path.relative_to(ROOT)} line {number} has U+{ord(character):04X}"
                )
