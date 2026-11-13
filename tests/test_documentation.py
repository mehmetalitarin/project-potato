"""Tests that keep the security documentation consistent and honest.

These read the Markdown files as text. They cannot prove that a document is
*correct*, but they catch the ways documentation usually decays: a broken
link, an identifier that points at nothing, a defence with no status, and
wording that claims more than the project can deliver.
"""

import re
from pathlib import Path

import pytest

from potato.core.config import Settings, parse_settings

ROOT = Path(__file__).resolve().parent.parent

THREAT_MODEL = ROOT / "docs" / "threat_model.md"
ARCHITECTURE = ROOT / "docs" / "architecture.md"
PERMISSIONS = ROOT / "docs" / "permissions.md"
README = ROOT / "README.md"

DESIGN_DOCUMENTS = [THREAT_MODEL, ARCHITECTURE, PERMISSIONS]
ALL_DOCUMENTS = [README, ROOT / "SECURITY.md", ROOT / "CONTRIBUTING.md", *DESIGN_DOCUMENTS]

THREAT_ID = re.compile(r"T-[A-Z]+-\d+")
GUARANTEE_ID = re.compile(r"\bP\d+\b")
RULE_ID = re.compile(r"\bR\d+\b")
STATUS = re.compile(r"Done|Partly done|Planned \(M\d(, M\d)*\)")
STRIDE = re.compile(r"[STRIDE](, [STRIDE])*")
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")

# The specification forbids ever claiming the application cannot be attacked.
OVERCLAIMS = [
    "completely secure",
    "fully secure",
    "totally secure",
    "100% secure",
    "unhackable",
    "cannot be hacked",
    "can't be hacked",
    "impossible to hack",
    "hack-proof",
    "bulletproof",
    "military-grade",
]


def _name(path: Path) -> str:
    return path.name


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _table_rows(text: str) -> list[list[str]]:
    """Return the cells of every Markdown table row, skipping separator rows."""
    rows = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            continue
        rows.append(cells)
    return rows


def _rows_keyed_by(path: Path, key: re.Pattern[str]) -> dict[str, list[str]]:
    """Return table rows whose first cell is an identifier matching ``key``."""
    rows: dict[str, list[str]] = {}
    for cells in _table_rows(_read(path)):
        if key.fullmatch(cells[0]):
            assert cells[0] not in rows, f"{cells[0]} is defined twice in {path.name}"
            rows[cells[0]] = cells
    return rows


def _heading_anchors(text: str) -> set[str]:
    """Return the anchors GitHub generates for a document's headings."""
    anchors = set()
    for heading in re.findall(r"^#+\s+(.+)$", text, flags=re.MULTILINE):
        slug = re.sub(r"[^\w\- ]", "", heading.strip().lower())
        anchors.add(slug.replace(" ", "-"))
    return anchors


THREATS = _rows_keyed_by(THREAT_MODEL, THREAT_ID)
GUARANTEES = _rows_keyed_by(PERMISSIONS, re.compile(r"P\d+"))
RULES = _rows_keyed_by(ARCHITECTURE, re.compile(r"R\d+"))


# --- Every document -----------------------------------------------------------


@pytest.mark.parametrize("document", ALL_DOCUMENTS, ids=_name)
def test_document_exists_and_starts_with_a_title(document: Path) -> None:
    assert document.is_file(), f"{document.name} is missing"
    assert _read(document).startswith("# ")


@pytest.mark.parametrize("document", ALL_DOCUMENTS, ids=_name)
def test_links_point_at_things_that_exist(document: Path) -> None:
    text = _read(document)

    for target in MARKDOWN_LINK.findall(text):
        if target.startswith(("https://", "http://", "mailto:")):
            continue
        file_part, _, anchor = target.partition("#")
        if not file_part:
            assert anchor in _heading_anchors(text), f"no heading for #{anchor}"
            continue
        linked = (document.parent / file_part).resolve()
        assert linked.is_relative_to(ROOT), f"{target} points outside the repository"
        assert linked.exists(), f"{document.name} links to missing {target}"


@pytest.mark.parametrize("document", ALL_DOCUMENTS, ids=_name)
def test_code_fences_are_closed(document: Path) -> None:
    fences = [line for line in _read(document).splitlines() if line.strip().startswith("```")]

    assert len(fences) % 2 == 0, f"{document.name} has an unclosed code block"


@pytest.mark.parametrize("document", ALL_DOCUMENTS, ids=_name)
def test_document_does_not_overclaim(document: Path) -> None:
    text = _read(document).lower()

    for phrase in OVERCLAIMS:
        assert phrase not in text, f"{document.name} says {phrase!r}"


@pytest.mark.parametrize("document", ALL_DOCUMENTS, ids=_name)
def test_every_identifier_mentioned_is_defined(document: Path) -> None:
    text = _read(document)

    assert set(THREAT_ID.findall(text)) <= set(THREATS)
    assert set(GUARANTEE_ID.findall(text)) <= set(GUARANTEES)
    assert set(RULE_ID.findall(text)) <= set(RULES)


@pytest.mark.parametrize("document", DESIGN_DOCUMENTS, ids=_name)
def test_design_document_says_it_is_a_design(document: Path) -> None:
    # A reader must never mistake a plan for a description of working code.
    assert "**Status: design document.**" in _read(document)


def test_readme_links_to_every_other_document() -> None:
    targets = {(ROOT / target).resolve() for target in MARKDOWN_LINK.findall(_read(README))}

    for document in ALL_DOCUMENTS:
        if document != README:
            assert document in targets, f"README does not link to {document.name}"


# --- Threat model -------------------------------------------------------------


def test_threat_model_defines_threats() -> None:
    assert THREATS


@pytest.mark.parametrize("threat", sorted(THREATS))
def test_threat_row_is_complete(threat: str) -> None:
    cells = THREATS[threat]

    assert len(cells) == 6, f"{threat} needs six columns"
    _, description, stride, defence, status, remains = cells
    assert description
    assert STRIDE.fullmatch(stride), f"{threat} has STRIDE value {stride!r}"
    assert defence
    assert STATUS.fullmatch(status), f"{threat} has status {status!r}"
    assert remains, f"{threat} must state what risk remains"


def test_threat_model_maps_all_fourteen_required_tests() -> None:
    numbered = [cells for cells in _table_rows(_read(THREAT_MODEL)) if cells[0].isdigit()]

    assert [int(cells[0]) for cells in numbered] == list(range(1, 15))
    for cells in numbered:
        assert THREAT_ID.search(cells[2]) or cells[2].startswith("None:")
        assert re.fullmatch(r"M\d", cells[3])


# --- Permissions --------------------------------------------------------------


def test_guarantees_are_numbered_without_gaps() -> None:
    assert list(GUARANTEES) == [f"P{n}" for n in range(1, len(GUARANTEES) + 1)]


@pytest.mark.parametrize("guarantee", sorted(GUARANTEES))
def test_guarantee_names_the_threats_it_answers(guarantee: str) -> None:
    assert THREAT_ID.search(GUARANTEES[guarantee][2])


def test_no_planned_tool_is_sensitive() -> None:
    # Version 1.0 must contain no operation that needs physical approval.
    tools = [
        cells
        for cells in _table_rows(_read(PERMISSIONS))
        if len(cells) == 4 and re.fullmatch(r"`[a-z_]+`", cells[0])
    ]

    assert tools, "expected the planned tools table"
    for name, _, _, risk in tools:
        assert risk in {"Low", "Medium"}, f"{name} has risk {risk!r}"


# --- Architecture -------------------------------------------------------------


def test_rules_are_numbered_without_gaps() -> None:
    assert list(RULES) == [f"R{n}" for n in range(1, len(RULES) + 1)]


@pytest.mark.parametrize("rule", sorted(RULES))
def test_rule_says_how_it_is_enforced_and_its_status(rule: str) -> None:
    cells = RULES[rule]

    assert len(cells) == 4
    assert cells[2], f"{rule} must say how it is enforced"
    assert STATUS.fullmatch(cells[3]), f"{rule} has status {cells[3]!r}"


# --- README -------------------------------------------------------------------


def test_readme_settings_example_is_valid_and_shows_the_real_defaults() -> None:
    examples = re.findall(r"```toml\n(.*?)```", _read(README), flags=re.DOTALL)

    assert len(examples) == 1
    assert parse_settings(examples[0]) == Settings()
