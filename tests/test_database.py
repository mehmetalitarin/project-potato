"""Tests for the local database (T-DATA-2, T-DATA-5, R9)."""

import ast
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path

import pytest

import potato.storage.database as database_module
from potato.storage.database import (
    APPLICATION_ID,
    DATABASE_FILE_NAME,
    MAX_VALUE_BYTES,
    SCHEMA_VERSION,
    Database,
    DatabaseError,
    Holding,
    default_database_path,
)


@pytest.fixture(autouse=True)
def usual_umask() -> Iterator[None]:
    """Run each test with a common umask, so results do not depend on the machine."""
    previous = os.umask(0o022)
    yield
    os.umask(previous)


@pytest.fixture
def path(tmp_path: Path) -> Path:
    return tmp_path / "potato" / DATABASE_FILE_NAME


@pytest.fixture
def database(path: Path) -> Iterator[Database]:
    with Database(path) as opened:
        yield opened


@contextmanager
def _raw(path: Path) -> Iterator[sqlite3.Connection]:
    """Open the file directly with SQLite, bypassing Potato's checks."""
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        yield connection
    finally:
        connection.close()


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


# --- Creating and reopening -------------------------------------------------


def test_default_path_is_in_application_support() -> None:
    path = default_database_path()
    assert path.parts[-3:] == ("Application Support", "Potato", "potato.db")


def test_new_database_is_owner_only(path: Path) -> None:
    with Database(path):
        pass
    assert _mode(path.parent) == 0o700
    assert _mode(path) == 0o600


def test_new_database_has_current_schema(database: Database) -> None:
    assert database.schema_version == SCHEMA_VERSION
    assert database.holdings() == []


def test_loose_file_permissions_are_tightened(path: Path) -> None:
    path.parent.mkdir(mode=0o700)
    path.touch(mode=0o644)
    path.chmod(0o644)
    with Database(path):
        pass
    assert _mode(path) == 0o600


def test_holdings_survive_reopening(path: Path) -> None:
    with Database(path) as first:
        first.set_holding(Holding("AAPL", Decimal("2.5")))
    with Database(path) as second:
        assert second.holdings() == [Holding("AAPL", Decimal("2.5"))]


def test_journal_file_is_owner_only_even_with_open_umask(database: Database, path: Path) -> None:
    # SQLite gives the journal the database file's permissions, not the
    # umask's. This checks that claim with the loosest umask there is.
    os.umask(0)
    connection = database._connection
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute("INSERT INTO holding VALUES ('AAPL', '1')")
        journal = path.with_name(path.name + "-journal")
        assert journal.exists()
        assert _mode(journal) == 0o600
    finally:
        connection.execute("ROLLBACK")


def test_closing_twice_is_harmless(path: Path) -> None:
    opened = Database(path)
    opened.close()
    opened.close()


def test_closed_database_refuses_use(path: Path) -> None:
    opened = Database(path)
    opened.close()
    with pytest.raises(DatabaseError):
        opened.holdings()
    with pytest.raises(DatabaseError):
        opened.set_holding(Holding("AAPL", Decimal(1)))


# --- Holdings ---------------------------------------------------------------


def test_set_replace_and_remove(database: Database) -> None:
    database.set_holding(Holding("MSFT", Decimal(3)))
    database.set_holding(Holding("AAPL", Decimal("1.5")))
    database.set_holding(Holding("MSFT", Decimal(4)))
    assert database.holdings() == [
        Holding("AAPL", Decimal("1.5")),
        Holding("MSFT", Decimal(4)),
    ]
    assert database.remove_holding("MSFT") is True
    assert database.remove_holding("MSFT") is False
    assert database.holdings() == [Holding("AAPL", Decimal("1.5"))]


def test_quantities_are_exact(database: Database) -> None:
    quantity = Decimal("0.1") + Decimal("0.2")
    database.set_holding(Holding("VWRL", quantity))
    assert database.holdings()[0].quantity == Decimal("0.3")


@pytest.mark.parametrize(
    ("given", "stored"),
    [
        (Decimal("2.50"), "2.5"),
        (Decimal("1E+3"), "1000"),
        (Decimal("0.00000001"), "0.00000001"),
        (Decimal(1_000_000_000), "1000000000"),
    ],
)
def test_quantities_are_stored_as_plain_digits(
    database: Database, path: Path, given: Decimal, stored: str
) -> None:
    database.set_holding(Holding("AAPL", given))
    with _raw(path) as raw:
        assert raw.execute("SELECT quantity FROM holding").fetchall() == [(stored,)]


@pytest.mark.parametrize("symbol", ["A", "AAPL", "BRK.B", "RDS-A", "A1234567.9"])
def test_valid_symbols_are_accepted(symbol: str) -> None:
    assert Holding(symbol, Decimal(1)).symbol == symbol


@pytest.mark.parametrize(
    "symbol",
    [
        "",
        "aapl",
        "1AB",
        ".A",
        "A B",
        "AAPL\n",
        "AAPLXXXXXXX",
        "ÄPPL",
        "A'B",
        "A'; DROP TABLE holding; --",
        "A%",
        "A*",
        b"AAPL",
        None,
        1,
    ],
)
def test_invalid_symbols_are_refused(symbol: object) -> None:
    with pytest.raises(ValueError, match="symbol"):
        Holding(symbol, Decimal(1))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "quantity",
    [
        Decimal(0),
        Decimal(-1),
        Decimal("-0.00000001"),
        Decimal("NaN"),
        Decimal("sNaN"),
        Decimal("Infinity"),
        Decimal(1_000_000_001),
        Decimal("0.000000001"),
        1,
        1.5,
        True,
        "1",
        None,
    ],
)
def test_invalid_quantities_are_refused(quantity: object) -> None:
    with pytest.raises(ValueError, match="quantity"):
        Holding("AAPL", quantity)  # type: ignore[arg-type]


def test_remove_refuses_invalid_symbol(database: Database) -> None:
    with pytest.raises(ValueError, match="symbol"):
        database.remove_holding("x' OR '1'='1")


# --- Crafted text and query safety (T-DATA-5) --------------------------------


def test_schema_refuses_bad_symbols_even_without_python_checks(
    database: Database, path: Path
) -> None:
    # Defence in depth: the table's own rules refuse what Holding refuses.
    with _raw(path) as raw:
        for bad in ["aapl", "A'B", "", "AAPLXXXXXXX", "1A"]:
            with pytest.raises(sqlite3.IntegrityError):
                raw.execute("INSERT INTO holding VALUES (?, '1')", (bad,))
        with pytest.raises(sqlite3.IntegrityError):
            raw.execute("INSERT INTO holding VALUES ('AAPL', NULL)")


@pytest.mark.parametrize("quantity", ["NaN", "-1", "0", "abc", "1e999", "0.000000001"])
def test_tampered_quantity_is_refused_when_read(
    database: Database, path: Path, quantity: str
) -> None:
    with _raw(path) as raw:
        raw.execute("INSERT INTO holding VALUES ('AAPL', ?)", (quantity,))
    with pytest.raises(DatabaseError, match="invalid quantity"):
        database.holdings()


def _module_tree() -> ast.Module:
    source = Path(database_module.__file__).read_text(encoding="utf-8")
    return ast.parse(source)


def test_every_query_is_a_fixed_statement() -> None:
    # Every call to execute() must pass a name, never text built in place.
    calls = [
        node
        for node in ast.walk(_module_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"execute", "executemany", "executescript"}
    ]
    assert calls, "expected the module to run queries"
    for call in calls:
        assert call.func.attr == "execute", "only execute() is used"  # type: ignore[attr-defined]
        assert isinstance(call.args[0], ast.Name), f"line {call.lineno}"


def test_no_text_is_built_at_run_time() -> None:
    # f-strings and % or .format() are not used for SQL anywhere in the file.
    sql_words = ("SELECT", "INSERT", "UPDATE", "DELETE", "PRAGMA", "CREATE", "DROP")
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.JoinedStr):
            text = ast.unparse(node).upper()
            assert not any(word in text for word in sql_words), f"line {node.lineno}"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            assert not isinstance(node.left, ast.Constant), f"line {node.lineno}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr != "format", f"line {node.lineno}"


def test_attaching_other_databases_is_blocked(database: Database, tmp_path: Path) -> None:
    with pytest.raises(sqlite3.OperationalError):
        database._connection.execute("ATTACH DATABASE ? AS other", (str(tmp_path / "x.db"),))


def test_oversized_values_are_refused(database: Database) -> None:
    with pytest.raises(sqlite3.DataError):
        database._connection.execute("SELECT zeroblob(?)", (MAX_VALUE_BYTES + 1,))


@pytest.mark.parametrize(
    ("setting", "expected"),
    [
        ("journal_mode", "delete"),
        ("secure_delete", 1),
        ("foreign_keys", 1),
        ("trusted_schema", 0),
        ("cell_size_check", 1),
    ],
)
def test_safety_settings_are_applied(database: Database, setting: str, expected: object) -> None:
    (value,) = database._connection.execute(f"PRAGMA {setting}").fetchone()
    assert value == expected


def test_application_id_in_the_schema_matches_the_constant() -> None:
    statement = database_module._MIGRATIONS[0][0]
    assert statement == f"PRAGMA application_id = {APPLICATION_ID}"
    assert APPLICATION_ID.to_bytes(4, "big") == b"Pota"


def test_each_migration_records_its_own_version() -> None:
    for number, migration in enumerate(database_module._MIGRATIONS, start=1):
        assert migration[-1] == f"PRAGMA user_version = {number}"


# --- Refusing unsafe or foreign files ---------------------------------------


def test_relative_path_is_refused() -> None:
    with pytest.raises(ValueError, match="absolute"):
        Database(Path("potato.db"))


def test_link_to_a_file_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.db"
    target.touch()
    link = tmp_path / "potato.db"
    link.symlink_to(target)
    with pytest.raises(DatabaseError, match="opened safely"):
        Database(link)
    assert target.read_bytes() == b""


def test_linked_folder_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(DatabaseError, match="folder"):
        Database(linked / DATABASE_FILE_NAME)
    assert list(real.iterdir()) == []


def test_folder_in_place_of_the_file_is_refused(path: Path) -> None:
    path.mkdir(parents=True)
    with pytest.raises(DatabaseError):
        Database(path)


def test_named_pipe_is_refused_without_waiting(path: Path) -> None:
    path.parent.mkdir(mode=0o700)
    os.mkfifo(path, 0o600)
    with pytest.raises(DatabaseError, match="not a regular file"):
        Database(path)


def test_folder_of_another_user_is_refused(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path.parent.mkdir(mode=0o700)
    monkeypatch.setattr(os, "getuid", lambda: os.geteuid() + 1)
    with pytest.raises(DatabaseError, match="folder"):
        Database(path)


def test_file_of_another_user_is_refused(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path.parent.mkdir(mode=0o700)
    path.touch(mode=0o600)
    monkeypatch.setattr(database_module, "ensure_private_directory", lambda _: None)
    monkeypatch.setattr(os, "getuid", lambda: os.geteuid() + 1)
    with pytest.raises(DatabaseError, match="another user"):
        Database(path)


def test_file_swapped_while_opening_is_refused(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(database_module, "_create_private_file", lambda _: (0, 0))
    path.parent.mkdir(mode=0o700)
    path.touch(mode=0o600)
    with pytest.raises(DatabaseError, match="replaced"):
        Database(path)


def _make_foreign_database(path: Path, statements: list[str]) -> bytes:
    path.parent.mkdir(mode=0o700, exist_ok=True)
    with _raw(path) as raw:
        for statement in statements:
            raw.execute(statement)
    path.chmod(0o600)
    return path.read_bytes()


@pytest.mark.parametrize(
    "statements",
    [
        ["CREATE TABLE notes (text TEXT)"],
        ["PRAGMA application_id = 12345"],
        ["PRAGMA application_id = 12345", "CREATE TABLE holding (symbol TEXT)"],
    ],
)
def test_another_programs_database_is_refused_untouched(path: Path, statements: list[str]) -> None:
    before = _make_foreign_database(path, statements)
    with pytest.raises(DatabaseError, match="not a Potato database"):
        Database(path)
    assert path.read_bytes() == before


def test_newer_schema_is_refused_untouched(path: Path) -> None:
    before = _make_foreign_database(
        path,
        [f"PRAGMA application_id = {APPLICATION_ID}", "PRAGMA user_version = 999"],
    )
    with pytest.raises(DatabaseError, match="newer version"):
        Database(path)
    assert path.read_bytes() == before


def test_file_that_is_not_a_database_is_refused_untouched(path: Path) -> None:
    path.parent.mkdir(mode=0o700)
    garbage = b"this is not a database at all " * 200
    path.write_bytes(garbage)
    path.chmod(0o600)
    with pytest.raises(DatabaseError, match="cannot be read"):
        Database(path)
    assert path.read_bytes() == garbage


def test_damaged_database_is_refused(path: Path) -> None:
    with Database(path) as opened:
        for number in range(400):
            opened.set_holding(Holding(f"A{number}", Decimal(number + 1)))
    data = bytearray(path.read_bytes())
    page_size = int.from_bytes(data[16:18], "big")
    # Scramble the second page, which holds table data.
    data[page_size : page_size * 2] = bytes(range(256)) * (page_size // 256)
    path.write_bytes(bytes(data))
    with pytest.raises(DatabaseError):
        Database(path)


def test_failed_migration_leaves_nothing_behind(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broken = (
        (
            database_module._MIGRATIONS[0][0],
            "CREATE TABLE holding (symbol TEXT) STRICT",
            "THIS IS NOT SQL",
            "PRAGMA user_version = 1",
        ),
    )
    monkeypatch.setattr(database_module, "_MIGRATIONS", broken)
    with pytest.raises(DatabaseError):
        Database(path)
    with _raw(path) as raw:
        assert raw.execute("PRAGMA user_version").fetchone() == (0,)
        assert raw.execute("SELECT count(*) FROM sqlite_schema").fetchone() == (0,)
    monkeypatch.undo()
    with Database(path) as opened:
        assert opened.schema_version == SCHEMA_VERSION


# --- Checks found missing by the remove-a-check experiment -------------------


def test_new_file_is_created_owner_only_from_the_start(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The file must never exist, even briefly, with looser permissions.
    tightened: list[int] = []
    monkeypatch.setattr(os, "fchmod", lambda descriptor, mode: tightened.append(mode))
    with Database(path):
        pass
    assert tightened == []
    assert _mode(path) == 0o600


def test_sqlite_never_creates_the_file_itself(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # If the checked file vanishes before SQLite opens it, opening fails
    # instead of SQLite creating a new file with default permissions.
    original = database_module._create_private_file

    def create_then_vanish(target: Path) -> tuple[int, int]:
        identity = original(target)
        target.unlink()
        return identity

    monkeypatch.setattr(database_module, "_create_private_file", create_then_vanish)
    with pytest.raises(DatabaseError):
        Database(path)
    assert not path.exists()


def test_failed_integrity_check_is_refused(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(database_module, "_QUICK_CHECK", "SELECT 'page 2 is damaged'")
    with pytest.raises(DatabaseError, match="damaged"):
        Database(path)


def test_wal_mode_left_in_the_file_is_switched_off(path: Path) -> None:
    # WAL mode is stored in the file. Potato switches it back, so no extra
    # files stay next to the database.
    with Database(path):
        pass
    with _raw(path) as raw:
        raw.execute("PRAGMA journal_mode = WAL")
    with Database(path) as opened:
        (mode,) = opened._connection.execute("PRAGMA journal_mode").fetchone()
        assert mode == "delete"
    assert not path.with_name(path.name + "-wal").exists()


def test_failed_write_is_rolled_back(database: Database) -> None:
    insert = "INSERT INTO holding VALUES (?, ?)"
    with pytest.raises(DatabaseError, match="could not be changed"):
        database._write(insert, ("not valid", "1"))
    assert not database._connection.in_transaction
    database.set_holding(Holding("AAPL", Decimal(1)))
    assert len(database.holdings()) == 1


def test_failed_migration_is_rolled_back(database: Database) -> None:
    with pytest.raises(sqlite3.OperationalError):
        database._migrate(0)
    assert not database._connection.in_transaction


def _replace_with_unchecked_table(path: Path, symbol: object, quantity: object) -> None:
    """Simulate a file edited outside Potato: same header, no table rules."""
    with _raw(path) as raw:
        raw.execute("DROP TABLE holding")
        raw.execute("CREATE TABLE holding (symbol, quantity)")
        raw.execute("INSERT INTO holding VALUES (?, ?)", (symbol, quantity))


def test_tampered_symbol_is_refused_when_read(database: Database, path: Path) -> None:
    _replace_with_unchecked_table(path, "x'; DROP TABLE holding; --", "1")
    with pytest.raises(DatabaseError, match="invalid symbol"):
        database.holdings()


def test_tampered_quantity_type_is_refused_when_read(database: Database, path: Path) -> None:
    _replace_with_unchecked_table(path, "AAPL", 5)
    with pytest.raises(DatabaseError, match="not text"):
        database.holdings()


def test_connection_is_closed_when_opening_fails(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[sqlite3.Connection] = []
    original = database_module._connect

    def recording_connect(target: Path) -> sqlite3.Connection:
        connection = original(target)
        opened.append(connection)
        return connection

    monkeypatch.setattr(database_module, "_connect", recording_connect)
    monkeypatch.setattr(database_module, "_QUICK_CHECK", "SELECT 'damaged'")
    with pytest.raises(DatabaseError):
        Database(path)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("SELECT 1")
