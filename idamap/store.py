"""SQLite storage. One file holds every database/session/call ever recorded.

Addresses are kept twice: as canonical hex text (for display / API) and as a
signed 64-bit integer (``*_i`` columns) so SQLite can index and range-query
them. Kernel-style addresses >= 2**63 wrap to negative numbers; ordering is
still correct within one half of the address space, which is all a single
binary ever uses.
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 1

# Coverage flags stored in functions.flags (bitwise OR of everything that
# happened to the function).
F_SEEN = 1 << 0          # surfaced in a focused result (callees list, xref hit, ...)
F_DISASM = 1 << 1        # disassembly viewed
F_DECOMP = 1 << 2        # Hex-Rays pseudocode viewed
F_XREF = 1 << 3          # xrefs / callers / callees / callgraph queried on it
F_CFG = 1 << 4           # basic blocks viewed
F_DATA = 1 << 5          # raw bytes / values read inside it
F_RENAMED = 1 << 6
F_COMMENTED = 1 << 7
F_TYPED = 1 << 8         # types / stack vars applied
F_PATCHED = 1 << 9
F_FRAME = 1 << 10        # stack frame / type inference viewed
F_LUMINA = 1 << 11       # lumina metadata applied

FLAG_NAMES = {
    F_SEEN: "seen", F_DISASM: "disasm", F_DECOMP: "decompiled", F_XREF: "xrefs",
    F_CFG: "cfg", F_DATA: "data", F_RENAMED: "renamed", F_COMMENTED: "commented",
    F_TYPED: "typed", F_PATCHED: "patched", F_FRAME: "frame", F_LUMINA: "lumina",
}

ANNOTATED = F_RENAMED | F_COMMENTED | F_TYPED | F_PATCHED | F_LUMINA

# Stages, lowest to highest. A function's stage is the highest one reached.
STAGES = ["unseen", "seen", "explored", "disassembled", "decompiled", "annotated"]


def stage_of(flags: int) -> str:
    if flags & ANNOTATED:
        return "annotated"
    if flags & F_DECOMP:
        return "decompiled"
    if flags & (F_DISASM | F_CFG | F_FRAME | F_DATA):
        return "disassembled"
    if flags & F_XREF:
        return "explored"
    if flags & F_SEEN:
        return "seen"
    return "unseen"


def flag_list(flags: int) -> list[str]:
    return [name for bit, name in FLAG_NAMES.items() if flags & bit]


def to_i(addr: int) -> int:
    """Unsigned 64-bit address -> signed value storable in SQLite."""
    addr &= (1 << 64) - 1
    return addr - (1 << 64) if addr >= (1 << 63) else addr


def from_i(v: int) -> int:
    return v + (1 << 64) if v < 0 else v


def hexa(addr: int) -> str:
    return "0x%x" % (addr & ((1 << 64) - 1))


def home() -> Path:
    return Path(os.environ.get("IDAMAP_HOME") or Path.home() / ".idamap")


def db_path() -> Path:
    return home() / "idamap.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);

CREATE TABLE IF NOT EXISTS databases (
    id INTEGER PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,          -- .i64 path (or input path for dsc)
    name TEXT,                         -- short display name
    label TEXT,                        -- user-provided label
    idb_path TEXT,
    input_path TEXT,
    sha256 TEXT,
    md5 TEXT,
    processor TEXT,
    bits INTEGER,
    file_type TEXT,
    min_ea TEXT,
    max_ea TEXT,
    func_total INTEGER,                -- function count reported by IDA
    map_imported_at REAL,              -- full export imported (all funcs + edges)
    created_at REAL,
    last_seen REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,               -- Claude Code session_id
    cwd TEXT,
    transcript_path TEXT,
    db_id INTEGER,                     -- database currently open in this session
    started_at REAL,
    last_seen REAL
);

-- ida-mcp --workspace mode: every call carries a database_id allocated by open_idb/open_dsc
CREATE TABLE IF NOT EXISTS workspace_ids (
    ws_id TEXT PRIMARY KEY,
    db_id INTEGER
);

CREATE TABLE IF NOT EXISTS prompts (
    id TEXT PRIMARY KEY,               -- Claude Code prompt_id
    session_id TEXT,
    ts REAL,
    text TEXT
);

CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY,
    tool_use_id TEXT UNIQUE,
    session_id TEXT,
    prompt_id TEXT,
    db_id INTEGER,
    tool TEXT,
    category TEXT,
    input TEXT,
    output TEXT,
    output_size INTEGER,
    status TEXT,                       -- running | ok | error
    error TEXT,
    started_at REAL,
    ended_at REAL,
    duration_ms INTEGER,
    intent TEXT,                       -- assistant text right before the call
    target TEXT,                       -- human readable target summary
    target_func_i INTEGER,             -- primary function targeted (if any)
    updated_at REAL
);
CREATE INDEX IF NOT EXISTS calls_db ON calls(db_id, id);
CREATE INDEX IF NOT EXISTS calls_upd ON calls(updated_at);

CREATE TABLE IF NOT EXISTS functions (
    db_id INTEGER NOT NULL,
    start_i INTEGER NOT NULL,
    start TEXT NOT NULL,
    name TEXT,
    orig_name TEXT,
    size INTEGER,                      -- NULL = stub (start known, extent unknown)
    flags INTEGER DEFAULT 0,
    touch_count INTEGER DEFAULT 0,
    first_touched REAL,
    last_touched REAL,
    human_status TEXT,
    note TEXT,
    note_updated REAL,
    updated_at REAL,
    PRIMARY KEY (db_id, start_i)
);
CREATE INDEX IF NOT EXISTS functions_upd ON functions(db_id, updated_at);

CREATE TABLE IF NOT EXISTS touches (
    id INTEGER PRIMARY KEY,
    call_id INTEGER,
    db_id INTEGER,
    func_i INTEGER,                    -- containing function (NULL = unresolved)
    addr TEXT,
    addr_i INTEGER,
    kind TEXT,                         -- decompile, disasm, xref, rename, ...
    role TEXT,                         -- target | result
    detail TEXT,
    ts REAL
);
CREATE INDEX IF NOT EXISTS touches_func ON touches(db_id, func_i);
CREATE INDEX IF NOT EXISTS touches_call ON touches(call_id);

CREATE TABLE IF NOT EXISTS edges (
    db_id INTEGER, src_i INTEGER, dst_i INTEGER, src TEXT, dst TEXT,
    source TEXT,                       -- which tool taught us this edge
    PRIMARY KEY (db_id, src_i, dst_i)
);

CREATE TABLE IF NOT EXISTS renames (
    id INTEGER PRIMARY KEY, db_id INTEGER, addr TEXT, addr_i INTEGER,
    old_name TEXT, new_name TEXT, call_id INTEGER, ts REAL
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY, db_id INTEGER, addr TEXT, addr_i INTEGER,
    func_i INTEGER, text TEXT, repeatable INTEGER, call_id INTEGER, ts REAL
);

CREATE TABLE IF NOT EXISTS segments (
    db_id INTEGER, name TEXT, start TEXT, end TEXT, start_i INTEGER, end_i INTEGER,
    perms TEXT, type TEXT,
    PRIMARY KEY (db_id, start_i)
);
"""


def connect(path: Path | None = None) -> sqlite3.Connection:
    path = path or db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
    return conn


def now() -> float:
    return time.time()
