"""Apply Claude Code hook events to the store."""

from __future__ import annotations

import json
import os
import sqlite3

from . import parse as P
from . import store as S
from . import transcript as T

MAX_OUTPUT = 512 * 1024
MAX_RESULTS_PER_CALL = 2000

KIND_FLAG = {kind: flag for kind, flag in P.TARGET_KIND.values()}


# --------------------------------------------------------------------------
# Databases & sessions
# --------------------------------------------------------------------------

def _db_name(key: str) -> str:
    base = os.path.basename(key.rstrip("/")) or key
    for ext in (".i64", ".idb"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base


def upsert_database(conn: sqlite3.Connection, key: str, meta: dict | None = None) -> int:
    ts = S.now()
    row = conn.execute("SELECT id FROM databases WHERE key=?", (key,)).fetchone()
    if row:
        db_id = row["id"]
        conn.execute("UPDATE databases SET last_seen=? WHERE id=?", (ts, db_id))
    else:
        db_id = conn.execute(
            "INSERT INTO databases(key, name, created_at, last_seen) VALUES (?,?,?,?)",
            (key, _db_name(key), ts, ts)).lastrowid
    if meta:
        update_db_meta(conn, db_id, meta)
    return db_id


def update_db_meta(conn, db_id: int, meta: dict) -> None:
    cols = ["idb_path", "input_path", "sha256", "md5", "processor", "bits", "file_type",
            "min_ea", "max_ea", "func_total"]
    sets, vals = [], []
    for c in cols:
        v = meta.get(c)
        if v not in (None, ""):
            sets.append(f"{c}=?")
            vals.append(v)
    if sets:
        conn.execute(f"UPDATE databases SET {', '.join(sets)} WHERE id=?", (*vals, db_id))


def _touch_session(conn, payload: dict) -> dict:
    sid = payload.get("session_id") or "unknown"
    ts = S.now()
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    harness = payload.get("harness") or ("claude-code" if payload.get("hook_event_name") else None)
    source = payload.get("source") or ("hook" if payload.get("hook_event_name") else None)
    if not row:
        conn.execute(
            "INSERT INTO sessions(id, harness, source, cwd, transcript_path, started_at, last_seen) VALUES (?,?,?,?,?,?,?)",
            (sid, harness, source, payload.get("cwd"), payload.get("transcript_path"), ts, ts))
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    else:
        conn.execute("UPDATE sessions SET last_seen=?, transcript_path=COALESCE(?, transcript_path), "
                     "harness=COALESCE(?, harness), source=COALESCE(?, source) WHERE id=?",
                     (ts, payload.get("transcript_path"), harness, source, sid))
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    return dict(row)


def _session_db(conn, session: dict, inp: dict | None = None) -> int:
    ws = (inp or {}).get("database_id")
    if ws:
        row = conn.execute("SELECT db_id FROM workspace_ids WHERE ws_id=?", (str(ws),)).fetchone()
        if row:
            return row["db_id"]
    if session.get("db_id"):
        return session["db_id"]
    row = conn.execute("SELECT id FROM databases ORDER BY last_seen DESC LIMIT 1").fetchone()
    if row:
        db_id = row["id"]
    else:
        db_id = upsert_database(conn, "unknown")
    conn.execute("UPDATE sessions SET db_id=? WHERE id=?", (db_id, session["id"]))
    return db_id


# --------------------------------------------------------------------------
# Function helpers
# --------------------------------------------------------------------------

def containing_function(conn, db_id: int, addr: int) -> int | None:
    """start_i of the function containing addr, or None."""
    ai = S.to_i(addr)
    row = conn.execute(
        "SELECT start_i, size FROM functions WHERE db_id=? AND start_i<=? ORDER BY start_i DESC LIMIT 1",
        (db_id, ai)).fetchone()
    if not row:
        return None
    if row["size"] is None:
        return row["start_i"] if row["start_i"] == ai else None
    return row["start_i"] if ai < row["start_i"] + max(row["size"], 1) else None


def function_by_name(conn, db_id: int, name: str) -> int | None:
    variants = [name, "_" + name, name.lstrip("_")]
    row = conn.execute(
        "SELECT start_i FROM functions WHERE db_id=? AND name IN (?,?,?) LIMIT 1",
        (db_id, *variants)).fetchone()
    return row["start_i"] if row else None


def upsert_functions(conn, db_id: int, recs: list[dict], ts: float) -> None:
    if not recs:
        return
    conn.executemany(
        """INSERT INTO functions(db_id, start_i, start, name, orig_name, size, flags, touch_count, updated_at)
           VALUES (?,?,?,?,?,?,0,0,?)
           ON CONFLICT(db_id, start_i) DO UPDATE SET
             name=COALESCE(excluded.name, functions.name),
             orig_name=COALESCE(functions.orig_name, excluded.orig_name),
             size=COALESCE(excluded.size, functions.size),
             updated_at=CASE WHEN functions.name IS NOT excluded.name OR functions.size IS NOT excluded.size
                             THEN excluded.updated_at ELSE functions.updated_at END""",
        [(db_id, S.to_i(r["start"]), S.hexa(r["start"]), r.get("name"), r.get("name"),
          r.get("size"), ts) for r in recs])


def ensure_stub(conn, db_id: int, addr: int, name: str | None, ts: float) -> int:
    ai = S.to_i(addr)
    conn.execute(
        """INSERT INTO functions(db_id, start_i, start, name, orig_name, size, flags, touch_count, updated_at)
           VALUES (?,?,?,?,?,NULL,0,0,?) ON CONFLICT(db_id, start_i) DO NOTHING""",
        (db_id, ai, S.hexa(addr), name, name, ts))
    return ai


def mark(conn, db_id: int, func_i: int, flag: int, ts: float, count: bool = True) -> None:
    """OR a coverage flag in. ``count`` = the function was a call's target (not
    merely listed in a result): only then do touch_count / first/last_touched move."""
    if count:
        conn.execute(
            """UPDATE functions SET flags = flags | ?, touch_count = touch_count + 1,
                   first_touched = COALESCE(first_touched, ?), last_touched = ?, updated_at = ?
               WHERE db_id=? AND start_i=?""",
            (flag, ts, ts, ts, db_id, func_i))
    else:
        conn.execute(
            "UPDATE functions SET flags = flags | ?, updated_at = ? WHERE db_id=? AND start_i=? AND flags & ? = 0",
            (flag, ts, db_id, func_i, flag))


def merge_stubs(conn, db_id: int, ts: float) -> None:
    """Fold stub functions (unknown size) that turned out to live inside a real function."""
    stubs = conn.execute(
        "SELECT start_i, flags, touch_count, first_touched, last_touched, human_status, note "
        "FROM functions WHERE db_id=? AND size IS NULL", (db_id,)).fetchall()
    for st in stubs:
        row = conn.execute(
            "SELECT start_i, size FROM functions WHERE db_id=? AND start_i<? AND size IS NOT NULL "
            "ORDER BY start_i DESC LIMIT 1", (db_id, st["start_i"])).fetchone()
        if not row or st["start_i"] >= row["start_i"] + max(row["size"], 1):
            continue
        real = row["start_i"]
        conn.execute("UPDATE touches SET func_i=? WHERE db_id=? AND func_i=?", (real, db_id, st["start_i"]))
        conn.execute("UPDATE comments SET func_i=? WHERE db_id=? AND func_i=?", (real, db_id, st["start_i"]))
        conn.execute("UPDATE calls SET target_func_i=? WHERE db_id=? AND target_func_i=?", (real, db_id, st["start_i"]))
        for col in ("src_i", "dst_i"):
            conn.execute(f"UPDATE OR IGNORE edges SET {col}=? WHERE db_id=? AND {col}=?", (real, db_id, st["start_i"]))
            conn.execute(f"DELETE FROM edges WHERE db_id=? AND {col}=?", (db_id, st["start_i"]))
        conn.execute(
            """UPDATE functions SET flags = flags | ?, touch_count = touch_count + ?,
                   first_touched = MIN(COALESCE(first_touched, ?), ?),
                   last_touched = MAX(COALESCE(last_touched, 0), ?),
                   human_status = COALESCE(human_status, ?), note = COALESCE(note, ?), updated_at=?
               WHERE db_id=? AND start_i=?""",
            (st["flags"], st["touch_count"], st["first_touched"] or ts, st["first_touched"] or ts,
             st["last_touched"] or 0, st["human_status"], st["note"], ts, db_id, real))
        conn.execute("DELETE FROM functions WHERE db_id=? AND start_i=?", (db_id, st["start_i"]))


def reresolve(conn, db_id: int, ts: float, limit: int = 20000) -> None:
    """Attach previously unresolved touches to functions learned later."""
    rows = conn.execute(
        "SELECT id, addr_i, kind, role FROM touches WHERE db_id=? AND func_i IS NULL AND addr_i IS NOT NULL LIMIT ?",
        (db_id, limit)).fetchall()
    for r in rows:
        fi = containing_function(conn, db_id, S.from_i(r["addr_i"]))
        if fi is None:
            continue
        conn.execute("UPDATE touches SET func_i=? WHERE id=?", (fi, r["id"]))
        flag = S.F_SEEN if r["role"] == "result" else KIND_FLAG.get(r["kind"], 0)
        if flag:
            mark(conn, db_id, fi, flag, ts, count=r["role"] == "target")


def add_edges(conn, db_id: int, edges: list[tuple[int, int]], source: str) -> None:
    rows = []
    for a, b in edges:
        fa = containing_function(conn, db_id, a)
        fb = containing_function(conn, db_id, b)
        if fa is None or fb is None:
            continue
        rows.append((db_id, fa, fb, S.hexa(S.from_i(fa)), S.hexa(S.from_i(fb)), source))
    conn.executemany("INSERT OR IGNORE INTO edges(db_id, src_i, dst_i, src, dst, source) VALUES (?,?,?,?,?,?)", rows)


# --------------------------------------------------------------------------
# Full-map import (produced by ida_scripts/export_map.py)
# --------------------------------------------------------------------------

def import_export(conn, path: str, db_id: int | None = None) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    ts = S.now()
    key = data.get("idb_path") or data.get("input_path") or path
    if db_id is None:
        row = conn.execute("SELECT id FROM databases WHERE key=? OR (sha256 IS NOT NULL AND sha256=?)",
                           (key, data.get("sha256"))).fetchone()
        db_id = row["id"] if row else upsert_database(conn, key)
    funcs = data.get("functions") or []
    update_db_meta(conn, db_id, {
        "idb_path": data.get("idb_path"), "input_path": data.get("input_path"),
        "sha256": data.get("sha256"), "md5": data.get("md5"), "processor": data.get("processor"),
        "bits": data.get("bits"), "file_type": data.get("file_type"),
        "min_ea": data.get("min_ea"), "max_ea": data.get("max_ea"), "func_total": len(funcs),
    })
    conn.execute("BEGIN")
    try:
        upsert_functions(conn, db_id, [
            {"start": int(f[0]), "size": max(int(f[1]) - int(f[0]), 1), "name": f[2]} for f in funcs], ts)
        # v2 export rows: [start, end, name, demangled, is_lib]
        conn.executemany("UPDATE functions SET demangled=?, is_lib=? WHERE db_id=? AND start_i=?",
                         [(f[3], f[4], db_id, S.to_i(int(f[0]))) for f in funcs if len(f) >= 5])
        refs = data.get("refs") or {}
        if refs:
            conn.execute("DELETE FROM func_refs WHERE db_id=?", (db_id,))
            conn.executemany(
                "INSERT OR IGNORE INTO func_refs(db_id, func_i, kind, value) VALUES (?,?,?,?)",
                [(db_id, S.to_i(int(f)), kind, value) for f, items in refs.items() for kind, value in items])
        _store_segments(conn, db_id, [
            {"name": s.get("name"), "start": int(s["start"]), "end": int(s["end"]),
             "perms": s.get("perms"), "type": s.get("type")} for s in data.get("segments") or []])
        conn.executemany(
            "INSERT OR IGNORE INTO edges(db_id, src_i, dst_i, src, dst, source) VALUES (?,?,?,?,?,'export')",
            [(db_id, S.to_i(int(a)), S.to_i(int(b)), S.hexa(int(a)), S.hexa(int(b)))
             for a, b in data.get("edges") or []])
        merge_stubs(conn, db_id, ts)
        reresolve(conn, db_id, ts, limit=200000)
        conn.execute("UPDATE databases SET map_imported_at=?, last_seen=? WHERE id=?", (ts, ts, db_id))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return {"db_id": db_id, "functions": len(funcs), "edges": len(data.get("edges") or []),
            "refs": sum(len(v) for v in (data.get("refs") or {}).values())}


def _store_segments(conn, db_id: int, segs: list[dict]) -> None:
    if not segs:
        return
    conn.execute("DELETE FROM segments WHERE db_id=?", (db_id,))
    conn.executemany(
        "INSERT OR REPLACE INTO segments(db_id, name, start, end, start_i, end_i, perms, type) VALUES (?,?,?,?,?,?,?,?)",
        [(db_id, s.get("name"), S.hexa(s["start"]), S.hexa(s["end"] or s["start"]),
          S.to_i(s["start"]), S.to_i(s["end"] or s["start"]), s.get("perms"), s.get("type")) for s in segs])


# --------------------------------------------------------------------------
# Hook events
# --------------------------------------------------------------------------

def handle(conn: sqlite3.Connection, payload: dict) -> None:
    event = payload.get("hook_event_name")
    tool_name = payload.get("tool_name") or ""
    if not tool_name.startswith("mcp__") or "ida" not in tool_name.split("__")[1]:
        return
    if event == "PreToolUse":
        on_pre(conn, payload)
    elif event == "PostToolUse":
        on_post(conn, payload, ok=True)
    elif event == "PostToolUseFailure":
        on_post(conn, payload, ok=False)


def _resolve_target(conn, db_id: int, t: P.Target) -> int | None:
    if t.addr is not None:
        return containing_function(conn, db_id, t.addr)
    if t.name:
        return function_by_name(conn, db_id, t.name)
    return None


def _ensure_prompt(conn, payload: dict) -> None:
    pid = payload.get("prompt_id")
    if not pid or conn.execute("SELECT 1 FROM prompts WHERE id=?", (pid,)).fetchone():
        return
    text = T.prompt_text(payload.get("transcript_path"), pid)
    conn.execute("INSERT OR IGNORE INTO prompts(id, session_id, ts, text) VALUES (?,?,?,?)",
                 (pid, payload.get("session_id"), S.now(), text))


DEDUP_WINDOW = 10.0


def _hook_duplicate(conn, tool: str, inp: dict, ts: float) -> int | None:
    """A hook-recorded call for the same tool+arguments, not yet claimed by a proxy.

    Claude Code runs PreToolUse synchronously before it sends the request, so
    when hooks and a proxy observe the same Claude Code session the hook row
    always exists by the time the proxy sees the request."""
    rows = conn.execute(
        """SELECT c.id, c.input FROM calls c JOIN sessions s ON s.id=c.session_id
           WHERE c.tool=? AND c.started_at>? AND s.source='hook'
             AND c.id NOT IN (SELECT call_id FROM call_aliases) ORDER BY c.id DESC LIMIT 20""",
        (tool, ts - DEDUP_WINDOW)).fetchall()
    for r in rows:
        try:
            if json.loads(r["input"] or "{}") == inp:
                return r["id"]
        except ValueError:
            continue
    return None


def on_pre(conn, payload: dict) -> int | None:
    ts = S.now()
    if str(payload.get("source", "")).startswith("proxy"):
        dup = None
        if payload.get("host_tool_use_id"):  # exact: Claude Code sends its tool_use id in _meta
            r = conn.execute("SELECT id FROM calls WHERE tool_use_id=?", (payload["host_tool_use_id"],)).fetchone()
            dup = r["id"] if r else None
        if dup is None:
            dup = _hook_duplicate(conn, P.short_tool(payload["tool_name"]), payload.get("tool_input") or {}, ts)
        if dup is not None:
            conn.execute("INSERT OR IGNORE INTO call_aliases(alias, call_id) VALUES (?,?)",
                         (payload.get("tool_use_id"), dup))
            return None
    session = _touch_session(conn, payload)
    tool = P.short_tool(payload["tool_name"])
    inp = payload.get("tool_input") or {}
    # open_idb/open_dsc decide their database in PostToolUse; don't invent one here
    opening = tool in ("open_idb", "open_dsc")
    db_id = None if opening and not session.get("db_id") else _session_db(conn, session, inp)
    _ensure_prompt(conn, payload)
    intent = T.intent_for(payload.get("transcript_path"), payload.get("tool_use_id"))
    targets = P.input_targets(tool, inp) if db_id is not None else []
    tf = next((fi for fi in (_resolve_target(conn, db_id, t) for t in targets) if fi is not None), None)
    cur = conn.execute(
        """INSERT INTO calls(tool_use_id, session_id, prompt_id, harness, db_id, tool, category, input, status,
                             started_at, intent, target, target_func_i, updated_at)
           VALUES (?,?,?,?,?,?,?,?,'running',?,?,?,?,?)
           ON CONFLICT(tool_use_id) DO NOTHING""",
        (payload.get("tool_use_id"), session["id"], payload.get("prompt_id"), session.get("harness"), db_id, tool,
         P.category(tool), json.dumps(inp), ts, intent, P.describe_target(tool, inp), tf, ts))
    return cur.lastrowid


def on_post(conn, payload: dict, ok: bool) -> None:
    ts = S.now()
    tool = P.short_tool(payload["tool_name"])
    inp = payload.get("tool_input") or {}
    tuid = payload.get("tool_use_id")
    if tuid and conn.execute("SELECT 1 FROM call_aliases WHERE alias=?", (tuid,)).fetchone():
        return  # the hook records this call
    row = conn.execute("SELECT * FROM calls WHERE tool_use_id=?", (tuid,)).fetchone() if tuid else None
    if row is None:  # PreToolUse missed (e.g. hooks installed mid-call)
        on_pre(conn, payload)
        row = conn.execute("SELECT * FROM calls WHERE tool_use_id=?", (tuid,)).fetchone()
        if row is None:
            return
    session = _touch_session(conn, payload)
    call_id, db_id = row["id"], row["db_id"]
    if db_id is None and not (ok and tool in ("open_idb", "open_dsc")):
        db_id = _session_db(conn, session, inp)
    text = P.response_text(payload.get("tool_response")) if ok else ""
    error = None if ok else str(payload.get("error") or "error")[:4000]
    dur = payload.get("duration_ms")
    started = row["started_at"] or ts

    conn.execute("BEGIN")
    try:
        facts = P.extract(tool, inp, text, ok=ok)

        # database switching / metadata
        if ok and tool in ("open_idb", "open_dsc"):
            m = facts.db_meta
            key = m.get("idb_path") or m.get("input_path") or "unknown"
            if tool == "open_dsc" and m.get("module"):
                key = f"{m.get('input_path')}::{m.get('module')}"
            db_id = upsert_database(conn, key, m)
            conn.execute("UPDATE sessions SET db_id=? WHERE id=?", (db_id, session["id"]))
            if m.get("workspace_id"):
                conn.execute("INSERT OR REPLACE INTO workspace_ids(ws_id, db_id) VALUES (?,?)",
                             (str(m["workspace_id"]), db_id))
        elif facts.db_meta:
            update_db_meta(conn, db_id, facts.db_meta)
        conn.execute("UPDATE databases SET last_seen=? WHERE id=?", (ts, db_id))

        if facts.segments:
            _store_segments(conn, db_id, facts.segments)
        if facts.functions:
            upsert_functions(conn, db_id, facts.functions, ts)
            merge_stubs(conn, db_id, ts)

        # names Hex-Rays printed for functions we only know as stubs
        for a, n in facts.stub_names.items():
            conn.execute("UPDATE functions SET name=?, orig_name=COALESCE(orig_name, ?), updated_at=? "
                         "WHERE db_id=? AND start_i=? AND name IS NULL", (n, n, ts, db_id, S.to_i(a)))

        # renames first, so old names are captured before the target touch
        for addr, cur_name, new in facts.renames:
            a = addr
            if a is None and cur_name:
                fi = function_by_name(conn, db_id, cur_name)
                a = S.from_i(fi) if fi is not None else None
            old = cur_name
            if a is not None:
                r = conn.execute("SELECT name FROM functions WHERE db_id=? AND start_i=?",
                                 (db_id, S.to_i(a))).fetchone()
                if r:
                    old = r["name"] or old
                    conn.execute("UPDATE functions SET orig_name=COALESCE(orig_name, ?), name=?, updated_at=? "
                                 "WHERE db_id=? AND start_i=?", (old, new, ts, db_id, S.to_i(a)))
            conn.execute("INSERT INTO renames(db_id, addr, addr_i, old_name, new_name, call_id, ts) VALUES (?,?,?,?,?,?,?)",
                         (db_id, S.hexa(a) if a is not None else None, S.to_i(a) if a is not None else None,
                          old, new, call_id, ts))

        primary = None
        if ok and facts.kind:
            for t in facts.targets:
                if not t.ok:
                    continue
                fi = _resolve_target(conn, db_id, t)
                if fi is None and t.addr is not None and facts.func_start_hint:
                    fi = ensure_stub(conn, db_id, t.addr, facts.stub_names.get(t.addr), ts)
                addr = t.addr if t.addr is not None else (S.from_i(fi) if fi is not None else None)
                conn.execute(
                    "INSERT INTO touches(call_id, db_id, func_i, addr, addr_i, kind, role, detail, ts) VALUES (?,?,?,?,?,?,?,?,?)",
                    (call_id, db_id, fi, S.hexa(addr) if addr is not None else t.name,
                     S.to_i(addr) if addr is not None else None, facts.kind, "target", t.detail, ts))
                if fi is not None:
                    primary = primary if primary is not None else fi
                    if facts.flag:
                        mark(conn, db_id, fi, facts.flag, ts)

        for addr, cur_name, text_c, rep in facts.comments:
            a = addr
            if a is None and cur_name:
                fi = function_by_name(conn, db_id, cur_name)
                a = S.from_i(fi) if fi is not None else None
            fi = containing_function(conn, db_id, a) if a is not None else None
            conn.execute("INSERT INTO comments(db_id, addr, addr_i, func_i, text, repeatable, call_id, ts) VALUES (?,?,?,?,?,?,?,?)",
                         (db_id, S.hexa(a) if a is not None else cur_name, S.to_i(a) if a is not None else None,
                          fi, text_c, int(rep), call_id, ts))

        seen = set()
        for addr, kind, detail in facts.results[:MAX_RESULTS_PER_CALL]:
            fi = containing_function(conn, db_id, addr)
            k = (fi if fi is not None else ("a", addr), kind, detail)
            if k in seen:
                continue
            seen.add(k)
            conn.execute(
                "INSERT INTO touches(call_id, db_id, func_i, addr, addr_i, kind, role, detail, ts) VALUES (?,?,?,?,?,?,'result',?,?)",
                (call_id, db_id, fi, S.hexa(addr), S.to_i(addr), kind, detail, ts))
            if fi is not None:
                mark(conn, db_id, fi, S.F_SEEN, ts, count=False)

        if facts.edges:
            add_edges(conn, db_id, facts.edges, tool)
        if facts.functions or facts.stub_names:
            reresolve(conn, db_id, ts)

        stored = text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + f"\n… [truncated, {len(text)} bytes total]"
        conn.execute(
            """UPDATE calls SET db_id=?, output=?, output_size=?, status=?, error=?, ended_at=?, duration_ms=?,
                   target_func_i=COALESCE(?, target_func_i), updated_at=?,
                   intent=COALESCE(?, intent) WHERE id=?""",
            (db_id, stored, len(text), "ok" if ok else "error", error, ts,
             dur if isinstance(dur, int) else int((ts - started) * 1000), primary, ts,
             T.intent_for(payload.get("transcript_path"), tuid), call_id))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    if facts.export_file and os.path.exists(facts.export_file):
        import_export(conn, facts.export_file, db_id)
