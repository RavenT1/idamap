"""Read-side queries shared by the HTTP API and the report/IDA exporters.

Addresses always leave this module as hex strings: JavaScript numbers cannot
represent 64-bit addresses exactly.
"""

from __future__ import annotations

import json
import time

from . import bundle
from . import parse as P
from . import store as S

HUMAN_STATUSES = ["todo", "in_progress", "reviewed", "interesting", "suspicious", "ignore"]


def _fname(row) -> str:
    return row["name"] or ("sub_%X" % S.from_i(row["start_i"]))


def databases(conn) -> list[dict]:
    out = []
    for d in conn.execute("SELECT * FROM databases ORDER BY last_seen DESC"):
        stats = conn.execute(
            """SELECT count(*) AS known,
                      sum(flags & ? != 0) AS touched,
                      sum(flags & ? != 0) AS decompiled,
                      sum(flags & ? != 0) AS annotated
               FROM functions WHERE db_id=?""",
            (S.F_DISASM | S.F_DECOMP | S.F_CFG | S.F_XREF | S.F_FRAME | S.F_DATA | S.ANNOTATED,
             S.F_DECOMP, S.ANNOTATED, d["id"])).fetchone()
        calls = conn.execute("SELECT count(*) FROM calls WHERE db_id=?", (d["id"],)).fetchone()[0]
        out.append({
            "id": d["id"], "key": d["key"], "name": d["label"] or d["name"], "label": d["label"],
            "processor": d["processor"], "file_type": d["file_type"], "bits": d["bits"],
            "input_path": d["input_path"], "sha256": d["sha256"],
            "func_total": d["func_total"], "known": stats["known"] or 0,
            "touched": stats["touched"] or 0, "decompiled": stats["decompiled"] or 0,
            "annotated": stats["annotated"] or 0, "calls": calls,
            "last_seen": d["last_seen"], "created_at": d["created_at"],
            "map_imported_at": d["map_imported_at"],
        })
    return out


def call_row(r, names: dict | None = None) -> dict:
    d = {
        "id": r["id"], "tool": r["tool"], "category": r["category"], "status": r["status"],
        "db_id": r["db_id"], "session_id": r["session_id"], "prompt_id": r["prompt_id"], "harness": r["harness"],
        "target": r["target"], "intent": r["intent"], "error": r["error"],
        "started_at": r["started_at"], "ended_at": r["ended_at"], "duration_ms": r["duration_ms"],
        "output_size": r["output_size"],
        "func": S.hexa(S.from_i(r["target_func_i"])) if r["target_func_i"] is not None else None,
    }
    if names is not None and r["target_func_i"] is not None:
        d["func_name"] = names.get(r["target_func_i"])
    return d


def _names_for(conn, db_id: int, rows) -> dict:
    ids = {r["target_func_i"] for r in rows if r["target_func_i"] is not None}
    if not ids:
        return {}
    q = ",".join("?" * len(ids))
    return {r["start_i"]: _fname(r) for r in conn.execute(
        f"SELECT start_i, name FROM functions WHERE db_id=? AND start_i IN ({q})", (db_id, *ids))}


def calls(conn, db_id: int | None, before_id: int | None = None, limit: int = 300) -> dict:
    where, args = [], []
    if db_id is not None:
        where.append("db_id=?")
        args.append(db_id)
    if before_id:
        where.append("id<?")
        args.append(before_id)
    sql = "SELECT * FROM calls" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
    rows = conn.execute(sql, (*args, limit)).fetchall()
    names = {}
    for dbid in {r["db_id"] for r in rows}:
        names.update(_names_for(conn, dbid, [r for r in rows if r["db_id"] == dbid]))
    pids = {r["prompt_id"] for r in rows if r["prompt_id"]}
    prompts = {}
    if pids:
        q = ",".join("?" * len(pids))
        prompts = {p["id"]: {"id": p["id"], "text": p["text"], "ts": p["ts"], "session_id": p["session_id"]}
                   for p in conn.execute(f"SELECT * FROM prompts WHERE id IN ({q})", tuple(pids))}
    return {"calls": [call_row(r, names) for r in rows], "prompts": prompts}


def call_detail(conn, call_id: int) -> dict | None:
    r = conn.execute("SELECT * FROM calls WHERE id=?", (call_id,)).fetchone()
    if not r:
        return None
    d = call_row(r, _names_for(conn, r["db_id"], [r]))
    d["input"] = json.loads(r["input"] or "{}")
    d["output"] = r["output"]
    d["touches"] = [dict(t) | {"func": S.hexa(S.from_i(t["func_i"])) if t["func_i"] is not None else None}
                    for t in conn.execute(
                        "SELECT kind, role, addr, detail, func_i FROM touches WHERE call_id=? LIMIT 500", (call_id,))]
    for t in d["touches"]:
        t.pop("func_i", None)
    return d


def changed_calls(conn, since: float) -> list[tuple[float, dict]]:
    """(updated_at, call) for calls written after ``since``."""
    rows = conn.execute("SELECT * FROM calls WHERE updated_at>? ORDER BY id LIMIT 500", (since,)).fetchall()
    names = {}
    for dbid in {r["db_id"] for r in rows}:
        names.update(_names_for(conn, dbid, [r for r in rows if r["db_id"] == dbid]))
    return [(r["updated_at"], call_row(r, names)) for r in rows]


def functions(conn, db_id: int, since: float | None = None) -> dict:
    sql = ("SELECT start_i, name, size, flags, touch_count, last_touched, first_touched, human_status, "
           "orig_name, note IS NOT NULL AND note != '' AS has_note, demangled, "
           "(SELECT summary || char(31) || status || char(31) || COALESCE(name_suggestion, '') FROM annotations a "
           " WHERE a.db_id=functions.db_id "
           " AND a.func_i=functions.start_i AND a.status != 'rejected' ORDER BY a.id DESC LIMIT 1) AS ann "
           "FROM functions WHERE db_id=?")
    args: list = [db_id]
    if since:
        sql += " AND updated_at>?"
        args.append(since)
    sql += " ORDER BY start_i"
    rows = conn.execute(sql, args).fetchall()
    # [start, name, size, flags, touches, last_touched, first_touched, human, orig_name, has_note,
    #  demangled, explanation summary, explanation status]
    out = []
    for r in rows:
        summ, st, sugg = (r["ann"].split("\x1f") + [None, None])[:3] if r["ann"] else (None, None, None)
        out.append([S.hexa(S.from_i(r["start_i"])), _fname(r), r["size"], r["flags"], r["touch_count"],
                    r["last_touched"], r["first_touched"], r["human_status"],
                    r["orig_name"] if r["orig_name"] and r["orig_name"] != r["name"] else None, bool(r["has_note"]),
                    r["demangled"], summ, st, sugg or None])
    return {"now": time.time(), "functions": out}


def function_detail(conn, db_id: int, start: int) -> dict | None:
    si = S.to_i(start)
    f = conn.execute("SELECT * FROM functions WHERE db_id=? AND start_i=?", (db_id, si)).fetchone()
    if not f:
        return None

    def fn(i):
        r = conn.execute("SELECT start_i, name, flags FROM functions WHERE db_id=? AND start_i=?", (db_id, i)).fetchone()
        return {"start": S.hexa(S.from_i(i)), "name": _fname(r) if r else S.hexa(S.from_i(i)),
                "flags": r["flags"] if r else 0}

    hist = conn.execute(
        """SELECT DISTINCT c.* FROM touches t JOIN calls c ON c.id=t.call_id
           WHERE t.db_id=? AND t.func_i=? ORDER BY c.id DESC LIMIT 200""", (db_id, si)).fetchall()
    roles = {}
    for t in conn.execute("SELECT call_id, kind, role, detail FROM touches WHERE db_id=? AND func_i=?", (db_id, si)):
        roles.setdefault(t["call_id"], []).append({"kind": t["kind"], "role": t["role"], "detail": t["detail"]})
    last_decomp = conn.execute(
        """SELECT c.id, c.output, c.tool, c.ended_at, c.input FROM touches t JOIN calls c ON c.id=t.call_id
           WHERE t.db_id=? AND t.func_i=? AND t.role='target' AND t.kind='decompile' AND c.tool='decompile'
             AND c.status='ok' ORDER BY c.id DESC LIMIT 1""", (db_id, si)).fetchone()
    decomp = None
    if last_decomp:
        out = last_decomp["output"] or ""
        j = P.try_json(out)
        if isinstance(j, dict) and isinstance(j.get("results"), list):
            for r in j["results"]:
                if P.parse_addr(r.get("address")) == start and r.get("decompile"):
                    out = r["decompile"]
        decomp = {"call_id": last_decomp["id"], "text": out, "ts": last_decomp["ended_at"]}
    strings = [r["detail"] for r in conn.execute(
        "SELECT DISTINCT detail FROM touches WHERE db_id=? AND func_i=? AND kind='string_ref' LIMIT 50", (db_id, si))]
    refs: dict[str, list] = {}
    for r in conn.execute("SELECT kind, value FROM func_refs WHERE db_id=? AND func_i=? ORDER BY kind, value",
                          (db_id, si)):
        refs.setdefault(r["kind"], []).append(r["value"])
    anns = [dict(a) | {"tags": json.loads(a["tags"] or "[]")} for a in conn.execute(
        "SELECT id, source, summary, name_suggestion, tags, framework, confidence, evidence, status, harness, "
        "created_at, reviewed_at, call_id FROM annotations WHERE db_id=? AND func_i=? ORDER BY id DESC", (db_id, si))]
    frameworks = []
    if refs.get("import"):
        try:
            idx = bundle.Index(bundle.bundle_info(conn, db_id))
            frameworks = [idx.describe(m) for m in idx.modules_in(refs["import"])]
        except Exception:  # noqa: BLE001 — a hint, never a failure
            frameworks = []
    return {
        "bundled_frameworks": frameworks,
        "demangled": f["demangled"], "is_lib": bool(f["is_lib"]), "references": refs, "explanations": anns,
        "start": S.hexa(start), "name": _fname(f), "orig_name": f["orig_name"], "size": f["size"],
        "flags": f["flags"], "flag_names": S.flag_list(f["flags"]), "stage": S.stage_of(f["flags"]),
        "touch_count": f["touch_count"], "first_touched": f["first_touched"], "last_touched": f["last_touched"],
        "human_status": f["human_status"], "note": f["note"], "note_updated": f["note_updated"],
        "callers": [fn(r[0]) for r in conn.execute(
            "SELECT src_i FROM edges WHERE db_id=? AND dst_i=? LIMIT 200", (db_id, si))],
        "callees": [fn(r[0]) for r in conn.execute(
            "SELECT dst_i FROM edges WHERE db_id=? AND src_i=? LIMIT 200", (db_id, si))],
        "renames": [dict(r) for r in conn.execute(
            "SELECT old_name, new_name, ts, call_id FROM renames WHERE db_id=? AND addr_i=? ORDER BY id", (db_id, si))],
        "comments": [dict(r) for r in conn.execute(
            "SELECT addr, text, repeatable, ts, call_id FROM comments WHERE db_id=? AND func_i=? ORDER BY id", (db_id, si))],
        "strings": strings,
        "decompile": decomp,
        "history": [call_row(c) | {"roles": roles.get(c["id"], [])} for c in hist],
    }


def set_human(conn, db_id: int, start: int, status: str | None = None, note: str | None = None,
              set_status: bool = False, set_note: bool = False) -> None:
    ts = time.time()
    si = S.to_i(start)
    conn.execute("""INSERT INTO functions(db_id, start_i, start, flags, touch_count, updated_at)
                    VALUES (?,?,?,0,0,?) ON CONFLICT DO NOTHING""", (db_id, si, S.hexa(start), ts))
    if set_status:
        conn.execute("UPDATE functions SET human_status=?, updated_at=? WHERE db_id=? AND start_i=?",
                     (status or None, ts, db_id, si))
    if set_note:
        conn.execute("UPDATE functions SET note=?, note_updated=?, updated_at=? WHERE db_id=? AND start_i=?",
                     (note, ts, ts, db_id, si))


def graph(conn, db_id: int, mode: str = "touched", limit: int = 1500) -> dict:
    touched = {r[0]: r for r in conn.execute(
        "SELECT start_i, name, size, flags, touch_count, human_status, last_touched FROM functions "
        "WHERE db_id=? AND ((flags & ?) != 0 OR human_status IS NOT NULL) ORDER BY last_touched DESC LIMIT ?",
        (db_id, ~S.F_SEEN, limit)).fetchall()}
    core = set(touched)
    ids = set(core)
    edges = []
    if core:
        # frontier = direct (1-hop) neighbours of the functions actually worked on
        for a, b in conn.execute("SELECT src_i, dst_i FROM edges WHERE db_id=?", (db_id,)):
            if a in core and b in core:
                edges.append((a, b))
            elif mode == "frontier" and (a in core or b in core):
                other = b if a in core else a
                if other in ids or len(ids) < limit:
                    ids.add(other)
                    edges.append((a, b))
    nodes = []
    if ids:
        missing = ids - set(touched)
        extra = {}
        for chunk in _chunks(list(missing), 500):
            q = ",".join("?" * len(chunk))
            for r in conn.execute(f"SELECT start_i, name, size, flags, touch_count, human_status, last_touched "
                                  f"FROM functions WHERE db_id=? AND start_i IN ({q})", (db_id, *chunk)):
                extra[r[0]] = r
        for i in ids:
            r = touched.get(i) or extra.get(i)
            nodes.append({
                "id": S.hexa(S.from_i(i)),
                "name": _fname(r) if r else S.hexa(S.from_i(i)),
                "size": r["size"] if r else None, "flags": r["flags"] if r else 0,
                "touches": r["touch_count"] if r else 0, "human": r["human_status"] if r else None,
                "frontier": i not in touched,
            })
    # exploration trail: order in which functions were first targeted
    trail = []
    seen = set()
    for r in conn.execute(
            "SELECT func_i FROM touches WHERE db_id=? AND role='target' AND kind != 'locate' AND func_i IS NOT NULL ORDER BY id",
            (db_id,)):
        if r[0] not in seen:
            seen.add(r[0])
            trail.append(S.hexa(S.from_i(r[0])))
    return {"nodes": nodes,
            "edges": [[S.hexa(S.from_i(a)), S.hexa(S.from_i(b))] for a, b in edges],
            "trail": trail}


def _chunks(xs, n):
    for i in range(0, len(xs), n):
        yield xs[i:i + n]


def _bundle(conn, db_id: int):
    try:
        return bundle.bundle_info(conn, db_id)
    except Exception:  # noqa: BLE001
        return None


def summary(conn, db_id: int) -> dict:
    d = next((x for x in databases(conn) if x["id"] == db_id), None)
    stages = {s: 0 for s in S.STAGES}
    human = {}
    for r in conn.execute("SELECT flags, human_status FROM functions WHERE db_id=?", (db_id,)):
        stages[S.stage_of(r["flags"])] += 1
        if r["human_status"]:
            human[r["human_status"]] = human.get(r["human_status"], 0) + 1
    by_tool = [dict(r) for r in conn.execute(
        "SELECT tool, category, count(*) AS n, sum(status='error') AS errors, avg(duration_ms) AS avg_ms "
        "FROM calls WHERE db_id=? GROUP BY tool ORDER BY n DESC", (db_id,))]
    activity = [[r[0], r[1]] for r in conn.execute(
        "SELECT CAST(started_at/60 AS INTEGER)*60 AS m, count(*) FROM calls WHERE db_id=? GROUP BY m ORDER BY m",
        (db_id,))]
    focus = []
    for r in conn.execute(
            """SELECT f.start_i, f.name, f.flags, max(t.id) AS last FROM touches t
               JOIN functions f ON f.db_id=t.db_id AND f.start_i=t.func_i
               WHERE t.db_id=? AND t.role='target' AND t.kind != 'locate'
               GROUP BY t.func_i ORDER BY last DESC LIMIT 15""", (db_id,)):
        focus.append({"start": S.hexa(S.from_i(r["start_i"])), "name": _fname(r), "flags": r["flags"]})
    renames = [dict(r) for r in conn.execute(
        "SELECT addr, old_name, new_name, ts FROM renames WHERE db_id=? ORDER BY id DESC LIMIT 30", (db_id,))]
    comments = [dict(r) | {"func": S.hexa(S.from_i(r["func_i"])) if r["func_i"] is not None else None}
                for r in conn.execute(
                    "SELECT addr, text, ts, func_i FROM comments WHERE db_id=? ORDER BY id DESC LIMIT 30", (db_id,))]
    for c in comments:
        c.pop("func_i", None)
    prompts = [dict(r) for r in conn.execute(
        """SELECT p.id, p.text, min(c.started_at) AS ts, count(*) AS calls, sum(c.status='error') AS errors
           FROM calls c LEFT JOIN prompts p ON p.id=c.prompt_id
           WHERE c.db_id=? AND c.prompt_id IS NOT NULL GROUP BY c.prompt_id ORDER BY ts DESC LIMIT 50""", (db_id,))]
    segments = [{"name": r["name"], "start": r["start"], "end": r["end"], "perms": r["perms"], "type": r["type"]}
                for r in conn.execute("SELECT * FROM segments WHERE db_id=? ORDER BY start_i", (db_id,))]
    explanations = [dict(r) | {"func": S.hexa(S.from_i(r["func_i"]))} for r in conn.execute(
        """SELECT a.id, a.func_i, a.summary, a.name_suggestion, a.status, a.confidence, a.harness, a.created_at,
                  f.name, f.start_i FROM annotations a LEFT JOIN functions f ON f.db_id=a.db_id AND f.start_i=a.func_i
           WHERE a.db_id=? ORDER BY a.id DESC LIMIT 20""", (db_id,))]
    for e in explanations:
        e["name"] = e["name"] or e["func"]
        e.pop("func_i", None)
        e.pop("start_i", None)
    ann_counts = {r[0]: r[1] for r in conn.execute(
        "SELECT status, count(*) FROM annotations WHERE db_id=? GROUP BY status", (db_id,))}
    sessions = conn.execute("SELECT count(DISTINCT session_id) FROM calls WHERE db_id=?", (db_id,)).fetchone()[0]
    session_list = [dict(r) for r in conn.execute(
        """SELECT s.id, s.harness, s.source, min(c.started_at) AS ts, max(c.started_at) AS last,
                  count(*) AS calls, sum(c.status='error') AS errors, count(DISTINCT c.prompt_id) AS prompts
           FROM calls c JOIN sessions s ON s.id=c.session_id WHERE c.db_id=?
           GROUP BY s.id ORDER BY last DESC LIMIT 30""", (db_id,))]
    return {"db": d, "stages": stages, "human": human, "by_tool": by_tool, "activity": activity,
            "focus": focus, "renames": renames, "comments": comments, "prompts": prompts,
            "segments": segments, "sessions": sessions, "session_list": session_list,
            "explanations": explanations, "explanation_counts": ann_counts, "bundle": _bundle(conn, db_id),
            "edges": conn.execute("SELECT count(*) FROM edges WHERE db_id=?", (db_id,)).fetchone()[0]}
