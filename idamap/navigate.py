"""Navigation tools the model can call: ``idamap_search`` and ``idamap_status``.

Both answer from idamap's own corpus (functions, references, coverage, explanations, the app
bundle), so they can combine what IDA knows with what the research has already covered — for
example "functions that import Keychain APIs and that nobody has decompiled yet".
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import bundle
from . import store as S

EXPORT_SCRIPT = Path(__file__).parent / "ida_scripts" / "export_map.py"
NO_DB = "idamap has no database recorded yet (open a binary with ida-mcp first)"

# "worked on" = someone looked at the code itself, not just at a name in a result list
WORKED = S.F_DISASM | S.F_DECOMP | S.F_CFG | S.F_FRAME | S.F_DATA | S.ANNOTATED

SEARCH_KINDS = ("any", "name", "string", "import", "class", "selector", "explanation")
REF_KIND = {"string": "str", "import": "import", "class": "class", "selector": "sel"}
MANGLED = re.compile(r"^_*(\$[sS]|T0|Z[NLS]?\d|\?)")
MIN_FRONTIER_SIZE = 40  # smaller functions are mostly import stubs / thunks
ESC = " ESCAPE '\\'"


def db_for(conn, session_id: str | None, args: dict) -> int | None:
    """The database a call is about; the 'unknown' placeholder (calls made before any open_idb) is not one."""
    def real(db_id):
        r = conn.execute("SELECT key FROM databases WHERE id=?", (db_id,)).fetchone() if db_id else None
        return db_id if r and r["key"] != "unknown" else None

    ws = args.get("database_id")
    if ws:
        r = conn.execute("SELECT db_id FROM workspace_ids WHERE ws_id=?", (str(ws),)).fetchone()
        if r and real(r["db_id"]):
            return r["db_id"]
    if session_id:
        r = conn.execute("SELECT db_id FROM sessions WHERE id=?", (session_id,)).fetchone()
        if r and real(r["db_id"]):
            return r["db_id"]
    r = conn.execute("SELECT id FROM databases WHERE key != 'unknown' ORDER BY last_seen DESC LIMIT 1").fetchone()
    return r["id"] if r else None


def fname(row) -> str:
    return row["name"] or "sub_%X" % S.from_i(row["start_i"])


def display(row) -> str:
    """Demangled name for mangled symbols, the plain name otherwise."""
    name = fname(row)
    dem = row["demangled"] if "demangled" in row.keys() else None
    return dem if dem and MANGLED.match(name) else name


def labeled(row) -> str:
    """'name @0xaddr': overloads share a short name, and the model needs the address to act on it."""
    return f"{display(row)} @{S.hexa(S.from_i(row['start_i']))}"


# compiler-generated Swift boilerplate: never what an analyst wants to read next
BOILERPLATE = re.compile(
    r"^(lazy protocol witness table accessor|type metadata accessor|outlined |protocol witness for|"
    r"reabstraction thunk|merged |value witness|___?swift_|key path (getter|setter|equality|hash)|"
    r"generic specialization <|nominal type descriptor|base conformance descriptor|"
    r"associated type (witness table accessor|descriptor)|partial apply for|dispatch thunk of|"
    r"default argument \d+ of|one-time initialization|full type metadata)")


def _like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _clip(s: str | None, n: int) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _is_mapped(conn, db: int) -> bool:
    r = conn.execute("SELECT map_imported_at FROM databases WHERE id=?", (db,)).fetchone()
    return bool(r and r["map_imported_at"])


def _map_note() -> str:
    return ("The binary is not indexed yet, so this answer is incomplete or empty. Call "
            f"run_script(file=\"{EXPORT_SCRIPT}\") once (it only reads the database and takes seconds), "
            "then repeat this call.")


def framework_index(conn, db: int) -> bundle.Index:
    try:
        return bundle.Index(bundle.bundle_info(conn, db))
    except Exception:  # noqa: BLE001 — bundle hints are a bonus, never a failure
        return bundle.Index(None)


# --------------------------------------------------------------------------
# idamap_search
# --------------------------------------------------------------------------

def search(conn, session_id: str | None, args: dict) -> str:
    db = db_for(conn, session_id, args)
    if db is None:
        return json.dumps({"error": NO_DB})
    query = str(args.get("query") or "").strip().lower()
    if not query:
        return json.dumps({"error": "query is required, e.g. \"keychain\" or \"SecItemCopyMatching\""})
    kind = str(args.get("kind") or "any").lower()
    if kind not in SEARCH_KINDS:
        return json.dumps({"error": f"kind must be one of: {', '.join(SEARCH_KINDS)}"})
    try:
        limit = max(1, min(int(args.get("limit") or 20), 50))
    except (TypeError, ValueError):
        limit = 20
    unexplored = args.get("unexplored_only") in (True, "true", "True", 1)
    terms = query.split()[:6]

    where, params = [], []
    for t in terms:
        like = _like(t)
        conds = []
        if kind in ("any", "name"):
            for col in ("f.name", "f.demangled", "f.orig_name"):
                conds.append(f"lower({col}) LIKE ?{ESC}")
                params.append(like)
        if kind == "any" or kind in REF_KIND:
            ref = ("EXISTS (SELECT 1 FROM func_refs r WHERE r.db_id=f.db_id AND r.func_i=f.start_i "
                   f"AND lower(r.value) LIKE ?{ESC}")
            params.append(like)
            if kind in REF_KIND:
                ref += " AND r.kind=?"
                params.append(REF_KIND[kind])
            conds.append(ref + ")")
        if kind in ("any", "explanation"):
            conds.append("EXISTS (SELECT 1 FROM annotations a WHERE a.db_id=f.db_id AND a.func_i=f.start_i "
                         f"AND a.status!='rejected' AND (lower(a.summary) LIKE ?{ESC} OR lower(a.name_suggestion) LIKE ?{ESC}))")
            params += [like, like]
        where.append("(" + " OR ".join(conds) + ")")
    if unexplored:
        where.append("(f.flags & ?) = 0")
        params.append(WORKED)

    base = " FROM functions f WHERE f.db_id=? AND " + " AND ".join(where)
    total = conn.execute("SELECT count(*)" + base, (db, *params)).fetchone()[0]
    hit_sql = " OR ".join([f"lower(f.name) LIKE ?{ESC} OR lower(f.demangled) LIKE ?{ESC}"] * len(terms))
    hit_params = [x for t in terms for x in (_like(t), _like(t))]
    rows = conn.execute("SELECT f.*" + base + f" ORDER BY ({hit_sql}) DESC, f.start_i LIMIT ?",
                        (db, *params, *hit_params, limit)).fetchall()

    idx = framework_index(conn, db)
    used_modules: list[str] = []
    ref_where = " OR ".join([f"lower(value) LIKE ?{ESC}"] * len(terms))
    ref_params = [_like(t) for t in terms]
    results = []
    for f in rows:
        item = {"address": S.hexa(S.from_i(f["start_i"])), "name": display(f), "stage": S.stage_of(f["flags"])}
        if f["size"]:
            item["size"] = f["size"]
        sql = f"SELECT kind, value FROM func_refs WHERE db_id=? AND func_i=? AND ({ref_where})"
        sub = [db, f["start_i"], *ref_params]
        if kind in REF_KIND:
            sql += " AND kind=?"
            sub.append(REF_KIND[kind])
        found = conn.execute(sql + " LIMIT 4", sub).fetchall()
        if found:
            item["matched"] = [f"{r['kind']}: {_clip(r['value'], 110)}" for r in found]
            mods = idx.modules_in(r["value"] for r in found if r["kind"] == "import")
            if mods:
                item["in_bundle"] = [idx.describe(m, with_path=False) for m in mods]
                used_modules += [m for m in mods if m not in used_modules]
        ann = conn.execute("SELECT summary, status, name_suggestion FROM annotations WHERE db_id=? AND func_i=? "
                           "AND status!='rejected' ORDER BY id DESC LIMIT 1", (db, f["start_i"])).fetchone()
        if f["size"] and f["size"] <= 32 and item.get("in_bundle"):
            # an import stub: the code that matters is whoever calls it
            callers = conn.execute(
                "SELECT c.* FROM edges e JOIN functions c ON c.db_id=e.db_id AND c.start_i=e.src_i "
                "WHERE e.db_id=? AND e.dst_i=? LIMIT 4", (db, f["start_i"])).fetchall()
            if callers:
                item["called_from"] = [labeled(c) for c in callers]
        if ann:
            item["explained"] = {"summary": _clip(ann["summary"], 160), "status": ann["status"]}
            if ann["name_suggestion"]:
                item["explained"]["suggested_name"] = ann["name_suggestion"]
        results.append(item)

    out: dict = {"query": query, "kind": kind, "total_matches": total, "shown": len(results), "results": results}
    if unexplored:
        out["filter"] = "unexplored_only: never disassembled / decompiled / annotated"
    named = [m["name"] for t in terms for m in idx.members.values() if m["name"].lower() == t and m["name"] != idx.own]
    paths = idx.unanalyzed_paths(used_modules + named)
    if paths:
        out["unanalyzed_framework_binaries"] = paths  # open one with open_idb to see its code
    notes = []
    if not _is_mapped(conn, db):
        out = {"map_required": _map_note(), **out}
    if total > len(results):
        notes.append("More matches exist: add words to the query, set kind, or use unexplored_only=true.")
    for n in named:  # the query names a bundled framework that has not been analyzed yet
        if n in paths:
            notes.append(f"{n} is part of this app but not analyzed yet: open its binary (path above) to see its code.")
    if notes:
        out["notes"] = notes
    return json.dumps(out, indent=1)


# --------------------------------------------------------------------------
# idamap_status
# --------------------------------------------------------------------------

def status(conn, session_id: str | None, args: dict) -> str:
    db = db_for(conn, session_id, args)
    if db is None:
        return json.dumps({"error": NO_DB})
    d = conn.execute("SELECT * FROM databases WHERE id=?", (db,)).fetchone()
    mapped = bool(d["map_imported_at"])
    stages = {s: 0 for s in S.STAGES}
    for r in conn.execute("SELECT flags FROM functions WHERE db_id=?", (db,)):
        stages[S.stage_of(r["flags"])] += 1
    known = sum(stages.values())
    total = max(d["func_total"] or 0, known)
    stages["unseen"] += max(0, total - known)
    out: dict = {
        "binary": d["label"] or d["name"], "processor": d["processor"], "functions_total": total,
        "map": "full (every function and call edge is indexed)" if mapped else "partial (only functions seen so far)",
        "coverage_by_stage": {k: v for k, v in stages.items()},
    }
    ex = {r[0]: r[1] for r in conn.execute("SELECT status, count(*) FROM annotations WHERE db_id=? GROUP BY status", (db,))}
    if ex:
        out["explanations"] = {k: ex.get(k, 0) for k in ("hypothesis", "confirmed", "rejected")}
    rev = {r[0]: r[1] for r in conn.execute(
        "SELECT human_status, count(*) FROM functions WHERE db_id=? AND human_status IS NOT NULL GROUP BY human_status", (db,))}
    if rev:
        out["analyst_review"] = rev

    recent = conn.execute(
        """SELECT f.* FROM functions f JOIN (SELECT func_i, max(id) AS last FROM touches
               WHERE db_id=? AND role='target' AND kind!='locate' AND func_i IS NOT NULL GROUP BY func_i) t
           ON t.func_i=f.start_i WHERE f.db_id=? ORDER BY t.last DESC LIMIT 6""", (db, db)).fetchall()
    if recent:
        out["last_inspected"] = [{"address": S.hexa(S.from_i(f["start_i"])), "name": display(f),
                                  "stage": S.stage_of(f["flags"])} for f in recent]

    frontier = conn.execute(
        """SELECT t.*, count(*) AS n FROM edges e
           JOIN functions s ON s.db_id=e.db_id AND s.start_i=e.src_i
           JOIN functions t ON t.db_id=e.db_id AND t.start_i=e.dst_i
           WHERE e.db_id=? AND (s.flags & ?) != 0 AND (t.flags & ?) = 0
             AND COALESCE(t.size,0) >= ? AND COALESCE(t.is_lib,0)=0
           GROUP BY t.start_i ORDER BY n DESC, t.size DESC LIMIT 60""", (db, WORKED, WORKED, MIN_FRONTIER_SIZE)).fetchall()
    frontier = [f for f in frontier if not BOILERPLATE.match(display(f))][:8]
    if frontier:
        out["look_next"] = [{"address": S.hexa(S.from_i(f["start_i"])), "name": display(f), "size": f["size"],
                             "called_from_analyzed_functions": f["n"]} for f in frontier]

    steps = []
    if not mapped:
        out = {"map_required": _map_note(), **out}
    pending = out.get("explanations", {}).get("hypothesis", 0)
    if pending:
        steps.append(f"{pending} explanation(s) still await the analyst's review; "
                     "idamap_lookup shows which are confirmed or rejected.")
    info = None
    try:
        info = bundle.bundle_info(conn, db)
    except Exception:  # noqa: BLE001
        info = None
    if info:
        idx = bundle.Index(info)
        stubs: dict[str, set] = {}  # module -> import stubs that point into it
        for r in conn.execute("SELECT func_i, value FROM func_refs WHERE db_id=? AND kind='import' LIMIT 200000", (db,)):
            for m in idx.modules_in([r["value"]]):
                stubs.setdefault(m, set()).add(r["func_i"])
        users: dict[str, int] = {}  # module -> distinct functions of this binary that call those stubs
        for m, ids in stubs.items():
            ids, callers = list(ids), set()
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                for r in conn.execute("SELECT DISTINCT src_i FROM edges WHERE db_id=? AND dst_i IN (%s)"
                                      % ",".join("?" * len(chunk)), (db, *chunk)):
                    callers.add(r[0])
            users[m] = len(callers) or len(ids)  # no edges yet (partial map): fall back to the stub count
        members = []
        for m in info["members"]:
            e = {"name": m["name"], "kind": m["kind"],
                 "status": "this binary" if m.get("current") else ("analyzed in idamap" if m.get("analyzed") else "not analyzed yet")}
            if m["name"] in users:
                e["functions_here_that_use_it"] = users[m["name"]]
            if not m.get("analyzed") and not m.get("current"):
                e["binary"] = os.path.relpath(m["path"], info["root"]) if m["path"].startswith(info["root"]) else m["path"]
            members.append(e)
        out["app_bundle"] = {"app": info["app"], "app_root": info["root"],
                             "note": "binary paths are relative to app_root", "binaries": members}
        for m in info["members"]:
            n = users.get(m["name"], 0)
            if n and not m.get("analyzed") and not m.get("current"):
                rel = os.path.relpath(m["path"], info["root"]) if m["path"].startswith(info["root"]) else m["path"]
                steps.append(f"{n} function(s) here use {m['name']}, which is not analyzed yet: the real "
                             f"implementations live in {rel} (relative to app_root).")
    if frontier:
        steps.append("look_next lists unanalyzed functions called most often from code that was already analyzed.")
    if steps:
        out["next_steps"] = steps
    return json.dumps(out, indent=1)


# --------------------------------------------------------------------------
# framework hints for idamap_lookup
# --------------------------------------------------------------------------

def lookup_hints(conn, db: int, idx: bundle.Index, func_row, import_values: list[str]) -> dict:
    """Extra fields for one function in an idamap_lookup answer."""
    hints: dict = {}
    mods = idx.modules_in(import_values) if idx else []
    if mods:
        hints["bundled_frameworks"] = [idx.describe(m) for m in mods]
    size = func_row["size"]
    if size and size <= 32 and import_values:
        note = f"Tiny stub ({size} bytes) that forwards to an imported symbol: the implementation is not in this binary."
        if mods:
            note += " It lives in the bundled framework " + ", ".join(mods) + "."
        hints["note"] = note
    return hints
