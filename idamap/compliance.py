"""How closely the LLM followed idamap's guidance, measured from the calls idamap recorded.

idamap's tool descriptions and usage hint ask the model to: start with ``idamap_status``, find functions with
``idamap_search`` instead of guessing ``list_functions`` filters, call ``idamap_lookup`` before analysing a
function and ``idamap_annotate`` once it understood it. This module counts how often that happened.

It is a count, not a verdict: nobody needs 100 % of these (not every decompiled function deserves an
explanation), and a low number can just mean the task did not call for the tool. What the numbers are good
for is comparing setups: with and without the playbook, one client against another, before and after a change.

Definitions, per *session* (one client connection; with Claude Code hooks one Claude Code session):

status first    ``idamap_status`` was called before the session's first investigative call
                (anything but session housekeeping and idamap's own tools). Sessions that never
                investigated are left out.
lookup first    of the functions the session decompiled or disassembled, those it had passed to
                ``idamap_lookup`` earlier in the same session.
explained       of the functions the session decompiled or disassembled, those it later passed to
                ``idamap_annotate``.
search          ``idamap_search`` calls against ``list_functions`` / ``list_funcs`` calls that carried a
                ``filter`` (the "guessing a filter" the usage hint warns about). Unfiltered listings are
                enumeration and not counted.
blind re-read   functions that already had an explanation (not rejected) before the session began and that
                the session analysed without looking them up first: the work the memory exists to save.

Only sessions in which idamap's tools were available are measured: the proxy records whether it offered them
(``sessions.tools_offered``). Sessions recorded before that existed are counted only if they used an idamap
tool, which flatters the numbers; the result says so (``inferred``).
"""

from __future__ import annotations

import json

IDAMAP_TOOLS = ("idamap_status", "idamap_search", "idamap_lookup", "idamap_annotate")
ANALYZE = ("decompile", "disasm")
MAX_SESSIONS = 12


def compute(conn, db_id: int) -> dict:
    scope = "SELECT DISTINCT session_id FROM calls WHERE db_id=?"
    sessions = {r["id"]: dict(r) for r in conn.execute(
        f"SELECT id, harness, source, started_at, tools_offered FROM sessions WHERE id IN ({scope})", (db_id,))}

    stats = {r["session_id"]: dict(r) for r in conn.execute(
        f"""SELECT session_id,
                   MIN(CASE WHEN tool='idamap_status' THEN id END) AS first_status,
                   MIN(CASE WHEN tool NOT LIKE 'idamap%' AND category != 'session' THEN id END) AS first_work,
                   SUM(tool IN ('idamap_status', 'idamap_search', 'idamap_lookup', 'idamap_annotate')) AS tool_calls,
                   SUM(tool = 'idamap_search') AS searches
            FROM calls WHERE session_id IN ({scope}) GROUP BY session_id""", (db_id,))}

    guessed = {}  # session -> list_functions calls that carried a filter
    for r in conn.execute(
            f"SELECT session_id, input FROM calls WHERE tool IN ('list_functions', 'list_funcs') "
            f"AND session_id IN ({scope})", (db_id,)):
        try:
            inp = json.loads(r["input"] or "{}")
        except ValueError:
            continue
        if isinstance(inp, dict) and str(inp.get("filter") or "").strip():
            guessed[r["session_id"]] = guessed.get(r["session_id"], 0) + 1

    # per (session, function): the call ids (they grow with time) of the first analysis, first lookup, last explanation
    pairs: dict[tuple, dict] = {}
    for r in conn.execute(
            f"""SELECT c.session_id AS sid, c.id AS cid, t.kind AS kind, COALESCE(t.func_i, t.addr_i) AS fk
                FROM touches t JOIN calls c ON c.id = t.call_id
                WHERE t.db_id=? AND t.role='target' AND c.session_id IN ({scope})
                  AND COALESCE(t.func_i, t.addr_i) IS NOT NULL
                  AND (t.kind IN ('decompile', 'disasm', 'explain')
                       OR (t.kind = 'locate' AND c.tool = 'idamap_lookup'))
                ORDER BY c.id""", (db_id, db_id)):
        p = pairs.setdefault((r["sid"], r["fk"]), {"analysis": None, "lookup": None, "explain": None})
        if r["kind"] in ANALYZE:
            p["analysis"] = p["analysis"] if p["analysis"] is not None else r["cid"]
        elif r["kind"] == "locate":
            p["lookup"] = p["lookup"] if p["lookup"] is not None else r["cid"]
        else:
            p["explain"] = r["cid"]

    known = {r["func_i"]: r["t"] for r in conn.execute(  # when each function first got a usable explanation
        "SELECT func_i, MIN(created_at) AS t FROM annotations WHERE db_id=? AND status != 'rejected' GROUP BY func_i",
        (db_id,))}

    per: dict[str, dict] = {}
    for (sid, fk), p in pairs.items():
        if p["analysis"] is None or sid not in sessions:
            continue
        s = per.setdefault(sid, {"analyzed": 0, "looked": 0, "explained": 0, "known": 0, "known_looked": 0})
        looked = p["lookup"] is not None and p["lookup"] < p["analysis"]
        s["analyzed"] += 1
        s["looked"] += looked
        s["explained"] += p["explain"] is not None and p["explain"] > p["analysis"]
        if fk in known and known[fk] < (sessions[sid]["started_at"] or 0):
            s["known"] += 1
            s["known_looked"] += looked

    rows, unmeasured, inferred = [], 0, 0
    total = {"first": 0, "late": 0, "never": 0, "analyzed": 0, "looked": 0, "explained": 0,
             "searches": 0, "guessed": 0, "known": 0, "known_looked": 0}
    for sid, sess in sessions.items():
        st = stats.get(sid) or {}
        offered = sess["tools_offered"] == 1
        used = (st.get("tool_calls") or 0) > 0
        if not (offered or used):
            unmeasured += 1
            continue
        inferred += not offered
        if st.get("first_work") is None:
            status = "na"
        elif st.get("first_status") is None:
            status = "never"
        else:
            status = "first" if st["first_status"] < st["first_work"] else "late"
        f = per.get(sid) or {"analyzed": 0, "looked": 0, "explained": 0, "known": 0, "known_looked": 0}
        row = {"id": sid, "harness": sess["harness"], "source": sess["source"], "started_at": sess["started_at"],
               "inferred": not offered, "status": status, "searches": st.get("searches") or 0,
               "guessed": guessed.get(sid, 0), **f}
        rows.append(row)
        if status != "na":
            total[status] += 1
        for k in ("analyzed", "looked", "explained", "known", "known_looked"):
            total[k] += f[k]
        total["searches"] += row["searches"]
        total["guessed"] += row["guessed"]

    rows.sort(key=lambda r: r["started_at"] or 0, reverse=True)
    return {
        "measured": len(rows), "unmeasured": unmeasured, "inferred": inferred,
        "status": {"first": total["first"], "late": total["late"], "never": total["never"],
                   "of": total["first"] + total["late"] + total["never"]},
        "lookup": {"yes": total["looked"], "of": total["analyzed"]},
        "explained": {"yes": total["explained"], "of": total["analyzed"]},
        "search": {"idamap_search": total["searches"], "guessed_filters": total["guessed"]},
        "known": {"of": total["known"], "looked_up": total["known_looked"],
                  "blind": total["known"] - total["known_looked"]},
        "sessions": rows[:MAX_SESSIONS],
    }
