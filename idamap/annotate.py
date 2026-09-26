"""LLM-facing tools served by the idamap proxy itself (never forwarded to ida-mcp).

* ``idamap_annotate`` — the model records what it understood about a function.
  Stored as an unconfirmed hypothesis the analyst can confirm or reject.
* ``idamap_lookup``   — the model reads what is already known before digging in,
  so knowledge carries over between sessions and harnesses.
"""

from __future__ import annotations

import json

from . import ingest
from . import parse as P
from . import store as S

ANNOTATE = "idamap_annotate"
LOOKUP = "idamap_lookup"
NAMES = {ANNOTATE, LOOKUP}
CONFIDENCE = ("low", "medium", "high")
STATUSES = ("hypothesis", "confirmed", "rejected")

TOOLS = [
    {
        "name": ANNOTATE,
        "title": "Record function explanation (idamap)",
        "description": (
            "Record your understanding of a function in the analyst's idamap research log after you have "
            "analyzed it (decompiled / disassembled / traced its xrefs). Does NOT modify the IDA database. "
            "Call it once per function you understood, and again later to refine. The analyst sees it as an "
            "unconfirmed hypothesis, so be concrete and cite what in the code supports it."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Function address as hex, e.g. 0x100004ac3"},
                "summary": {"type": "string", "description": "What the function does, 1-3 sentences"},
                "name_suggestion": {"type": "string", "description": "Meaningful name you would give it"},
                "tags": {"type": "array", "items": {"type": "string"},
                         "description": "Short tags, e.g. [\"network\", \"json-parsing\"]"},
                "framework": {"type": "string",
                              "description": "Library / SDK / framework it belongs to or mainly uses, if identifiable"},
                "confidence": {"type": "string", "enum": list(CONFIDENCE)},
                "evidence": {"type": "string", "description": "What in the code supports this (calls, strings, constants)"},
                "database_id": {"type": "string", "description": "ida-mcp workspace database_id, only in --workspace mode"},
            },
            "required": ["address", "summary"],
        },
    },
    {
        "name": LOOKUP,
        "title": "Look up what is known about functions (idamap)",
        "description": (
            "Call this FIRST, before decompiling or analyzing a function you have not looked at in this "
            "conversation. It is cheap and returns knowledge IDA does not have: explanations recorded in earlier "
            "sessions (possibly by other assistants) and whether the analyst confirmed or rejected them, the "
            "analyst's own notes and review status, renames, referenced strings / selectors / classes / imports, "
            "and known callers / callees. Accepts up to 20 addresses."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"description": "Hex address or array of hex addresses",
                            "anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
                "database_id": {"type": "string", "description": "ida-mcp workspace database_id, only in --workspace mode"},
            },
            "required": ["address"],
        },
    },
]

INSTRUCTIONS = (
    "\n\nidamap: this session is recorded for the analyst. Before analyzing a function, call idamap_lookup "
    "with its address: earlier sessions and the analyst may already have explained, confirmed or rejected it "
    "(IDA itself does not know this). After you understand a function, call idamap_annotate with a short "
    "summary, a suggested name and the evidence.")


def _db_for(conn, session_id: str | None, args: dict) -> int | None:
    ws = args.get("database_id")
    if ws:
        r = conn.execute("SELECT db_id FROM workspace_ids WHERE ws_id=?", (str(ws),)).fetchone()
        if r:
            return r["db_id"]
    if session_id:
        r = conn.execute("SELECT db_id FROM sessions WHERE id=?", (session_id,)).fetchone()
        if r and r["db_id"]:
            return r["db_id"]
    r = conn.execute("SELECT id FROM databases ORDER BY last_seen DESC LIMIT 1").fetchone()
    return r["id"] if r else None


def _fname(row) -> str:
    return row["name"] or "sub_%X" % S.from_i(row["start_i"])


def validate_annotation(args: dict) -> str | None:
    if P.parse_addr(args.get("address")) is None:
        return "address must be a hex string such as 0x100004ac3"
    if not str(args.get("summary") or "").strip():
        return "summary is required"
    if args.get("confidence") and args["confidence"] not in CONFIDENCE:
        return "confidence must be one of: low, medium, high"
    return None


def describe_annotate(conn, session_id: str | None, args: dict) -> str:
    """Response text for idamap_annotate (the write itself happens in store_annotation)."""
    addr = P.parse_addr(args.get("address"))
    db = _db_for(conn, session_id, args)
    label = S.hexa(addr)
    if db is not None:
        fi = ingest.containing_function(conn, db, addr)
        if fi is not None:
            r = conn.execute("SELECT start_i, name FROM functions WHERE db_id=? AND start_i=?", (db, fi)).fetchone()
            label = f"{_fname(r)} ({S.hexa(S.from_i(fi))})"
    return f"Recorded explanation for {label}. The analyst will review it in idamap."


def store_annotation(conn, session_id: str | None, harness: str | None, args: dict, call_id: int | None) -> int | None:
    addr = P.parse_addr(args.get("address"))
    db = _db_for(conn, session_id, args)
    if addr is None or db is None:
        return None
    fi = ingest.containing_function(conn, db, addr)
    if fi is None:
        fi = ingest.ensure_stub(conn, db, addr, None, S.now())
    tags = args.get("tags")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    tags = [str(t)[:40] for t in (tags or [])][:12]
    conf = args.get("confidence") if args.get("confidence") in CONFIDENCE else None
    return conn.execute(
        """INSERT INTO annotations(db_id, func_i, source, summary, name_suggestion, tags, framework, confidence,
                                   evidence, status, call_id, session_id, harness, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,'hypothesis',?,?,?,?)""",
        (db, fi, "llm", str(args.get("summary")).strip()[:2000], (args.get("name_suggestion") or None),
         json.dumps(tags), (args.get("framework") or None), conf, (str(args.get("evidence") or "")[:2000] or None),
         call_id, session_id, harness, S.now())).lastrowid


def lookup(conn, session_id: str | None, args: dict) -> str:
    raw = args.get("address")
    addrs = [P.parse_addr(a) for a in (raw if isinstance(raw, list) else [raw])][:20]
    db = _db_for(conn, session_id, args)
    if db is None:
        return json.dumps({"error": "idamap has no database recorded yet"})
    out = []
    for a in addrs:
        if a is None:
            out.append({"error": "invalid address"})
            continue
        fi = ingest.containing_function(conn, db, a)
        if fi is None:
            out.append({"address": S.hexa(a), "known": False})
            continue
        f = conn.execute("SELECT * FROM functions WHERE db_id=? AND start_i=?", (db, fi)).fetchone()
        item = {"address": S.hexa(S.from_i(fi)), "name": _fname(f), "known": True,
                "coverage": S.flag_list(f["flags"]), "calls_made_on_it": f["touch_count"]}
        if f["demangled"]:
            item["demangled"] = f["demangled"]
        if f["orig_name"] and f["orig_name"] != f["name"]:
            item["original_name"] = f["orig_name"]
        if f["human_status"]:
            item["analyst_status"] = f["human_status"]
        if f["note"]:
            item["analyst_note"] = f["note"]
        anns = conn.execute(
            "SELECT * FROM annotations WHERE db_id=? AND func_i=? ORDER BY id DESC LIMIT 5", (db, fi)).fetchall()
        if anns:
            item["explanations"] = [
                {k: v for k, v in {
                    "summary": x["summary"], "name_suggestion": x["name_suggestion"],
                    "tags": json.loads(x["tags"] or "[]") or None, "framework": x["framework"],
                    "confidence": x["confidence"], "status": x["status"], "by": x["harness"] or x["source"],
                }.items() if v} for x in anns]
        refs: dict[str, list] = {}
        for r in conn.execute("SELECT kind, value FROM func_refs WHERE db_id=? AND func_i=?", (db, fi)):
            bucket = refs.setdefault(r["kind"], [])
            if len(bucket) < 12:
                bucket.append(r["value"])
        if refs:
            item["references"] = refs

        def names(sql):
            return [_fname(r) for r in conn.execute(sql, (db, fi))]

        callers = names("SELECT f.start_i, f.name FROM edges e JOIN functions f ON f.db_id=e.db_id AND f.start_i=e.src_i "
                        "WHERE e.db_id=? AND e.dst_i=? LIMIT 15")
        callees = names("SELECT f.start_i, f.name FROM edges e JOIN functions f ON f.db_id=e.db_id AND f.start_i=e.dst_i "
                        "WHERE e.db_id=? AND e.src_i=? LIMIT 15")
        if callers:
            item["callers"] = callers
        if callees:
            item["callees"] = callees
        out.append(item)
    return json.dumps(out if len(out) != 1 else out[0], indent=1)


def set_status(conn, db_id: int, ann_id: int, status: str) -> bool:
    if status not in STATUSES:
        return False
    cur = conn.execute("UPDATE annotations SET status=?, reviewed_at=? WHERE id=? AND db_id=?",
                       (status, S.now(), ann_id, db_id))
    conn.execute("UPDATE functions SET updated_at=? WHERE db_id=? AND start_i=(SELECT func_i FROM annotations WHERE id=?)",
                 (S.now(), db_id, ann_id))
    return cur.rowcount > 0
