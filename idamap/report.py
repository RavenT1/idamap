"""Exports: a Markdown research log and an IDAPython script that paints the
coverage back into the IDA GUI."""

from __future__ import annotations

import html
import json
import time

from . import queries as Q
from . import store as S


def _t(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"


# Everything below the hard-coded labels is text from an analysed binary or from a model that read one. A
# Markdown viewer that renders raw HTML (many do) must not get to see tags in it, and a stray backtick must not
# close a code span early, so free text is HTML-escaped and code spans lose their backticks.
def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""), quote=False)


def _cs(s) -> str:
    return str(s if s is not None else "").replace("`", "'").replace("\n", " ").replace("\r", " ")


def _md(s) -> str:
    return _esc(str(s or "")).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def markdown(conn, db_id: int) -> str:
    sm = Q.summary(conn, db_id)
    d = sm["db"] or {}
    total = d.get("func_total") or d.get("known") or 0
    lines = [f"# Reverse engineering log — {_md(d.get('name'))}", ""]
    lines += [f"- **Database**: `{_cs(d.get('key'))}`",
              f"- **Input**: `{_cs(d.get('input_path') or '—')}`",
              f"- **Processor**: {_md(d.get('processor') or '—')} / {_md(d.get('file_type') or '—')}",
              f"- **SHA-256**: `{_cs(d.get('sha256') or '—')}`",
              f"- **Tool calls**: {d.get('calls')} across {sm['sessions']} session(s)",
              f"- **Generated**: {_t(time.time())}", ""]
    lines += ["## Coverage", "", "| Stage | Functions |", "|---|---|"]
    for st in reversed(S.STAGES):
        lines.append(f"| {st} | {sm['stages'][st]} |")
    touched = sum(v for k, v in sm["stages"].items() if k not in ("unseen", "seen"))
    if total:
        lines += ["", f"Inspected **{touched} / {total}** functions ({100 * touched / total:.1f}%)."]
    lines.append("")

    funcs = conn.execute(
        "SELECT * FROM functions WHERE db_id=? AND (flags & ? != 0 OR human_status IS NOT NULL OR note IS NOT NULL) "
        "ORDER BY first_touched", (db_id, ~S.F_SEEN)).fetchall()
    lines += ["## Functions worked on", "",
              "| Function | Address | Stage | What happened | Human | Note |", "|---|---|---|---|---|---|"]
    for f in funcs:
        name = f["name"] or "sub_%X" % S.from_i(f["start_i"])
        if f["orig_name"] and f["orig_name"] != f["name"]:
            name += f" (was `{_cs(f['orig_name'])}`)"
        lines.append(f"| {_md(name)} | `{f['start']}` | {S.stage_of(f['flags'])} | "
                     f"{', '.join(S.flag_list(f['flags']))} | {f['human_status'] or ''} | {_md(f['note'])} |")
    lines.append("")

    expl = conn.execute(
        """SELECT a.*, f.name, f.start FROM annotations a JOIN functions f ON f.db_id=a.db_id AND f.start_i=a.func_i
           WHERE a.db_id=? AND a.status != 'rejected' ORDER BY f.start_i, a.id DESC""", (db_id,)).fetchall()
    if expl:
        lines += ["## LLM explanations", "",
                  "Recorded by the model with `idamap_annotate`. **Unconfirmed** entries are hypotheses.", "",
                  "| Function | Address | Status | Explanation | Suggested name | Framework | Confidence | Evidence |",
                  "|---|---|---|---|---|---|---|---|"]
        seen = set()
        for a in expl:
            if a["func_i"] in seen:  # latest non-rejected per function
                continue
            seen.add(a["func_i"])
            status = "confirmed" if a["status"] == "confirmed" else "unconfirmed"
            lines.append(f"| {_md(a['name'])} | `{a['start']}` | {status} | {_md(a['summary'])} | "
                         f"{_md(a['name_suggestion'])} | {_md(a['framework'])} | {a['confidence'] or ''} | {_md(a['evidence'])} |")
        lines.append("")

    if sm["renames"]:
        lines += ["## Renames", "", "| Address | Old | New | When |", "|---|---|---|---|"]
        for r in reversed(sm["renames"]):
            lines.append(f"| `{r['addr']}` | {_md(r['old_name'])} | {_md(r['new_name'])} | {_t(r['ts'])} |")
        lines.append("")
    if sm["comments"]:
        lines += ["## Comments", "", "| Address | Comment |", "|---|---|"]
        for c in reversed(sm["comments"]):
            lines.append(f"| `{c['addr']}` | {_md(c['text'])} |")
        lines.append("")

    lines += ["## Session timeline", ""]
    rows = conn.execute("SELECT * FROM calls WHERE db_id=? ORDER BY id", (db_id,)).fetchall()
    prompts = {p["id"]: p["text"] for p in conn.execute("SELECT id, text FROM prompts")}
    cur = object()
    last_intent = None
    prev = None
    for r in rows:
        # prompts come from Claude Code hooks; proxy-only harnesses are grouped by session + idle gap
        if r["prompt_id"]:
            key = r["prompt_id"]
        elif prev is not None and not prev["prompt_id"] and prev["session_id"] == r["session_id"] \
                and r["started_at"] - prev["started_at"] < 300:
            key = cur
        else:
            key = ("s", r["id"])
        prev = r
        if key != cur:
            cur = key
            via = f" via {_md(r['harness'])}" if r["harness"] else ""
            if r["prompt_id"]:
                txt = (prompts.get(r["prompt_id"]) or "(prompt unavailable)").strip()
                lines += ["", f"### {_t(r['started_at'])} — task{via}", "", "> " + _esc(txt[:600]).replace("\n", "\n> "), ""]
            else:
                lines += ["", f"### {_t(r['started_at'])} — work block{via}", ""]
        if r["intent"] and r["intent"] != last_intent:
            last_intent = r["intent"]
            lines += ["", f"*{_md(r['intent'].strip()[:400])}*", ""]
        mark = "✗" if r["status"] == "error" else "·"
        lines.append(f"- {mark} `{r['tool']}` {_md(r['target'])}" + (f" — **{_md(r['error'])[:120]}**" if r["error"] else ""))
    lines.append("")
    return "\n".join(lines)


# IDA colours are 0xBBGGRR. Pastel so text stays readable on light/dark themes.
IDA_COLORS = {
    "seen": 0xF2EDE6,
    "explored": 0xF7E7C9,
    "disassembled": 0xC9EAF7,
    "decompiled": 0xCDEFD2,
    "annotated": 0xF3D6EC,
}


def ida_sync_script(conn, db_id: int) -> str:
    rows = conn.execute(
        "SELECT start, name, flags, touch_count, human_status, note FROM functions "
        "WHERE db_id=? AND (flags != 0 OR human_status IS NOT NULL OR note IS NOT NULL)", (db_id,)).fetchall()
    expl = {}
    for a in conn.execute("SELECT f.start, a.summary, a.status FROM annotations a JOIN functions f "
                          "ON f.db_id=a.db_id AND f.start_i=a.func_i WHERE a.db_id=? AND a.status != 'rejected' "
                          "ORDER BY a.id", (db_id,)):
        expl[a["start"]] = ("" if a["status"] == "confirmed" else "(unconfirmed) ") + a["summary"]
    data = [[r["start"], S.stage_of(r["flags"]), ", ".join(S.flag_list(r["flags"])), r["touch_count"],
             r["human_status"], r["note"], expl.get(r["start"])] for r in rows]
    d = conn.execute("SELECT name, key FROM databases WHERE id=?", (db_id,)).fetchone()
    # a file name is attacker-influenced and this lands in a comment of a script the analyst runs inside IDA:
    # no line-break of any kind (\n, \r, U+2028, ...) may survive
    title = "".join(ch if ch.isprintable() else " " for ch in f"{d['name']} ({d['key']})")
    return f'''# idamap → IDA coverage sync for {title}
# Generated {_t(time.time())}. Run in IDA: File > Script file…
# Colours every function the LLM worked on by coverage stage and adds a
# function comment with the idamap summary. Re-running replaces old tags.
# Set CLEAR = True to remove all idamap colours/comments.
import json, warnings
warnings.simplefilter("ignore", DeprecationWarning)
import ida_funcs, idc

CLEAR = False
COLORS = json.loads({json.dumps(IDA_COLORS)!r})
# [start, stage, what happened, calls, human review, note, LLM explanation]
DATA = json.loads({json.dumps(data)!r})
TAG = "[idamap]"

def strip_tag(cmt):
    return "\\n".join(l for l in (cmt or "").split("\\n") if not l.startswith(TAG)).strip()

n = 0
for start, stage, what, touches, human, note, explanation in DATA:
    ea = int(start, 16)
    f = ida_funcs.get_func(ea)
    if not f:
        continue
    old = strip_tag(ida_funcs.get_func_cmt(f, True))
    if CLEAR:
        f.color = 0xFFFFFFFF
        ida_funcs.set_func_cmt(f, old, True)
    else:
        f.color = COLORS.get(stage, 0xFFFFFFFF)
        tag = "%s %s — %s (%d calls)" % (TAG, stage, what, touches)
        if human:
            tag += " | human: " + human
        if note:
            tag += "\\n%s note: %s" % (TAG, note.replace("\\n", " "))
        if explanation:
            tag += "\\n%s LLM: %s" % (TAG, explanation.replace("\\n", " "))
        ida_funcs.set_func_cmt(f, (old + "\\n" + tag).strip(), True)
    ida_funcs.update_func(f)
    n += 1
idc.refresh_idaview_anyway()
print("idamap: %s %d functions" % ("cleared" if CLEAR else "painted", n))
'''
