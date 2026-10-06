"""Turn one ida-mcp tool call (input + output) into structured facts.

ida-mcp conventions this relies on (verified against ida-mcp's real output):

* Single-address calls return the payload directly (plain text for
  ``decompile``/``disasm``, JSON for most others).
* Array-address calls return ``{"results": [{"address": A, <payload> | "error"}]}``.
* Function records look like ``{"address", "name", "size"}`` (sometimes with
  ``start``/``end``).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from . import store as S

# --------------------------------------------------------------------------
# Tool metadata
# --------------------------------------------------------------------------

CATEGORIES: dict[str, list[str]] = {
    "session": ["open_idb", "open_dsc", "close_idb", "dsc_add_dylib", "dsc_add_region",
                "load_debug_info", "analysis_status", "task_status", "idb_meta",
                "tool_catalog", "tool_help", "recent_operations", "analyze_funcs"],
    "listing": ["list_functions", "list_funcs", "lookup_funcs", "resolve_function",
                "function_at", "addr_info", "export_funcs", "segments", "imports",
                "exports", "entrypoints", "list_globals"],
    "code": ["disasm", "disasm_by_name", "disasm_function_at", "render_range",
             "decompile", "pseudocode_at", "basic_blocks"],
    "xref": ["xrefs_to", "xrefs_from", "xref_matrix", "callers", "callees", "callgraph",
             "find_paths", "xrefs_to_field", "xrefs_to_string"],
    "data": ["get_bytes", "get_string", "get_u8", "get_u16", "get_u32", "get_u64",
             "get_global_value", "int_convert", "read_struct"],
    "search": ["find_bytes", "search", "strings", "find_string", "analyze_strings",
               "find_insns", "find_insn_operands"],
    "types": ["local_types", "declare_type", "apply_types", "infer_types", "stack_frame",
              "declare_stack", "delete_stack", "structs", "struct_info", "search_structs"],
    "edit": ["set_comments", "rename", "patch", "patch_asm", "lumina_apply",
             "lumina_lookup", "list_patches"],
    "script": ["run_script"],
    "idamap": ["idamap_annotate", "idamap_lookup", "idamap_search", "idamap_status"],
}
TOOL_CATEGORY = {t: c for c, ts in CATEGORIES.items() for t in ts}

# tool -> (touch kind, coverage flag) for the address(es) the call targets.
TARGET_KIND: dict[str, tuple[str, int]] = {
    "decompile": ("decompile", S.F_DECOMP),
    "pseudocode_at": ("decompile", S.F_DECOMP),
    "disasm": ("disasm", S.F_DISASM),
    "disasm_by_name": ("disasm", S.F_DISASM),
    "disasm_function_at": ("disasm", S.F_DISASM),
    "render_range": ("disasm", S.F_DISASM),
    "basic_blocks": ("cfg", S.F_CFG),
    "xrefs_to": ("xref", S.F_XREF),
    "xrefs_from": ("xref", S.F_XREF),
    "xref_matrix": ("xref", S.F_XREF),
    "callers": ("xref", S.F_XREF),
    "callees": ("xref", S.F_XREF),
    "callgraph": ("xref", S.F_XREF),
    "find_paths": ("xref", S.F_XREF),
    "get_bytes": ("data", S.F_DATA),
    "get_string": ("data", S.F_DATA),
    "get_u8": ("data", S.F_DATA),
    "get_u16": ("data", S.F_DATA),
    "get_u32": ("data", S.F_DATA),
    "get_u64": ("data", S.F_DATA),
    "read_struct": ("data", S.F_DATA),
    "stack_frame": ("frame", S.F_FRAME),
    "infer_types": ("frame", S.F_FRAME),
    "apply_types": ("types", S.F_TYPED),
    "declare_stack": ("types", S.F_TYPED),
    "delete_stack": ("types", S.F_TYPED),
    "set_comments": ("comment", S.F_COMMENTED),
    "rename": ("rename", S.F_RENAMED),
    "patch": ("patch", S.F_PATCHED),
    "patch_asm": ("patch", S.F_PATCHED),
    "lumina_apply": ("lumina", S.F_LUMINA),
    "lumina_lookup": ("locate", 0),
    "function_at": ("locate", 0),
    "addr_info": ("locate", 0),
    "lookup_funcs": ("locate", 0),
    "resolve_function": ("locate", 0),
    "idamap_annotate": ("explain", S.F_EXPLAINED),
    "idamap_lookup": ("locate", 0),
}

# Tools whose target is certainly the start of a function (so an unknown
# target address may be recorded as a stub function).
FUNC_START_TOOLS = {"decompile", "basic_blocks", "callers", "callees", "callgraph",
                    "stack_frame", "infer_types", "lumina_apply"}

EXPORT_MARKER = "IDAMAP_EXPORT_FILE="


def short_tool(tool_name: str) -> str:
    """mcp__ida__decompile -> decompile"""
    return tool_name.split("__")[-1] if tool_name.startswith("mcp__") else tool_name


def category(tool: str) -> str:
    return TOOL_CATEGORY.get(tool, "other")


# --------------------------------------------------------------------------
# Value helpers
# --------------------------------------------------------------------------

_HEX = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]+)h?\s*$")


def parse_addr(v: Any) -> int | None:
    """Parse an address value; returns None for names / garbage."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v & ((1 << 64) - 1)
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, str):
        s = v.strip()
        if s.lower().startswith("0x"):
            try:
                return int(s, 16)
            except ValueError:
                return None
        if s.isdigit():
            return int(s, 10)
    return None


def as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def response_text(resp: Any) -> str:
    """Flatten a Claude Code MCP tool_response into text."""
    if resp is None:
        return ""
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        if "content" in resp:
            return response_text(resp["content"])
        if resp.get("type") == "text":
            return resp.get("text", "")
        return json.dumps(resp)
    if isinstance(resp, list):
        parts = []
        for b in resp:
            if isinstance(b, dict) and b.get("type") == "text":
                parts.append(b.get("text", ""))
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    return str(resp)


def try_json(text: str) -> Any:
    t = text.strip()
    if not t or t[0] not in "[{":
        return None
    try:
        return json.loads(t)
    except ValueError:
        return None


_SIG = re.compile(r"([A-Za-z_$?@.~][\w$?@.~:<>]*)\s*\(")
_CALLCONV = {"__fastcall", "__cdecl", "__stdcall", "__thiscall", "__usercall", "__userpurge", "__noreturn"}


def decompiled_name(code: str) -> str | None:
    """Best-effort function name from the first line of Hex-Rays output."""
    for line in code.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        for m in _SIG.finditer(line):
            name = m.group(1)
            if name not in _CALLCONV and not name.startswith("__int"):
                return name
        return None
    return None


# --------------------------------------------------------------------------
# Extraction result
# --------------------------------------------------------------------------

@dataclass
class Target:
    addr: int | None
    name: str | None = None
    ok: bool = True
    detail: str | None = None


@dataclass
class Facts:
    kind: str | None = None           # touch kind for targets
    flag: int = 0                     # coverage flag for targets
    targets: list[Target] = field(default_factory=list)
    functions: list[dict] = field(default_factory=list)       # {start, name, size}
    results: list[tuple[int, str, str | None]] = field(default_factory=list)  # (addr, kind, detail)
    edges: list[tuple[int, int]] = field(default_factory=list)  # (from addr, to addr) — any addr inside functions
    renames: list[tuple[int | None, str | None, str]] = field(default_factory=list)  # (addr, current_name, new)
    comments: list[tuple[int | None, str | None, str, bool]] = field(default_factory=list)
    segments: list[dict] = field(default_factory=list)
    db_meta: dict = field(default_factory=dict)
    stub_names: dict[int, str] = field(default_factory=dict)
    export_file: str | None = None
    func_start_hint: bool = False


def _func_record(d: Any) -> dict | None:
    if not isinstance(d, dict):
        return None
    start = parse_addr(d.get("start", d.get("address")))
    name = d.get("name")
    if start is None or not isinstance(name, str):
        return None
    size = d.get("size")
    if not isinstance(size, int):
        end = parse_addr(d.get("end"))
        size = end - start if end is not None and end > start else None
    return {"start": start, "name": name, "size": size}


def _func_records(v: Any) -> list[dict]:
    out = []
    for item in as_list(v):
        r = _func_record(item)
        if r:
            out.append(r)
    return out


# --------------------------------------------------------------------------
# Input-side extraction (available at PreToolUse time)
# --------------------------------------------------------------------------

def input_targets(tool: str, inp: dict) -> list[Target]:
    inp = inp or {}
    vals: list[Any] = []
    names: list[str] = []
    if tool == "callgraph":
        vals = as_list(inp.get("roots"))
    elif tool == "find_paths":
        vals = [inp.get("start"), inp.get("end")]
    elif tool == "xref_matrix":
        vals = as_list(inp.get("addrs"))
    elif tool == "render_range":
        vals = [inp.get("start")]
    elif tool == "lookup_funcs":
        vals = as_list(inp.get("queries"))
    elif tool == "resolve_function":
        names = [inp.get("name")]
    elif tool == "disasm_by_name":
        names = [inp.get("name")]
    elif tool == "rename":
        if "address" in inp:
            vals = [inp.get("address")]
        else:
            names = [inp.get("current_name")]
    else:
        if "address" in inp:
            vals = as_list(inp.get("address"))
        elif "target_name" in inp:
            names = [inp.get("target_name")]
    out = []
    for v in vals:
        if v is None:
            continue
        a = parse_addr(v)
        out.append(Target(a, None if a is not None else str(v)))
    for n in names:
        if n:
            out.append(Target(None, str(n)))
    return out


def describe_target(tool: str, inp: dict) -> str:
    """One-line human summary of what the call is about."""
    inp = inp or {}
    ts = input_targets(tool, inp)
    bits = []
    for t in ts[:4]:
        bits.append(S.hexa(t.addr) if t.addr is not None else (t.name or "?"))
    if len(ts) > 4:
        bits.append("+%d" % (len(ts) - 4))
    s = ", ".join(bits)
    extra = None
    if tool == "rename":
        extra = "→ %s" % inp.get("name")
    elif tool == "set_comments":
        extra = "“%s”" % str(inp.get("comment", ""))[:60]
    elif tool in ("open_idb", "load_debug_info", "open_dsc"):
        extra = str(inp.get("path", ""))
    elif tool in ("find_string", "xrefs_to_string", "analyze_strings", "get_global_value",
                  "list_globals"):
        extra = "“%s”" % inp.get("query", "")
    elif tool in ("strings", "list_functions", "list_funcs", "local_types", "structs",
                  "search_structs") and inp.get("filter"):
        extra = "filter “%s”" % inp.get("filter")
    elif tool in ("find_bytes", "find_insns", "find_insn_operands"):
        extra = str(inp.get("patterns", ""))[:80]
    elif tool == "search":
        extra = "%s %s" % (inp.get("kind", ""), str(inp.get("targets", ""))[:60])
    elif tool == "tool_help":
        extra = str(inp.get("name", ""))
    elif tool == "tool_catalog":
        extra = str(inp.get("query") or inp.get("category") or "")
    elif tool == "run_script":
        extra = str(inp.get("file") or (inp.get("code") or "").strip().splitlines()[0:1])[:80]
    elif tool == "idamap_search":
        extra = "“%s”%s" % (str(inp.get("query") or "")[:60], " (unexplored)" if inp.get("unexplored_only") else "")
    elif tool == "idamap_annotate":
        extra = "“%s”" % str(inp.get("name_suggestion") or inp.get("summary") or "")[:60]
    elif tool in ("declare_type", "apply_types"):
        extra = str(inp.get("decl") or inp.get("type_name") or "")[:60]
    elif tool == "callgraph":
        extra = "%s depth %s" % (inp.get("direction", "callees"), inp.get("max_depth", 2))
    if extra:
        s = (s + " " + extra).strip()
    return s


# --------------------------------------------------------------------------
# Output-side extraction (PostToolUse)
# --------------------------------------------------------------------------

def _per_target(out: Any, text: str, targets: list[Target]) -> list[tuple[Target, Any, str | None]]:
    """Pair each input target with its payload (or error)."""
    if isinstance(out, dict) and isinstance(out.get("results"), list) and len(targets) != 1:
        pairs = []
        for i, r in enumerate(out["results"]):
            if not isinstance(r, dict):
                continue
            a = parse_addr(r.get("address", r.get("query")))
            t = Target(a) if a is not None else (targets[i] if i < len(targets) else Target(None))
            pairs.append((t, r, r.get("error")))
        return pairs
    payload = out if out is not None else text
    return [(t, payload, None) for t in targets]


def extract(tool: str, inp: dict, resp_text: str, ok: bool = True) -> Facts:
    inp = inp or {}
    f = Facts()
    kind_flag = TARGET_KIND.get(tool)
    if kind_flag:
        f.kind, f.flag = kind_flag
    f.func_start_hint = tool in FUNC_START_TOOLS
    targets = input_targets(tool, inp)
    if not ok:
        f.targets = [Target(t.addr, t.name, ok=False) for t in targets]
        return f

    out = try_json(resp_text)
    pairs = _per_target(out, resp_text, targets)
    f.targets = []
    for t, payload, err in pairs:
        t.ok = err is None
        if err:
            t.detail = str(err)[:200]
        f.targets.append(t)

    # ---- per-tool learning ------------------------------------------------
    if tool in ("open_idb",) and isinstance(out, dict):
        f.db_meta = {
            "idb_path": out.get("path"), "processor": out.get("processor"),
            "bits": out.get("bits"), "file_type": out.get("file_type"),
            "func_total": out.get("function_count"), "input_path": inp.get("path"),
            "workspace_id": out.get("database_id"),
        }
    elif tool == "open_dsc":
        f.db_meta = {"idb_path": (out or {}).get("path") if isinstance(out, dict) else None,
                     "input_path": inp.get("path"), "module": inp.get("module"),
                     "file_type": "DSC"}
        if isinstance(out, dict):
            f.db_meta.update({k: out.get(k) for k in ("processor", "bits")})
            f.db_meta["func_total"] = out.get("function_count")
            f.db_meta["workspace_id"] = out.get("database_id")
    elif tool == "idb_meta" and isinstance(out, dict):
        f.db_meta = {
            "input_path": (out.get("input_file_path") or "").rstrip("\x00") or None,
            "sha256": out.get("sha256"), "md5": out.get("md5"),
            "processor": out.get("processor"), "bits": out.get("bits"),
            "file_type": out.get("file_type"), "func_total": out.get("function_count"),
            "min_ea": out.get("min_address"), "max_ea": out.get("max_address"),
        }
    elif tool == "segments":
        for s in as_list(out):
            if isinstance(s, dict) and parse_addr(s.get("start")) is not None:
                f.segments.append({
                    "name": s.get("name"), "start": parse_addr(s.get("start")),
                    "end": parse_addr(s.get("end")), "perms": s.get("permissions"),
                    "type": s.get("type"),
                })
    elif tool in ("list_functions", "list_funcs"):
        if isinstance(out, dict):
            f.functions = _func_records(out.get("functions"))
            if not inp.get("filter") and isinstance(out.get("total"), int):
                f.db_meta["func_total"] = out["total"]
    elif tool == "export_funcs":
        for key in ("functions", "results", "exports"):
            if isinstance(out, dict) and key in out:
                f.functions = _func_records(out[key])
        if isinstance(out, list):
            f.functions = _func_records(out)
    elif tool == "lookup_funcs" and isinstance(out, dict):
        f.targets = []
        for r in as_list(out.get("results")):
            if isinstance(r, dict):
                rec = _func_record(r.get("result"))
                if rec:
                    f.functions.append(rec)
                    f.targets.append(Target(rec["start"], rec["name"]))
    elif tool in ("function_at", "resolve_function") and isinstance(out, dict):
        rec = _func_record(out)
        if rec:
            f.functions.append(rec)
            f.targets = [Target(rec["start"], rec["name"])]
    elif tool == "addr_info" and isinstance(out, dict):
        rec = _func_record(out.get("function"))
        if rec:
            f.functions.append(rec)
    elif tool == "pseudocode_at":
        for _t, payload, _e in pairs:
            if isinstance(payload, dict):
                rec = _func_record(payload.get("function"))
                if rec:
                    f.functions.append(rec)
    elif tool in ("callers", "callees"):
        key = tool
        for t, payload, err in pairs:
            if err or t.addr is None:
                continue
            items = payload.get(key) if isinstance(payload, dict) else payload
            for rec in _func_records(items):
                f.functions.append(rec)
                f.results.append((rec["start"], "callee" if tool == "callees" else "caller", None))
                f.edges.append((t.addr, rec["start"]) if tool == "callees" else (rec["start"], t.addr))
    elif tool == "callgraph" and isinstance(out, dict):
        recs = _func_records(out.get("nodes"))
        f.functions.extend(recs)
        roots = {t.addr for t in targets}
        for r in recs:
            if r["start"] not in roots:
                f.results.append((r["start"], "graph", None))
        for e in as_list(out.get("edges")):
            if isinstance(e, dict):
                a, b = parse_addr(e.get("from")), parse_addr(e.get("to"))
                if a is not None and b is not None:
                    f.edges.append((a, b))
    elif tool in ("xrefs_to", "xrefs_from"):
        for t, payload, err in pairs:
            if err or not isinstance(payload, dict):
                continue
            for x in as_list(payload.get("xrefs")):
                if not isinstance(x, dict):
                    continue
                a, b = parse_addr(x.get("from")), parse_addr(x.get("to"))
                if a is None or b is None:
                    continue
                other = a if tool == "xrefs_to" else b
                f.results.append((other, "xref", str(x.get("type") or "")))
                if "Call" in str(x.get("type", "")):
                    f.edges.append((a, b))
    elif tool == "xrefs_to_string" and isinstance(out, dict):
        for s in as_list(out.get("strings")):
            if not isinstance(s, dict):
                continue
            content = str(s.get("content", "")).rstrip("\x00")[:120]
            for x in as_list(s.get("xrefs")):
                a = parse_addr(x.get("from") if isinstance(x, dict) else x)
                if a is not None:
                    f.results.append((a, "string_ref", content))
    elif tool == "rename" and isinstance(out, dict):
        a = parse_addr(out.get("address"))
        new = out.get("name") or inp.get("name")
        if new:
            f.renames.append((a, inp.get("current_name"), str(new)))
            if a is not None:
                f.targets = [Target(a)]
    elif tool == "set_comments":
        a = parse_addr(out.get("address")) if isinstance(out, dict) else None
        if a is None and targets:
            a = targets[0].addr
        f.comments.append((a, inp.get("target_name"), str(inp.get("comment", "")),
                           bool(inp.get("repeatable"))))
    elif tool == "decompile":
        for t, payload, err in pairs:
            code = payload.get("decompile") if isinstance(payload, dict) else payload
            if not err and isinstance(code, str) and t.addr is not None:
                n = decompiled_name(code)
                if n:
                    f.stub_names[t.addr] = n
    elif tool == "run_script":
        stdout = out.get("stdout", "") if isinstance(out, dict) else resp_text
        m = re.search(re.escape(EXPORT_MARKER) + r"(.+?) functions=\d+", stdout or "") or \
            re.search(re.escape(EXPORT_MARKER) + r"(\S+)", stdout or "")
        if m:
            f.export_file = m.group(1)
    elif tool in ("find_insns", "find_insn_operands", "find_bytes", "search", "find_string"):
        f.results.extend((a, "search_hit", None) for a in _collect_addrs(out, limit=300))

    return f


def _collect_addrs(v: Any, limit: int, _acc: list | None = None) -> list[int]:
    """Collect ``address``/``ea``/``from`` values from arbitrary JSON (bounded)."""
    acc = [] if _acc is None else _acc
    if len(acc) >= limit:
        return acc
    if isinstance(v, dict):
        for k in ("address", "ea", "from", "match_address"):
            a = parse_addr(v.get(k))
            if a is not None:
                acc.append(a)
                break
        for k, sub in v.items():
            if isinstance(sub, (dict, list)):
                _collect_addrs(sub, limit, acc)
    elif isinstance(v, list):
        for sub in v:
            if isinstance(sub, str):  # e.g. search(kind=text) -> ["0x1000", ...]
                a = parse_addr(sub)
                if a is not None:
                    acc.append(a)
                continue
            _collect_addrs(sub, limit, acc)
            if len(acc) >= limit:
                break
    return acc
