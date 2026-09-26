# idamap — full map export (IDAPython).
#
# Dumps every function, every call edge and the segment layout of the open
# database to JSON so idamap can show the *whole* binary, not only the parts
# the LLM happened to list.
#
# Two ways to run it:
#   * through ida-mcp:   run_script(file="<this file>")
#     The idamap hook sees the IDAMAP_EXPORT_FILE= line and imports it
#     automatically. Only one short line goes back into the LLM context.
#   * in IDA GUI:        File > Script file…, then `idamap import <json>`
#
# Output: $IDAMAP_HOME/exports/<idb name>-<sha8>.json (default ~/.idamap).

import json
import os
import time
import warnings

warnings.simplefilter("ignore", DeprecationWarning)

import ida_funcs
import ida_loader
import ida_name
import ida_nalt
import ida_segment
import ida_xref
import idautils
import idc

try:
    import ida_ida

    def _minmax():
        return ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()

    def _procname():
        return ida_ida.inf_get_procname()

    def _bits():
        return 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
except Exception:  # older IDA
    import idaapi

    def _minmax():
        return idaapi.cvar.inf.min_ea, idaapi.cvar.inf.max_ea

    def _procname():
        return idaapi.get_inf_structure().procname

    def _bits():
        return 64 if idaapi.get_inf_structure().is_64bit() else 32


def _hex(b):
    return b.hex() if isinstance(b, (bytes, bytearray)) else None


REF_BUDGET_SECS = 240      # stop collecting references on huge binaries (map stays complete)
REFS_PER_KIND = 25


def _seg(ea):
    s = ida_segment.getseg(ea)
    return ida_segment.get_segm_name(s) if s else ""


def _demangle(name):
    try:
        d = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM) or ida_name.demangle_name(name, 0)
    except Exception:
        d = None
    return d if d and d != name else None


def _funcs_referencing(ea, depth=2):
    """Functions whose code references ea, directly or through one data item
    (cfstring -> cstring, selref -> methname, GOT -> import)."""
    out = set()
    for x in idautils.XrefsTo(ea, 0):
        f = ida_funcs.get_func(x.frm)
        if f:
            out.add(f.start_ea)
        elif depth > 1:
            out |= _funcs_referencing(idc.get_item_head(x.frm), depth - 1)
        if len(out) > 400:  # hugely shared item (e.g. a common selector): enough
            break
    return out


def collect_refs(deadline):
    refs = {}
    counts = {}

    def add(f, kind, value):
        k = (f, kind)
        if counts.get(k, 0) >= REFS_PER_KIND:
            return
        bucket = refs.setdefault(f, set())
        if (kind, value) not in bucket:
            bucket.add((kind, value))
            counts[k] = counts.get(k, 0) + 1

    complete = True
    for s in idautils.Strings():
        if time.time() > deadline:
            complete = False
            break
        sg = _seg(s.ea)
        if sg in ("HEADER", "__swift5_reflstr", "__swift5_typeref", "__swift5_fieldmd"):
            continue
        kind = "sel" if sg == "__objc_methname" else "str"
        text = str(s)[:160]
        for f in _funcs_referencing(s.ea):
            add(f, kind, text)

    def on_import(ea, name, _ord):
        if name and time.time() <= deadline:
            label = _demangle(name) or name  # Swift / C++ imports are unreadable mangled
            for f in _funcs_referencing(ea):
                add(f, "import", label)
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(i, on_import)

    for s_ea in idautils.Segments():
        if _seg(s_ea) != "__objc_classrefs":
            continue
        seg = ida_segment.getseg(s_ea)
        for h in idautils.Heads(seg.start_ea, seg.end_ea):
            name = ida_name.get_name(h) or ""
            cls = name.replace("classRef_", "").replace("_OBJC_CLASS_$_", "")
            for f in _funcs_referencing(h, 1):
                add(f, "class", cls)
    return {"%d" % f: sorted(v) for f, v in refs.items()}, complete and time.time() <= deadline


def main():
    started = time.time()
    funcs = []
    starts = set()
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        name = ida_funcs.get_func_name(f.start_ea) or ("sub_%X" % f.start_ea)
        funcs.append([f.start_ea, f.end_ea, name, _demangle(name), 1 if f.flags & ida_funcs.FUNC_LIB else 0])
        starts.add(f.start_ea)

    edges = set()
    for callee in starts:
        for x in idautils.XrefsTo(callee, 0):
            if not x.iscode or x.type not in (ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_JN, ida_xref.fl_JF):
                continue
            caller = ida_funcs.get_func(x.frm)
            if caller and caller.start_ea != callee:
                edges.add((caller.start_ea, callee))

    segs = []
    for s_ea in idautils.Segments():
        s = ida_segment.getseg(s_ea)
        perms = "".join(c if s.perm & m else "-" for c, m in (("r", 4), ("w", 2), ("x", 1)))
        segs.append({"name": ida_segment.get_segm_name(s), "start": s.start_ea, "end": s.end_ea,
                     "perms": perms, "type": {2: "CODE", 3: "DATA", 4: "BSS", 1: "XTRN"}.get(s.type, str(s.type))})

    refs, refs_complete = collect_refs(started + REF_BUDGET_SECS)

    lo, hi = _minmax()
    sha = _hex(ida_nalt.retrieve_input_file_sha256())
    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    data = {
        "version": 1,
        "exported_at": time.time(),
        "idb_path": idb_path,
        "input_path": ida_nalt.get_input_file_path(),
        "sha256": sha,
        "md5": _hex(ida_nalt.retrieve_input_file_md5()),
        "processor": _procname(),
        "bits": _bits(),
        "min_ea": "0x%x" % lo,
        "max_ea": "0x%x" % hi,
        "segments": segs,
        "functions": funcs,
        "edges": sorted(edges),
        "refs": refs,
        "refs_complete": refs_complete,
    }
    out_dir = os.path.join(os.environ.get("IDAMAP_HOME") or os.path.expanduser("~/.idamap"), "exports")
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(idb_path or "idb"))[0]
    path = os.path.join(out_dir, "%s-%s.json" % (base, (sha or "nosha")[:8]))
    with open(path, "w") as fh:
        json.dump(data, fh)
    print("IDAMAP_EXPORT_FILE=%s functions=%d edges=%d refs=%d%s (%.1fs)"
          % (path, len(funcs), len(edges), sum(len(v) for v in refs.values()),
             "" if refs_complete else " (refs truncated: time budget)", time.time() - started))


main()
