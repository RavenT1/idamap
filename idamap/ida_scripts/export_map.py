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


def main():
    started = time.time()
    funcs = []
    starts = set()
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        funcs.append([f.start_ea, f.end_ea, ida_funcs.get_func_name(f.start_ea) or ("sub_%X" % f.start_ea)])
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
    }
    out_dir = os.path.join(os.environ.get("IDAMAP_HOME") or os.path.expanduser("~/.idamap"), "exports")
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(idb_path or "idb"))[0]
    path = os.path.join(out_dir, "%s-%s.json" % (base, (sha or "nosha")[:8]))
    with open(path, "w") as fh:
        json.dump(data, fh)
    print("IDAMAP_EXPORT_FILE=%s functions=%d edges=%d segments=%d (%.1fs)"
          % (path, len(funcs), len(edges), len(segs), time.time() - started))


main()
