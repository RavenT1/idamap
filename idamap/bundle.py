"""App-bundle awareness.

iOS / macOS apps spread their code over several Mach-O files: the main executable plus
``Frameworks/*.framework``. A function in one binary is often a thin stub that forwards to a
symbol living in another one, and a model that does not know this burns calls rediscovering it.

This module groups the binaries of one app (by path), tells which of them idamap has already
analyzed, and resolves an imported symbol to the bundled framework that defines it.
"""

from __future__ import annotations

import os
import plistlib
import re
from pathlib import Path

MAX_MEMBERS = 300

# Swift mangling: $s<len><Module>... (optionally after a stdlib extension prefix such as $sSa)
_SWIFT_MOD = re.compile(r"^_*\$[sS](?:S[a-zA-Z])?(\d+)([A-Za-z_][A-Za-z0-9_]*)")


def swift_module(symbol: str) -> str | None:
    """Module name encoded in a mangled Swift symbol, or None."""
    m = _SWIFT_MOD.match(symbol or "")
    if not m:
        return None
    n = int(m.group(1))
    mod = m.group(2)[:n]
    return mod if len(mod) == n else None


def app_root(path: str | None) -> Path | None:
    """Outermost ``*.app`` directory containing ``path``."""
    if not path:
        return None
    for parent in reversed(Path(path).parents):
        if parent.suffix.lower() == ".app":
            return parent
    return None


def _plist_executable(d: Path) -> str | None:
    for rel in ("Info.plist", "Contents/Info.plist", "Resources/Info.plist", "Versions/A/Resources/Info.plist"):
        try:
            with open(d / rel, "rb") as fh:
                value = plistlib.load(fh).get("CFBundleExecutable")
            if value:
                return str(value)
        except Exception:  # noqa: BLE001 — missing / unreadable / malformed plist
            continue
    return None


def scan(root: Path) -> list[dict]:
    """Main executable and bundled frameworks found on disk (best effort)."""
    out: list[dict] = []
    main = _plist_executable(root) or root.stem
    for cand in (root / main, root / "Contents" / "MacOS" / main):
        try:
            if cand.is_file():
                out.append({"name": main, "kind": "main", "path": str(cand)})
                break
        except OSError:
            continue
    for fw_dir in (root / "Frameworks", root / "Contents" / "Frameworks"):
        try:
            dirs = sorted(fw_dir.glob("*.framework"))[:MAX_MEMBERS]
        except OSError:
            continue
        for d in dirs:
            exe = _plist_executable(d) or d.stem
            out.append({"name": d.stem, "kind": "framework", "path": str(d / exe)})
    return out


def _like_prefix(prefix: str) -> str:
    return prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def bundle_info(conn, db_id: int) -> dict | None:
    """The app this database belongs to and the state of every binary in it."""
    row = conn.execute("SELECT id, name, input_path, idb_path, key FROM databases WHERE id=?", (db_id,)).fetchone()
    if row is None:
        return None
    root = app_root(row["input_path"]) or app_root(row["idb_path"]) or app_root(row["key"])
    if root is None:
        return None
    try:
        members = scan(root)
    except OSError:
        members = []
    recorded = {}
    for r in conn.execute(
            "SELECT id, name, input_path, func_total, map_imported_at FROM databases "
            "WHERE input_path LIKE ? ESCAPE '\\'", (_like_prefix(str(root) + os.sep),)):
        recorded[os.path.normpath(r["input_path"])] = r
    seen = set()
    for m in members:
        r = recorded.get(os.path.normpath(m["path"]))
        seen.add(os.path.normpath(m["path"]))
        m["analyzed"] = r is not None
        m["db_id"] = r["id"] if r else None
        m["mapped"] = bool(r and r["map_imported_at"])
        m["functions"] = r["func_total"] if r else None
        m["current"] = r is not None and r["id"] == db_id
    for path, r in recorded.items():  # recorded in idamap but gone from disk / not scanned
        if path in seen:
            continue
        base = os.path.basename(path)
        members.append({"name": base, "kind": "binary", "path": path, "analyzed": True, "db_id": r["id"],
                        "mapped": bool(r["map_imported_at"]), "functions": r["func_total"], "current": r["id"] == db_id})
    return {"app": root.stem, "root": str(root), "members": members[:MAX_MEMBERS]}


class Index:
    """Resolve symbols to bundle members."""

    def __init__(self, info: dict | None):
        self.members = {}
        self.own = None
        for m in (info or {}).get("members", []):
            self.members.setdefault(m["name"], m)
            if m.get("current"):
                self.own = m["name"]
        names = sorted((n for n in self.members if len(n) >= 3), key=len, reverse=True)
        self._rx = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(re.escape(n) for n in names) + r")\.") if names else None

    def __bool__(self) -> bool:
        return bool(self.members)

    def modules_in(self, values) -> list[str]:
        """Bundle members (other than the current binary) the given symbol names point into."""
        found: list[str] = []
        for v in values:
            if not v:
                continue
            cands = []
            mod = swift_module(v)
            if mod:
                cands.append(mod)
            if self._rx:
                cands.extend(self._rx.findall(v))
            for c in cands:
                if c in self.members and c != self.own and c not in found:
                    found.append(c)
        return found

    def describe(self, name: str, with_path: bool = True) -> dict:
        m = self.members[name]
        d = {"name": name, "status": "analyzed in idamap" if m.get("analyzed") else "not analyzed yet"}
        if with_path and not m.get("analyzed"):
            d["binary"] = m["path"]
        return d

    def unanalyzed_paths(self, names) -> dict:
        """name -> binary path for the given members that idamap has not analyzed (listed once per answer)."""
        return {n: self.members[n]["path"] for n in names if n in self.members and not self.members[n].get("analyzed")}
