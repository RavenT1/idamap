"""User settings (~/.idamap/config.json). Every enrichment feature is opt-in."""

from __future__ import annotations

import json

from . import store as S

DEFAULTS = {
    # the MCP proxy adds idamap_annotate / idamap_lookup / idamap_search / idamap_status tools
    # so the LLM can record and reuse what it understood, and navigate the binary
    "annotate_tools": False,
    # with the tools on, the first idamap_search / idamap_status call indexes the whole binary by
    # running idamap's own (read-only) export script inside ida-mcp, so the tools are useful at once
    "auto_map": True,
}

DESCRIPTIONS = {
    "auto_map": "With the idamap tools on, index the whole binary automatically on first use (runs idamap's read-only export script in ida-mcp)",
    "annotate_tools": "Proxy exposes idamap_annotate / idamap_lookup / idamap_search / idamap_status to the LLM",
}


def _path():
    return S.home() / "config.json"


def load() -> dict:
    cfg = dict(DEFAULTS)
    try:
        cfg.update({k: v for k, v in json.loads(_path().read_text()).items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    return cfg


def get(key: str):
    return load()[key]


def set_value(key: str, value) -> dict:
    if key not in DEFAULTS:
        raise KeyError(key)
    cfg = load()
    cfg[key] = value
    S.ensure_home()
    p = _path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n")
    tmp.replace(p)
    return cfg
