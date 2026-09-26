"""User settings (~/.idamap/config.json). Every enrichment feature is opt-in."""

from __future__ import annotations

import json

from . import store as S

DEFAULTS = {
    # the MCP proxy adds idamap_annotate / idamap_lookup tools so the LLM
    # can record (and later re-read) what it understood about a function
    "annotate_tools": False,
}

DESCRIPTIONS = {
    "annotate_tools": "Proxy exposes idamap_annotate / idamap_lookup so the LLM can record and reuse function explanations",
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
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n")
    tmp.replace(p)
    return cfg
