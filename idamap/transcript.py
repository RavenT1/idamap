"""Read context out of a Claude Code transcript (JSONL).

* ``intent_for`` — the assistant's own words right before a tool call
  ("Let me look at the XOR routine…"). This is what makes a timeline readable
  for a human: *why* the model looked at something, not only *what*.
* ``prompt_text`` — the user prompt a call belongs to.

Both are best-effort: any failure returns None and never blocks the hook.
"""

from __future__ import annotations

import json
import os

TAIL_BYTES = 2 * 1024 * 1024
MAX_INTENT = 700


def _tail_lines(path: str, nbytes: int = TAIL_BYTES) -> list[str]:
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        if size > nbytes:
            fh.seek(size - nbytes)
            fh.readline()  # drop partial line
        data = fh.read()
    return data.decode("utf-8", "replace").splitlines()


def _is_real_prompt(entry: dict) -> bool:
    if entry.get("type") != "user" or entry.get("isMeta"):
        return False
    content = (entry.get("message") or {}).get("content")
    if isinstance(content, str):
        return True
    if isinstance(content, list):
        return any(isinstance(b, dict) and b.get("type") == "text" for b in content) and not any(
            isinstance(b, dict) and b.get("type") == "tool_result" for b in content)
    return False


def intent_for(transcript_path: str | None, tool_use_id: str | None) -> str | None:
    """Nearest assistant text preceding ``tool_use_id`` within the same prompt.

    Returns None when the tool_use is not in the transcript yet. Claude Code
    writes the current assistant message only after PreToolUse fires, so
    guessing from "the latest text" would attach the *previous* call's intent.
    """
    if not transcript_path or not os.path.exists(transcript_path):
        return None
    try:
        entries = []
        for line in _tail_lines(transcript_path):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
        idx = None
        if tool_use_id:
            for i in range(len(entries) - 1, -1, -1):
                content = (entries[i].get("message") or {}).get("content")
                if isinstance(content, list) and any(
                        isinstance(b, dict) and b.get("id") == tool_use_id for b in content):
                    idx = i + 1
                    break
        if idx is None:
            return None
        for i in range(idx - 1, -1, -1):
            e = entries[i]
            if _is_real_prompt(e):
                return None
            if e.get("type") == "user":
                # a tool_result means an earlier round ended: text before it
                # belongs to earlier calls, not this one
                c = (e.get("message") or {}).get("content")
                if isinstance(c, list) and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c):
                    return None
                continue
            if e.get("type") != "assistant":
                continue
            content = (e.get("message") or {}).get("content")
            if not isinstance(content, list):
                continue
            texts = [b.get("text", "") for b in content
                     if isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip()]
            if texts:
                t = texts[-1].strip()
                return t if len(t) <= MAX_INTENT else t[:MAX_INTENT].rstrip() + "…"
    except OSError:
        return None
    return None


def prompt_text(transcript_path: str | None, prompt_id: str | None) -> str | None:
    if not transcript_path or not prompt_id or not os.path.exists(transcript_path):
        return None
    try:
        with open(transcript_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if prompt_id not in line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("promptId") != prompt_id or not _is_real_prompt(e):
                    continue
                content = e["message"]["content"]
                if isinstance(content, list):
                    content = "\n".join(b.get("text", "") for b in content
                                        if isinstance(b, dict) and b.get("type") == "text")
                return content.strip()[:4000]
    except OSError:
        return None
    return None
