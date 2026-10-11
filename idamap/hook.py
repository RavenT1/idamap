"""Claude Code hook entry point: ``python -m idamap.hook`` (reads the event on stdin).

It must never break the tool call it observes: every failure is swallowed,
logged to ``~/.idamap/hook_errors.log`` and the process exits 0 with no output.
"""

from __future__ import annotations

import json
import sys
import time
import traceback


def main() -> int:
    raw = ""
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
        from . import ingest, store

        conn = store.connect()
        try:
            ingest.handle(conn, payload)
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 — observer must be invisible
        try:
            from . import store

            # What failed, never what was in the event: it carries your prompt and the binary's output.
            try:
                event = json.loads(raw)
                what = {k: event.get(k) for k in ("hook_event_name", "tool_name")}
            except Exception:  # noqa: BLE001
                what = {}
            store.append_log("hook_errors.log", f"--- {time.strftime('%Y-%m-%d %H:%M:%S')}\n{traceback.format_exc()}\n"
                                                f"event: {what} ({len(raw)} bytes, content not logged)\n")
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
