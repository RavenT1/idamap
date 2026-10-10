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

            log = store.ensure_home() / "hook_errors.log"
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(f"--- {time.strftime('%Y-%m-%d %H:%M:%S')}\n{traceback.format_exc()}\n"
                         f"payload: {raw[:2000]}\n")
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
