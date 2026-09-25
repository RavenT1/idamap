"""Local web UI + JSON API + live event stream (SSE). Stdlib only."""

from __future__ import annotations

import json
import mimetypes
import re
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from . import parse as P
from . import queries as Q
from . import report
from . import store as S

WEB = Path(__file__).parent / "web"
EXPORT_SCRIPT = Path(__file__).parent / "ida_scripts" / "export_map.py"

_local = threading.local()


def conn():
    c = getattr(_local, "conn", None)
    if c is None:
        c = _local.conn = S.connect()
    return c


class Handler(BaseHTTPRequestHandler):
    server_version = f"idamap/{__version__}"

    def log_message(self, fmt, *args):  # quiet
        pass

    # ---------------------------------------------------------------- helpers
    def _send(self, body: bytes, ctype: str, status: int = 200, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status: int = 200):
        self._send(json.dumps(obj, default=str).encode(), "application/json; charset=utf-8", status)

    def _err(self, status: int, msg: str):
        self._json({"error": msg}, status)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    # ---------------------------------------------------------------- routing
    def do_GET(self):
        u = urlparse(self.path)
        qs = {k: v[-1] for k, v in parse_qs(u.query).items()}
        p = u.path
        try:
            if p == "/api/info":
                return self._json({"version": __version__, "db_path": str(S.db_path()),
                                   "export_script": str(EXPORT_SCRIPT),
                                   "stages": S.STAGES, "human_statuses": Q.HUMAN_STATUSES,
                                   "categories": P.CATEGORIES})
            if p == "/api/dbs":
                return self._json(Q.databases(conn()))
            if p == "/api/live":
                return self._live(qs)
            m = re.fullmatch(r"/api/call/(\d+)", p)
            if m:
                d = Q.call_detail(conn(), int(m.group(1)))
                return self._json(d) if d else self._err(404, "no such call")
            if p == "/api/calls":
                db = int(qs["db"]) if qs.get("db") else None
                return self._json(Q.calls(conn(), db, int(qs.get("before") or 0) or None,
                                          min(int(qs.get("limit") or 300), 2000)))
            m = re.fullmatch(r"/api/db/(\d+)/(summary|functions|graph|report\.md|ida_sync\.py)", p)
            if m:
                db, what = int(m.group(1)), m.group(2)
                if what == "summary":
                    return self._json(Q.summary(conn(), db))
                if what == "functions":
                    return self._json(Q.functions(conn(), db, float(qs["since"]) if qs.get("since") else None))
                if what == "graph":
                    return self._json(Q.graph(conn(), db, qs.get("mode", "touched")))
                name = conn().execute("SELECT name FROM databases WHERE id=?", (db,)).fetchone()
                base = re.sub(r"[^\w.-]+", "_", name[0] if name else "db")
                if what == "report.md":
                    return self._send(report.markdown(conn(), db).encode(), "text/markdown; charset=utf-8",
                                      extra={"Content-Disposition": f'attachment; filename="{base}-idamap.md"'})
                return self._send(report.ida_sync_script(conn(), db).encode(), "text/x-python; charset=utf-8",
                                  extra={"Content-Disposition": f'attachment; filename="{base}-idamap_sync.py"'})
            m = re.fullmatch(r"/api/db/(\d+)/function/(0x[0-9a-fA-F]+)", p)
            if m:
                d = Q.function_detail(conn(), int(m.group(1)), int(m.group(2), 16))
                return self._json(d) if d else self._err(404, "unknown function")
            return self._static(p)
        except BrokenPipeError:
            pass
        except Exception as e:  # noqa: BLE001
            return self._err(500, f"{type(e).__name__}: {e}")

    def do_POST(self):
        p = urlparse(self.path).path
        try:
            body = self._body()
            m = re.fullmatch(r"/api/db/(\d+)/function/(0x[0-9a-fA-F]+)", p)
            if m:
                Q.set_human(conn(), int(m.group(1)), int(m.group(2), 16),
                            status=body.get("human_status"), note=body.get("note"),
                            set_status="human_status" in body, set_note="note" in body)
                return self._json({"ok": True})
            m = re.fullmatch(r"/api/db/(\d+)", p)
            if m and "label" in body:
                conn().execute("UPDATE databases SET label=? WHERE id=?",
                               ((body["label"] or "").strip() or None, int(m.group(1))))
                return self._json({"ok": True})
            return self._err(404, "not found")
        except Exception as e:  # noqa: BLE001
            return self._err(500, f"{type(e).__name__}: {e}")

    def do_DELETE(self):
        m = re.fullmatch(r"/api/db/(\d+)", urlparse(self.path).path)
        if not m:
            return self._err(404, "not found")
        db = int(m.group(1))
        c = conn()
        for t in ("calls", "functions", "touches", "edges", "renames", "comments", "segments"):
            c.execute(f"DELETE FROM {t} WHERE db_id=?", (db,))
        c.execute("UPDATE sessions SET db_id=NULL WHERE db_id=?", (db,))
        c.execute("DELETE FROM databases WHERE id=?", (db,))
        return self._json({"ok": True})

    # ---------------------------------------------------------------- static
    def _static(self, p: str):
        if p in ("", "/"):
            p = "/index.html"
        f = (WEB / p.lstrip("/")).resolve()
        if WEB.resolve() not in f.parents or not f.is_file():
            return self._err(404, "not found")
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self._send(f.read_bytes(), ctype)

    # ---------------------------------------------------------------- SSE
    def _live(self, qs):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        c = conn()
        # Hooks commit a moment after they stamp updated_at, so a row can land
        # "in the past". Re-scan an overlap window and drop what was already sent.
        overlap = 3.0
        cursor = time.time()
        sent: dict[int, float] = {}
        db_sig = f_sig = None
        last_ping = 0.0
        try:
            while True:
                fresh = [(u, row) for u, row in Q.changed_calls(c, cursor - overlap) if sent.get(row["id"]) != u]
                if fresh:
                    for u, row in fresh:
                        sent[row["id"]] = u
                    cursor = max(cursor, max(u for u, _ in fresh))
                    self._event("calls", [row for _, row in fresh])
                    sent = {k: v for k, v in sent.items() if v > cursor - 2 * overlap}
                sig = tuple(c.execute("SELECT count(*), max(last_seen), max(map_imported_at) FROM databases").fetchone())
                if db_sig is not None and sig != db_sig:
                    self._event("dbs", {})
                db_sig = sig
                fs = c.execute("SELECT max(updated_at) FROM functions").fetchone()[0] or 0
                if f_sig is not None and fs != f_sig:
                    self._event("functions", {"since": f_sig - overlap})
                f_sig = fs
                if time.time() - last_ping > 15:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    last_ping = time.time()
                time.sleep(0.4)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def _event(self, name: str, data):
        self.wfile.write(f"event: {name}\ndata: {json.dumps(data, default=str)}\n\n".encode())
        self.wfile.flush()


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False) -> None:
    S.connect().close()  # create schema
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    url = f"http://{host}:{port}/"
    print(f"idamap {__version__} — {url}  (db: {S.db_path()})")
    if open_browser:
        import webbrowser
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
