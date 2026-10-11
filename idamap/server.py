"""Local web UI + JSON API + live event stream (SSE). Stdlib only."""

from __future__ import annotations

import gzip
import hmac
import json
import mimetypes
import os
import re
import secrets
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, annotate, compliance, config
from . import parse as P
from . import queries as Q
from . import report
from . import store as S

WEB = Path(__file__).parent / "web"


def _clean(value) -> str:
    """A response header value can never carry a line break (it would end the header and start another)."""
    return str(value).replace("\r", " ").replace("\n", " ")
EXPORT_SCRIPT = Path(__file__).parent / "ida_scripts" / "export_map.py"

_local = threading.local()

MAX_BODY = 1 << 20  # the UI only ever writes short JSON (a note, a status): refuse anything bigger

# Sent with every response. The UI renders text that comes from analysed binaries and from the model, so it
# gets a strict policy (no inline script, no foreign origins) and may not be framed (clickjacking the
# "delete records" button).
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
                                "frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class _TooLarge(Exception):
    pass


def conn():
    c = getattr(_local, "conn", None)
    if c is None:
        c = _local.conn = S.connect()
    return c


class Handler(BaseHTTPRequestHandler):
    server_version = f"idamap/{__version__}"

    def log_message(self, fmt, *args):  # quiet
        pass

    def finish(self):
        try:
            super().finish()
        finally:  # one short-lived thread per request: don't leave its connection to the GC
            c = getattr(_local, "conn", None)
            if c is not None:
                c.close()
                _local.conn = None

    # ---------------------------------------------------------------- helpers
    def _send(self, body: bytes, ctype: str, status: int = 200, extra: dict | None = None):
        # big payloads (the full function list of a 100k-function binary is >10 MB of JSON) compress ~5-10x
        if len(body) > 64 * 1024 and "gzip" in (self.headers.get("Accept-Encoding") or ""):
            body = gzip.compress(body, compresslevel=5)
            extra = {**(extra or {}), "Content-Encoding": "gzip", "Vary": "Accept-Encoding"}
        self.send_response(status)
        self.send_header("Content-Type", _clean(ctype))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in {**SECURITY_HEADERS, **(extra or {})}.items():
            self.send_header(k, _clean(v))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status: int = 200):
        self._send(json.dumps(obj, default=str).encode(), "application/json; charset=utf-8", status)

    def _err(self, status: int, msg: str):
        self._json({"error": msg}, status)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n < 0 or n > MAX_BODY:
            raise _TooLarge
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    # ---------------------------------------------------------------- security
    # The UI is a local tool without accounts. Two browser-borne attacks matter:
    # DNS rebinding (a web page reads the API through an attacker hostname that
    # resolves to 127.0.0.1) and cross-site writes (a page POSTs to localhost).
    # Rejecting foreign Host headers stops the first; requiring a same-origin
    # JSON request for every write stops the second.
    def _allowed_hosts(self) -> set[str] | None:
        host, port = self.server.server_address[:2]
        if host in ("0.0.0.0", "::"):
            return None  # user opted into LAN exposure (serve warns about it)
        names = {host, "localhost", "127.0.0.1", "[::1]", "::1"}
        return {f"{n}:{port}" for n in names} | {n for n in names if port == 80}

    def _token_ok(self) -> bool:
        """Optional shared secret: `idamap serve --token`, always on when listening beyond localhost.

        The first visit carries it in the URL (?token=...); it is then kept in a cookie scoped to this port, so
        the page, its API calls and the event stream need nothing else."""
        token = getattr(self.server, "token", None)
        if not token:
            return True
        name = f"idamap_token_{self.server.server_address[1]}"
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie") or "")
        except Exception:  # noqa: BLE001 — a malformed Cookie header is just "no cookie"
            pass
        if name in jar and hmac.compare_digest(jar[name].value, token):
            return True
        u = urlparse(self.path)
        given = (parse_qs(u.query).get("token") or [""])[-1]
        if self.command == "GET" and u.path in ("", "/") and given and hmac.compare_digest(given, token):
            self.send_response(302)
            self.send_header("Set-Cookie", _clean(f"{name}={token}; Path=/; HttpOnly; SameSite=Strict"))
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, _clean(v))
            self.end_headers()
            return False
        self._err(401, "token required: open the URL printed by `idamap serve`")
        return False

    def _guard(self, write: bool) -> bool:
        allowed = self._allowed_hosts()
        hosthdr = (self.headers.get("Host") or "").lower()
        if allowed is not None and hosthdr not in allowed:
            self._err(403, "forbidden host")
            return False
        if not self._token_ok():
            return False
        if write:
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc.lower() != hosthdr:
                self._err(403, "cross-origin write refused")
                return False
            if self.command == "POST" and not (self.headers.get("Content-Type") or "").startswith("application/json"):
                self._err(415, "application/json required")
                return False
        return True

    # ---------------------------------------------------------------- routing
    def do_GET(self):
        if not self._guard(write=False):
            return
        u = urlparse(self.path)
        qs = {k: v[-1] for k, v in parse_qs(u.query).items()}
        p = u.path
        try:
            if p == "/api/config":
                return self._json({"values": config.load(), "descriptions": config.DESCRIPTIONS})
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
            m = re.fullmatch(r"/api/db/(\d+)/(summary|compliance|functions|graph|report\.md|ida_sync\.py)", p)
            if m:
                db, what = int(m.group(1)), m.group(2)
                if what == "summary":
                    return self._json(Q.summary(conn(), db))
                if what == "compliance":
                    return self._json(compliance.compute(conn(), db))
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
        if not self._guard(write=True):
            return
        p = urlparse(self.path).path
        try:
            body = self._body()
            if p == "/api/config":
                if body.get("key") not in config.DEFAULTS or not isinstance(body.get("value"), bool):
                    return self._err(400, "expected {key, value: bool}")
                return self._json({"values": config.set_value(body["key"], body["value"])})
            m = re.fullmatch(r"/api/db/(\d+)/annotation/(\d+)", p)
            if m:
                ok = annotate.set_status(conn(), int(m.group(1)), int(m.group(2)), str(body.get("status")))
                return self._json({"ok": ok}, 200 if ok else 400)
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
        except _TooLarge:
            return self._err(413, "request body too large")
        except Exception as e:  # noqa: BLE001
            return self._err(500, f"{type(e).__name__}: {e}")

    def do_DELETE(self):
        if not self._guard(write=True):
            return
        m = re.fullmatch(r"/api/db/(\d+)", urlparse(self.path).path)
        if not m:
            return self._err(404, "not found")
        delete_database(conn(), int(m.group(1)))
        return self._json({"ok": True})

    # ---------------------------------------------------------------- static
    def _static(self, p: str):
        if p in ("", "/"):
            p = "/index.html"
        root = os.path.realpath(WEB)
        path = os.path.realpath(os.path.join(root, p.lstrip("/")))
        if not path.startswith(root + os.sep) or not os.path.isfile(path):
            return self._err(404, "not found")
        f = Path(path)
        # explicit types: on Windows mimetypes reads the registry and may say text/plain for .js
        ctype = {".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml"}.get(
            f.suffix) or mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        if ctype.startswith("text/"):
            ctype += "; charset=utf-8"
        self._send(f.read_bytes(), ctype)

    # ---------------------------------------------------------------- SSE
    def _live(self, qs):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, _clean(v))
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


def delete_database(c, db: int) -> None:
    """Forget everything idamap recorded for one database (the IDA database itself is untouched)."""
    c.execute("DELETE FROM call_aliases WHERE call_id IN (SELECT id FROM calls WHERE db_id=?)", (db,))
    for t in ("calls", "functions", "touches", "edges", "renames", "comments", "segments", "func_refs", "annotations",
              "workspace_ids", "db_aliases"):
        c.execute(f"DELETE FROM {t} WHERE db_id=?", (db,))
    c.execute("UPDATE sessions SET db_id=NULL WHERE db_id=?", (db,))
    c.execute("DELETE FROM databases WHERE id=?", (db,))
    c.execute("DELETE FROM prompts WHERE id NOT IN (SELECT DISTINCT prompt_id FROM calls WHERE prompt_id IS NOT NULL)")
    c.execute("DELETE FROM sessions WHERE id NOT IN (SELECT DISTINCT session_id FROM calls)")


def serve(host: str = "127.0.0.1", port: int = 8777, open_browser: bool = False, token: bool = False) -> None:
    S.connect().close()  # create schema
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    beyond = host not in ("127.0.0.1", "localhost", "::1")
    httpd.token = secrets.token_urlsafe(24) if (token or beyond) else None  # type: ignore[attr-defined]
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{shown}:{port}/" + (f"?token={httpd.token}" if httpd.token else "")  # type: ignore[attr-defined]
    print(f"idamap {__version__} — {url}  (db: {S.db_path()})", flush=True)
    if httpd.token:  # type: ignore[attr-defined]
        print("Access needs the token in this URL (a random one per run); it is kept in a cookie afterwards.", flush=True)
    if beyond:
        print("WARNING: listening beyond localhost. Anyone who can reach this port and has the token can read your "
              "research data and the code snippets in it; the connection is not encrypted.", flush=True)
    if open_browser:
        import webbrowser
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
