"""Harness-agnostic capture: a transparent MCP proxy in front of ida-mcp.

Any MCP client (Cursor, Codex, Claude Desktop, Gemini CLI, VS Code, Windsurf,
Zed, Cline, Claude Code, ...) can be pointed at the proxy instead of ida-mcp:

* stdio:  command ``idamap proxy -- ida-mcp [args]`` instead of ``ida-mcp [args]``
* HTTP:   ``idamap proxy --listen 127.0.0.1:8766 --upstream http://127.0.0.1:8765/``
          in front of ``ida-mcp serve-http``; the client uses the listen URL.

Bytes are forwarded first and observed afterwards; recording happens on a
separate thread through a queue. A parsing or database failure can never
delay, alter or break the MCP stream.
"""

from __future__ import annotations

import http.client
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import store as S

# clientInfo.name -> short harness label
_HARNESS_HINTS = [
    ("claude-code", "claude-code"), ("claude-ai", "claude-desktop"), ("claude", "claude"),
    ("codex", "codex"), ("cursor", "cursor"), ("windsurf", "windsurf"), ("gemini", "gemini-cli"),
    ("visual studio code", "vscode"), ("vscode", "vscode"), ("copilot", "vscode"), ("zed", "zed"),
    ("cline", "cline"), ("roo", "roo-code"), ("continue", "continue"), ("goose", "goose"),
    ("opencode", "opencode"), ("amp", "amp"), ("crush", "crush"), ("qwen", "qwen-code"),
    ("lm studio", "lm-studio"), ("jetbrains", "jetbrains"),
]


def harness_name(client_info: dict | None) -> str:
    name = str((client_info or {}).get("name") or "").strip()
    low = name.lower()
    for needle, label in _HARNESS_HINTS:
        if needle in low:
            return label
    return low or "mcp-client"


def _log_error(where: str) -> None:
    try:
        log = S.home() / "proxy_errors.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(f"--- {time.strftime('%Y-%m-%d %H:%M:%S')} {where}\n{traceback.format_exc()}\n")
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------
# Recording (own thread, own SQLite connection)
# --------------------------------------------------------------------------

class Recorder:
    def __init__(self, source: str):
        self.source = source
        self.q: queue.Queue = queue.Queue()
        self.t = threading.Thread(target=self._run, name="idamap-recorder", daemon=True)
        self.t.start()

    def put(self, kind: str, payload: dict) -> None:
        self.q.put((kind, payload))

    def close(self, timeout: float = 5.0) -> None:
        self.q.put(None)
        self.t.join(timeout)

    def _run(self) -> None:
        from . import ingest

        conn = None
        while True:
            item = self.q.get()
            if item is None:
                return
            kind, p = item
            try:
                if conn is None:
                    conn = S.connect()
                if kind == "pre":
                    ingest.on_pre(conn, p)
                else:
                    ingest.on_post(conn, p, ok=(kind == "ok"))
            except Exception:  # noqa: BLE001
                _log_error(f"record {kind} {p.get('tool_name')}")


# --------------------------------------------------------------------------
# JSON-RPC observation
# --------------------------------------------------------------------------

def _text_of(result: dict) -> str:
    parts = []
    for b in result.get("content") or []:
        if isinstance(b, dict) and b.get("type") == "text":
            parts.append(b.get("text", ""))
    if not parts and "structuredContent" in result:
        parts.append(json.dumps(result["structuredContent"]))
    return "\n".join(parts)


class Observer:
    """Pairs tools/call requests with their responses, per session."""

    def __init__(self, recorder: Recorder, harness_override: str | None = None):
        self.rec = recorder
        self.override = harness_override
        self.pending: dict[tuple[str, str], tuple] = {}
        self.harness: dict[str, str] = {}
        self.lock = threading.Lock()
        self.cwd = os.getcwd()

    def _payload(self, session: str, key: str, name: str, args: dict, host_id: str | None = None) -> dict:
        p = {"session_id": session, "tool_use_id": f"{session}:{key}", "tool_name": f"mcp__ida__{name}",
             "tool_input": args, "harness": self.override or self.harness.get(session, "mcp-client"),
             "source": self.rec.source, "cwd": self.cwd}
        if host_id:
            p["host_tool_use_id"] = host_id  # e.g. Claude Code's toolu_… id, for exact hook dedupe
        return p

    def client_message(self, session: str, msg) -> None:
        for m in msg if isinstance(msg, list) else [msg]:
            if not isinstance(m, dict):
                continue
            method = m.get("method")
            params = m.get("params") or {}
            meta = params.get("_meta") or {}
            if method == "initialize":  # MCP <= 2025
                self.harness[session] = harness_name(params.get("clientInfo"))
            elif isinstance(meta.get("io.modelcontextprotocol/clientInfo"), dict):
                # MCP 2026-07-28 is handshake-free: clientInfo rides on every request
                self.harness[session] = harness_name(meta["io.modelcontextprotocol/clientInfo"])
            if method == "tools/call" and "id" in m:
                key = json.dumps(m["id"])
                name, args = str(params.get("name", "?")), params.get("arguments") or {}
                host_id = meta.get("claudecode/toolUseId")
                with self.lock:
                    self.pending[(session, key)] = (name, args, time.time(), host_id)
                self.rec.put("pre", self._payload(session, key, name, args, host_id))
            elif method == "notifications/cancelled":
                key = json.dumps(params.get("requestId"))
                with self.lock:
                    p = self.pending.pop((session, key), None)
                if p:
                    self._finish(session, key, p, None, "cancelled by client")

    def server_message(self, session: str, msg) -> None:
        if not self.pending:
            return
        for m in msg if isinstance(msg, list) else [msg]:
            if not isinstance(m, dict) or "id" not in m or ("result" not in m and "error" not in m):
                continue
            key = json.dumps(m["id"])
            with self.lock:
                p = self.pending.pop((session, key), None)
            if not p:
                continue
            if "error" in m:
                err = m["error"] or {}
                self._finish(session, key, p, None, f"{err.get('message', 'error')} (code {err.get('code')})")
                continue
            result = m.get("result") or {}
            text = _text_of(result)
            if result.get("isError"):
                self._finish(session, key, p, None, text or "tool reported isError")
            else:
                self._finish(session, key, p, text, None)

    def _finish(self, session, key, p, text, error) -> None:
        name, args, t0, host_id = p
        payload = self._payload(session, key, name, args, host_id)
        payload["duration_ms"] = int((time.time() - t0) * 1000)
        if error is None:
            payload["tool_response"] = [{"type": "text", "text": text or ""}]
            self.rec.put("ok", payload)
        else:
            payload["error"] = error
            self.rec.put("error", payload)

    def abandon(self, session: str, reason: str) -> None:
        """Server went away with calls in flight."""
        with self.lock:
            left = [(k, v) for k, v in self.pending.items() if k[0] == session]
            for k, _ in left:
                del self.pending[k]
        for (sess, key), p in left:
            self._finish(sess, key, p, None, reason)


def _parse(data: bytes):
    data = data.strip()
    if not data or data[:1] not in (b"{", b"["):
        return None
    try:
        return json.loads(data)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# stdio proxy
# --------------------------------------------------------------------------

def run_stdio(cmd: list[str], harness: str | None = None) -> int:
    if not cmd:
        cmd = ["ida-mcp"]
    exe = shutil.which(cmd[0]) or cmd[0]
    session = f"stdio-{uuid.uuid4().hex[:12]}"
    rec = Recorder("proxy-stdio")
    obs = Observer(rec, harness)
    try:
        child = subprocess.Popen([exe, *cmd[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    except OSError as e:
        sys.stderr.write(f"idamap proxy: cannot start {cmd!r}: {e}\n")
        return 127

    def stop(*_):
        try:
            child.terminate()
        except OSError:
            pass

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, stop)
        except (ValueError, OSError):
            pass

    def client_to_server():
        src = sys.stdin.buffer
        try:
            while True:
                line = src.readline()
                if not line:
                    break
                child.stdin.write(line)
                child.stdin.flush()
                try:
                    msg = _parse(line)
                    if msg is not None:
                        obs.client_message(session, msg)
                except Exception:  # noqa: BLE001
                    _log_error("client message")
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                child.stdin.close()
            except OSError:
                pass

    threading.Thread(target=client_to_server, name="idamap-c2s", daemon=True).start()

    out = sys.stdout.buffer
    try:
        while True:
            line = child.stdout.readline()
            if not line:
                break
            out.write(line)
            out.flush()
            try:
                msg = _parse(line)
                if msg is not None:
                    obs.server_message(session, msg)
            except Exception:  # noqa: BLE001
                _log_error("server message")
    except (BrokenPipeError, OSError):
        stop()
    rc = child.wait()
    obs.abandon(session, f"ida-mcp exited (code {rc}) before responding")
    rec.close()
    return rc


# --------------------------------------------------------------------------
# Streamable-HTTP proxy
# --------------------------------------------------------------------------

_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
        "transfer-encoding", "upgrade", "content-length", "host", "accept-encoding"}


class _SSE:
    """Incremental text/event-stream parser that yields each event's data."""

    def __init__(self):
        self.buf = b""

    def feed(self, chunk: bytes):
        self.buf += chunk.replace(b"\r\n", b"\n")
        while b"\n\n" in self.buf:
            event, self.buf = self.buf.split(b"\n\n", 1)
            data = b"\n".join(l[5:].lstrip() for l in event.split(b"\n") if l.startswith(b"data:"))
            if data:
                yield data


def make_http_proxy(listen: str, upstream: str, harness: str | None = None) -> ThreadingHTTPServer:
    up = urlsplit(upstream)
    if up.scheme not in ("http", "https"):
        raise SystemExit(f"--upstream must be an http(s) URL, got {upstream!r}")
    base = up.path.rstrip("/")
    rec = Recorder("proxy-http")
    obs = Observer(rec, harness)
    anon = f"http-{uuid.uuid4().hex[:8]}"   # stateless mode: no Mcp-Session-Id

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            self._forward("POST")

        def do_GET(self):
            self._forward("GET")

        def do_DELETE(self):
            self._forward("DELETE")

        def do_OPTIONS(self):
            self._forward("OPTIONS")

        def _forward(self, method: str):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
            sid = self.headers.get("Mcp-Session-Id")
            session = f"http-{sid}" if sid else anon
            msg = _parse(body) if body else None
            init_info = None
            if msg is not None:
                try:
                    for m in msg if isinstance(msg, list) else [msg]:
                        if isinstance(m, dict) and m.get("method") == "initialize":
                            init_info = harness_name((m.get("params") or {}).get("clientInfo"))
                    obs.client_message(session, msg)
                except Exception:  # noqa: BLE001
                    _log_error("http client message")

            headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
            headers["Host"] = up.netloc
            conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(up.hostname, up.port, timeout=None)
            try:
                conn.request(method, base + self.path, body=body, headers=headers)
                resp = conn.getresponse()
            except OSError as e:
                self.send_error(502, f"idamap proxy: upstream unreachable: {e}")
                if msg is not None:
                    obs.abandon(session, f"upstream unreachable: {e}")
                return

            new_sid = resp.getheader("Mcp-Session-Id")
            if new_sid and init_info:
                obs.harness[f"http-{new_sid}"] = init_info
            ctype = (resp.getheader("Content-Type") or "").lower()
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in _HOP:
                    self.send_header(k, v)
            observe_session = session
            try:
                if "text/event-stream" in ctype or resp.getheader("Content-Length") is None:
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    sse = _SSE() if "text/event-stream" in ctype else None
                    raw = b""
                    while True:
                        chunk = resp.read1(65536)
                        if not chunk:
                            break
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                        self.wfile.flush()
                        try:
                            if sse:
                                for data in sse.feed(chunk):
                                    m = _parse(data)
                                    if m is not None:
                                        obs.server_message(observe_session, m)
                            elif len(raw) < 64 * 1024 * 1024:
                                raw += chunk
                        except Exception:  # noqa: BLE001
                            _log_error("http sse")
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                    if raw:
                        m = _parse(raw)
                        if m is not None:
                            obs.server_message(observe_session, m)
                else:
                    data = resp.read()
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    self.wfile.flush()
                    try:
                        m = _parse(data)
                        if m is not None:
                            obs.server_message(observe_session, m)
                    except Exception:  # noqa: BLE001
                        _log_error("http json")
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                conn.close()

    host, _, port = listen.rpartition(":")
    httpd = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    httpd.daemon_threads = True
    httpd.recorder = rec  # type: ignore[attr-defined]
    return httpd


def run_http(listen: str, upstream: str, harness: str | None = None) -> int:
    httpd = make_http_proxy(listen, upstream, harness)
    sys.stderr.write(f"idamap proxy: http://{listen}/  ->  {upstream}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.recorder.close()  # type: ignore[attr-defined]
    return 0
