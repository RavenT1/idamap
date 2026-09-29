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
    ("omp-coding-agent", "omp"),
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

    def flush(self, timeout: float = 2.0) -> None:
        """Wait until everything queued so far is written (reads then see it)."""
        done = threading.Event()
        self.q.put(("flush", done))
        done.wait(timeout)

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
            if kind == "flush":
                p.set()
                continue
            try:
                if conn is None:
                    conn = S.connect()
                if kind == "pre":
                    ingest.on_pre(conn, p)
                elif kind == "virtual":
                    self._virtual(conn, p)
                else:
                    ingest.on_post(conn, p, ok=(kind == "ok"))
            except Exception:  # noqa: BLE001
                _log_error(f"record {kind} {p.get('tool_name')}")

    @staticmethod
    def _virtual(conn, p: dict) -> None:
        """A call idamap answered itself: record it like any other call."""
        from . import annotate, ingest

        ingest.on_pre(conn, p)
        tuid = p["tool_use_id"]
        row = conn.execute("SELECT id FROM calls WHERE tool_use_id=?", (tuid,)).fetchone() or \
            conn.execute("SELECT call_id AS id FROM call_aliases WHERE alias=?", (tuid,)).fetchone()
        if p.get("_store_annotation"):
            annotate.store_annotation(conn, p["session_id"], p.get("harness"), p["tool_input"],
                                      row["id"] if row else None)
        ingest.on_post(conn, p, ok=p.get("_ok", True))


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

    def __init__(self, recorder: Recorder, harness_override: str | None = None, virtual_tools: bool = False):
        self.rec = recorder
        self.override = harness_override
        self.virtual = virtual_tools
        self.pending: dict[tuple[str, str], tuple] = {}
        self.augment_ids: set[tuple[str, str]] = set()
        self.harness: dict[str, str] = {}
        self.lock = threading.Lock()
        self.cwd = os.getcwd()
        self._local = threading.local()

    # ---- idamap's own tools (opt-in) -------------------------------------
    def _conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._local.conn = S.connect()
        return c

    def intercept(self, session: str, msg) -> dict | None:
        """Answer tools/call for idamap_* locally; None = forward to ida-mcp."""
        if not self.virtual or not isinstance(msg, dict) or msg.get("method") != "tools/call" or "id" not in msg:
            return None
        from . import annotate

        params = msg.get("params") or {}
        name = params.get("name")
        if name not in annotate.NAMES:
            return None
        meta = params.get("_meta") or {}
        if isinstance(meta.get("io.modelcontextprotocol/clientInfo"), dict):
            self.harness[session] = harness_name(meta["io.modelcontextprotocol/clientInfo"])
        args = params.get("arguments") or {}
        key = json.dumps(msg["id"])
        payload = self._payload(session, key, name, args, meta.get("claudecode/toolUseId"))
        store = False
        self.rec.flush()  # earlier calls' results (functions, renames) must be visible
        try:
            conn = self._conn()
            if name == annotate.ANNOTATE:
                err = annotate.validate_annotation(args)
                text = err or annotate.describe_annotate(conn, session, args)
                ok, store = err is None, err is None
            else:
                text, ok = annotate.lookup(conn, session, args), True
        except Exception as e:  # noqa: BLE001
            _log_error(f"virtual tool {name}")
            text, ok = f"idamap error: {e}", False
        payload.update(_store_annotation=store, _ok=ok, duration_ms=0)
        if ok:
            payload["tool_response"] = [{"type": "text", "text": text}]
        else:
            payload["error"] = text
        self.rec.put("virtual", payload)
        result = {"content": [{"type": "text", "text": text}], "isError": not ok}
        if meta.get("io.modelcontextprotocol/protocolVersion"):
            result = {"resultType": "complete", **result}  # MCP 2026 results must say they are complete
        return {"jsonrpc": "2.0", "id": msg["id"], "result": result}

    def augment(self, session: str, msg):
        """Add idamap's tools / instructions to tools/list, initialize and server/discover results."""
        if not self.augment_ids or not isinstance(msg, dict) or "id" not in msg:
            return None
        key = (session, json.dumps(msg["id"]))
        with self.lock:
            if key not in self.augment_ids:
                return None
            self.augment_ids.discard(key)
        from . import annotate

        result = msg.get("result")
        if not isinstance(result, dict):
            return None
        changed = False
        if isinstance(result.get("tools"), list):
            have = {t.get("name") for t in result["tools"] if isinstance(t, dict)}
            result["tools"] = result["tools"] + [t for t in annotate.TOOLS if t["name"] not in have]
            changed = True
        if isinstance(result.get("instructions"), str) and annotate.INSTRUCTIONS not in result["instructions"]:
            result["instructions"] += annotate.INSTRUCTIONS
            changed = True
        return msg if changed else None

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
            if self.virtual and "id" in m and (method in ("initialize", "server/discover")
                                               or (method == "tools/list" and not params.get("cursor"))):
                with self.lock:
                    self.augment_ids.add((session, json.dumps(m["id"])))
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

def run_stdio(cmd: list[str], harness: str | None = None, virtual_tools: bool = False) -> int:
    if not cmd:
        cmd = ["ida-mcp"]
    exe = shutil.which(cmd[0]) or cmd[0]
    session = f"stdio-{uuid.uuid4().hex[:12]}"
    rec = Recorder("proxy-stdio")
    obs = Observer(rec, harness, virtual_tools)
    out = sys.stdout.buffer
    out_lock = threading.Lock()

    def emit(data: bytes) -> None:
        with out_lock:
            out.write(data)
            out.flush()
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

    for name in ("SIGTERM", "SIGINT", "SIGHUP"):  # SIGHUP does not exist on Windows
        sig = getattr(signal, name, None)
        if sig is None:
            continue
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
                if obs.virtual and b"idamap_" in line and b"tools/call" in line:
                    try:
                        reply = obs.intercept(session, _parse(line))
                    except Exception:  # noqa: BLE001
                        _log_error("intercept")
                        reply = None
                    if reply is not None:
                        emit(json.dumps(reply).encode() + b"\n")
                        continue
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

    try:
        while True:
            line = child.stdout.readline()
            if not line:
                break
            msg = None
            if obs.augment_ids:
                try:
                    msg = _parse(line)
                    changed = obs.augment(session, msg)
                    if changed is not None:
                        line = json.dumps(changed).encode() + b"\n"
                except Exception:  # noqa: BLE001
                    _log_error("augment")
            emit(line)
            try:
                msg = msg if msg is not None else _parse(line)
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


def exit_now(rc: int) -> None:
    """Exit without interpreter finalisation.

    The client->server thread may still be blocked reading stdin (the client
    keeps it open after the server died); normal shutdown would then abort with
    "could not acquire lock for stdin". Everything that matters is flushed."""
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        os._exit(rc)


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


def make_http_proxy(listen: str, upstream: str, harness: str | None = None,
                    virtual_tools: bool = False) -> ThreadingHTTPServer:
    up = urlsplit(upstream)
    if up.scheme not in ("http", "https"):
        raise SystemExit(f"--upstream must be an http(s) URL, got {upstream!r}")
    base = up.path.rstrip("/")
    rec = Recorder("proxy-http")
    obs = Observer(rec, harness, virtual_tools)
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
                    reply = obs.intercept(session, msg) if obs.virtual else None
                    if reply is not None:
                        data = json.dumps(reply).encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                        return
                    obs.client_message(session, msg)
                except Exception:  # noqa: BLE001
                    _log_error("http client message")
            augment = bool(obs.augment_ids) and isinstance(msg, dict) and \
                (session, json.dumps(msg.get("id"))) in obs.augment_ids

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
                if augment:  # small response we must rewrite: buffer it
                    data = resp.read()
                    data = _augment_body(obs, session, data, "text/event-stream" in ctype)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    self.wfile.flush()
                elif "text/event-stream" in ctype or resp.getheader("Content-Length") is None:
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


def _augment_body(obs: Observer, session: str, data: bytes, sse: bool) -> bytes:
    try:
        if not sse:
            changed = obs.augment(session, _parse(data))
            return json.dumps(changed).encode() if changed is not None else data
        out = []
        for event in data.replace(b"\r\n", b"\n").split(b"\n\n"):
            lines = event.split(b"\n")
            payload = b"\n".join(l[5:].lstrip() for l in lines if l.startswith(b"data:"))
            changed = obs.augment(session, _parse(payload)) if payload else None
            if changed is not None:
                lines = [l for l in lines if not l.startswith(b"data:")] + [b"data: " + json.dumps(changed).encode()]
            out.append(b"\n".join(lines))
        return b"\n\n".join(out)
    except Exception:  # noqa: BLE001
        _log_error("http augment")
        return data


def run_http(listen: str, upstream: str, harness: str | None = None, virtual_tools: bool = False) -> int:
    httpd = make_http_proxy(listen, upstream, harness, virtual_tools)
    sys.stderr.write(f"idamap proxy: http://{listen}/  ->  {upstream}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.recorder.close()  # type: ignore[attr-defined]
    return 0
