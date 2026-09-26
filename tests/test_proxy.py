"""The MCP proxy must be byte-transparent and record calls like the hooks do."""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from idamap import ingest, store

ROOT = Path(__file__).resolve().parent.parent

LIST = {"functions": [{"address": "0x1000004b0", "name": "_decrypt", "size": 100},
                      {"address": "0x100000514", "name": "_main", "size": 184}], "total": 2}


def reply(name, args):
    """Canned ida-mcp behaviour: (text, is_error)."""
    if name == "open_idb":
        return json.dumps({"path": "/x/t.i64", "function_count": 2, "processor": "ARM"}), False
    if name == "list_functions":
        return json.dumps(LIST), False
    if name == "decompile":
        if str(args.get("address", "")).startswith("0x"):
            return "int __fastcall main(int argc)\n{\n  return 0;\n}\n", False
        return "Invalid address format: main", True
    return "{}", False


FAKE_SERVER = textwrap.dedent(f"""
    import json, sys
    sys.path.insert(0, {str(ROOT)!r})
    from tests.test_proxy import reply
    for line in sys.stdin:
        m = json.loads(line)
        if "id" not in m:
            continue
        if m["method"] == "initialize":
            res = {{"protocolVersion": "2025-06-18", "capabilities": {{"tools": {{}}}}, "serverInfo": {{"name": "fake"}}}}
        elif m["method"] == "tools/call":
            text, err = reply(m["params"]["name"], m["params"].get("arguments") or {{}})
            res = {{"content": [{{"type": "text", "text": text}}], "isError": err}}
        else:
            res = {{}}
        sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": m["id"], "result": res}}) + "\\n")
        sys.stdout.flush()
""")

CALLS = [("open_idb", {"path": "/x/t"}), ("list_functions", {}),
         ("decompile", {"address": "0x100000514"}), ("decompile", {"address": "main"})]


def messages(client="Cursor"):
    out = [{"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": client, "version": "1"}}},
           {"jsonrpc": "2.0", "method": "notifications/initialized"}]
    for i, (name, args) in enumerate(CALLS, 1):
        out.append({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}})
    return out


def messages_2026(client="claude-code"):
    """MCP 2026-07-28: no initialize handshake, clientInfo in every request's _meta."""
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": client, "version": "1"}}
    return [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
             "params": {"name": name, "arguments": args, "_meta": {**meta, "claudecode/toolUseId": f"toolu_{i}"}}}
            for i, (name, args) in enumerate(CALLS, 1)]


class ProxyBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {**os.environ, "IDAMAP_HOME": self.tmp.name, "PYTHONPATH": str(ROOT)}
        os.environ["IDAMAP_HOME"] = self.tmp.name

    def tearDown(self):
        os.environ.pop("IDAMAP_HOME", None)
        self.tmp.cleanup()

    def db(self):
        return store.connect()

    def check_recorded(self, harness, source):
        conn = self.db()
        rows = conn.execute("SELECT tool, status, harness, error FROM calls ORDER BY id").fetchall()
        self.assertEqual([(r["tool"], r["status"]) for r in rows],
                         [("open_idb", "ok"), ("list_functions", "ok"), ("decompile", "ok"), ("decompile", "error")])
        self.assertTrue(all(r["harness"] == harness for r in rows))
        self.assertIn("Invalid address format", rows[3]["error"])
        self.assertEqual(conn.execute("SELECT source FROM sessions").fetchone()[0], source)
        f = conn.execute("SELECT name, flags FROM functions WHERE start='0x100000514'").fetchone()
        self.assertEqual(f["name"], "_main")
        self.assertEqual(store.stage_of(f["flags"]), "decompiled")
        self.assertEqual(conn.execute("SELECT key FROM databases").fetchone()[0], "/x/t.i64")


class StdioProxyTests(ProxyBase):
    def test_transparent_and_recorded(self):
        srv = Path(self.tmp.name) / "fake_server.py"
        srv.write_text(FAKE_SERVER)
        direct_in = "".join(json.dumps(m) + "\n" for m in messages())
        direct = subprocess.run([sys.executable, str(srv)], input=direct_in.encode(), capture_output=True, env=self.env)
        proxied = subprocess.run([sys.executable, "-m", "idamap", "proxy", "--", sys.executable, str(srv)],
                                 input=direct_in.encode(), capture_output=True, env=self.env, timeout=30)
        self.assertEqual(proxied.returncode, 0, proxied.stderr)
        self.assertEqual(proxied.stdout, direct.stdout)  # byte-identical stream
        self.check_recorded("cursor", "proxy-stdio")

    def test_mcp_2026_handshake_free(self):
        srv = Path(self.tmp.name) / "fake_server.py"
        srv.write_text(FAKE_SERVER)
        data = "".join(json.dumps(m) + "\n" for m in messages_2026()).encode()
        r = subprocess.run([sys.executable, "-m", "idamap", "proxy", "--", sys.executable, str(srv)],
                           input=data, capture_output=True, env=self.env, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_recorded("claude-code", "proxy-stdio")


class HttpProxyTests(ProxyBase):
    def test_sse_upstream(self):
        class Up(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                m = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if "id" not in m:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if m["method"] == "tools/call":
                    text, err = reply(m["params"]["name"], m["params"].get("arguments") or {})
                    res = {"content": [{"type": "text", "text": text}], "isError": err}
                else:
                    res = {"protocolVersion": "2025-06-18", "capabilities": {}}
                body = f"event: message\ndata: {json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': res})}\n\n".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Mcp-Session-Id", "sess-1")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        up = ThreadingHTTPServer(("127.0.0.1", 0), Up)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        from idamap import proxy

        px = proxy.make_http_proxy("127.0.0.1:0", f"http://127.0.0.1:{up.server_port}/")
        threading.Thread(target=px.serve_forever, daemon=True).start()
        sid = None
        for m in messages("gemini-cli-mcp-client"):
            headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
            if sid:
                headers["Mcp-Session-Id"] = sid
            req = urllib.request.Request(f"http://127.0.0.1:{px.server_port}/", json.dumps(m).encode(), headers)
            with urllib.request.urlopen(req) as r:
                sid = r.headers.get("Mcp-Session-Id") or sid
                data = r.read()
                if "id" in m:
                    self.assertIn(b'"id": %d' % m["id"], data)
        px.recorder.close()
        px.shutdown()
        up.shutdown()
        self.check_recorded("gemini-cli", "proxy-http")


class DedupTests(ProxyBase):
    def test_exact_dedupe_by_claude_tool_use_id(self):
        conn = self.db()
        ingest.handle(conn, {"session_id": "cc", "tool_name": "mcp__ida__callers", "tool_input": {"address": "0x10"},
                             "tool_use_id": "toolu_9", "hook_event_name": "PreToolUse"})
        # arguments differ in shape (proxy saw an array), the host id still links them
        ingest.on_pre(conn, {"session_id": "stdio-y", "tool_name": "mcp__ida__callers", "tool_input": {"address": ["0x10"]},
                             "tool_use_id": "stdio-y:1", "host_tool_use_id": "toolu_9", "source": "proxy-stdio"})
        self.assertEqual(conn.execute("SELECT count(*) FROM calls").fetchone()[0], 1)

    def test_proxy_defers_to_hook(self):
        conn = self.db()
        base = {"session_id": "cc", "tool_name": "mcp__ida__decompile", "tool_input": {"address": "0x10"},
                "tool_use_id": "toolu_1", "transcript_path": None}
        ingest.handle(conn, {**base, "hook_event_name": "PreToolUse"})
        px = {"session_id": "stdio-x", "tool_name": "mcp__ida__decompile", "tool_input": {"address": "0x10"},
              "tool_use_id": "stdio-x:1", "source": "proxy-stdio", "harness": "claude-code"}
        ingest.on_pre(conn, px)
        ingest.on_post(conn, {**px, "tool_response": [{"type": "text", "text": "int f(void)\n{}"}]}, ok=True)
        ingest.handle(conn, {**base, "hook_event_name": "PostToolUse",
                             "tool_response": [{"type": "text", "text": "int f(void)\n{}"}]})
        rows = conn.execute("SELECT tool_use_id, status FROM calls").fetchall()
        self.assertEqual([tuple(r) for r in rows], [("toolu_1", "ok")])


if __name__ == "__main__":
    unittest.main()
