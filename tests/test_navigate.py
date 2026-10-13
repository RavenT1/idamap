"""idamap_search / idamap_status / bundle awareness, against a small synthetic app bundle."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from idamap import annotate, bundle, ingest, navigate, store

ROOT = Path(__file__).resolve().parent.parent

LOGIN, TOKEN, STUB, JB, BIG = 0x2000, 0x1000, 0x3000, 0x4000, 0x5000

# [start, end, name, demangled, is_lib]
FUNCS = [
    [TOKEN, TOKEN + 0x80, "sub_1000", None, 0],
    [LOGIN, LOGIN + 0x100, "_$s3Foo7AuthMgrC5loginyyF", "Foo.AuthMgr.login()", 0],
    [STUB, STUB + 0x20, "sub_3000", None, 0],
    [JB, JB + 0x200, "sub_4000", None, 0],
    [BIG, BIG + 0x300, "sub_5000", None, 0],
]
REFS = {
    TOKEN: [["import", "Crypto.AES.init(key:)"], ["str", "Bearer %@"]],
    LOGIN: [["import", "Net.Request.send()"], ["sel", "dataTaskWithRequest:completionHandler:"]],
    STUB: [["import", "Net.Request.send()"]],
    JB: [["str", "/Applications/Cydia.app"]],
}
EDGES = [[LOGIN, TOKEN], [LOGIN, STUB], [LOGIN, JB]]


def make_app(tmp: Path) -> Path:
    app = tmp / "Foo.app"
    (app / "Frameworks" / "Net.framework").mkdir(parents=True)
    (app / "Frameworks" / "Crypto.framework").mkdir()
    for p in (app / "Foo", app / "Frameworks" / "Net.framework" / "Net", app / "Frameworks" / "Crypto.framework" / "Crypto"):
        p.write_bytes(b"\xcf\xfa\xed\xfe")
    return app


class Corpus(unittest.TestCase):
    mapped = True

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_home = os.environ.get("IDAMAP_HOME")
        os.environ["IDAMAP_HOME"] = self.tmp.name
        self.app = make_app(Path(self.tmp.name))
        self.main = self.app / "Foo"
        self.conn = store.connect()  # <IDAMAP_HOME>/idamap.db, the file a proxy subprocess will use too
        data = {"idb_path": str(self.main) + ".i64", "input_path": str(self.main), "sha256": "ab" * 32,
                "processor": "ARM", "bits": 64, "functions": FUNCS, "edges": EDGES,
                "refs": {str(k): v for k, v in REFS.items()}, "segments": []}
        exp = Path(self.tmp.name) / "export.json"
        exp.write_text(json.dumps(data))
        if self.mapped:
            self.db = ingest.import_export(self.conn, str(exp))["db_id"]
        else:  # partial: functions known, no full-map import marker
            self.db = ingest.import_export(self.conn, str(exp))["db_id"]
            self.conn.execute("UPDATE databases SET map_imported_at=NULL WHERE id=?", (self.db,))
        self.conn.execute("UPDATE functions SET flags=? WHERE db_id=? AND start_i=?", (store.F_DECOMP, self.db, LOGIN))
        annotate.store_annotation(self.conn, None, "codex", {
            "address": hex(JB), "summary": "Checks for Cydia to detect a jailbroken device",
            "name_suggestion": "isJailbroken", "confidence": "high"}, None)

    def tearDown(self):
        self.conn.close()
        if self.old_home is None:
            os.environ.pop("IDAMAP_HOME", None)
        else:
            os.environ["IDAMAP_HOME"] = self.old_home
        self.tmp.cleanup()

    def search(self, **args):
        return json.loads(navigate.search(self.conn, None, args))

    def addrs(self, res):
        return {r["address"] for r in res["results"]}


class SearchTests(Corpus):
    def test_by_string_and_demangled_name(self):
        r = self.search(query="bearer")
        self.assertEqual(self.addrs(r), {hex(TOKEN)})
        self.assertIn("str: Bearer %@", r["results"][0]["matched"])
        r = self.search(query="authmgr login", kind="name")  # words AND together, demangled name is searchable
        self.assertEqual(self.addrs(r), {hex(LOGIN)})
        self.assertEqual(r["results"][0]["name"], "Foo.AuthMgr.login()")

    def test_kinds(self):
        self.assertEqual(self.addrs(self.search(query="dataTask", kind="selector")), {hex(LOGIN)})
        self.assertEqual(self.addrs(self.search(query="dataTask", kind="string")), set())
        self.assertEqual(self.addrs(self.search(query="cydia", kind="string")), {hex(JB)})
        r = self.search(query="jailbroken device", kind="explanation")
        self.assertEqual(self.addrs(r), {hex(JB)})
        self.assertEqual(r["results"][0]["explained"]["suggested_name"], "isJailbroken")

    def test_unexplored_only(self):
        r = self.search(query="net", kind="import")
        self.assertEqual(self.addrs(r), {hex(LOGIN), hex(STUB)})
        r = self.search(query="net", kind="import", unexplored_only=True)
        self.assertEqual(self.addrs(r), {hex(STUB)})  # LOGIN was decompiled

    def test_bundle_resolution_in_results(self):
        r = self.search(query="send")
        item = next(i for i in r["results"] if i["address"] == hex(STUB))
        self.assertEqual(item["in_bundle"][0]["name"], "Net")
        self.assertEqual(item["in_bundle"][0]["status"], "not analyzed yet")
        self.assertNotIn("binary", item["in_bundle"][0])  # paths are listed once, not per result
        self.assertTrue(r["unanalyzed_framework_binaries"]["Net"].endswith("Net.framework/Net"))
        self.assertEqual(item["called_from"], [f"Foo.AuthMgr.login() @{hex(LOGIN)}"])  # the stub's caller is what matters
        r = self.search(query="net")  # the query names a bundled framework that is not analyzed
        self.assertTrue(any("not analyzed yet" in n for n in r["notes"]))
        self.assertIn("Net", r["unanalyzed_framework_binaries"])

    def test_limits_errors_and_escaping(self):
        r = self.search(query="sub", limit=2)
        self.assertEqual((r["shown"], r["total_matches"]), (2, 4))
        self.assertTrue(any("More matches" in n for n in r["notes"]))
        self.assertIn("error", self.search(query=""))
        self.assertIn("error", self.search(query="x", kind="bogus"))
        self.assertEqual(self.search(query="100%")["total_matches"], 0)   # % is not a wildcard
        self.assertEqual(self.search(query="sub_100_")["total_matches"], 0)  # nor is _
        self.assertEqual(self.search(query="sub_1000")["total_matches"], 1)

    def test_rejected_explanations_do_not_surface(self):
        self.conn.execute("UPDATE annotations SET status='rejected'")
        self.assertEqual(self.addrs(self.search(query="jailbroken device", kind="explanation")), set())


class QualityTests(Corpus):
    def test_boilerplate_is_not_suggested_and_callers_carry_addresses(self):
        # a big, much-called compiler helper must not crowd out real functions in look_next
        self.conn.execute("UPDATE functions SET name='lazy protocol witness table accessor for type X', demangled=NULL "
                          "WHERE db_id=? AND start_i=?", (self.db, TOKEN))
        st = json.loads(navigate.status(self.conn, None, {}))
        self.assertEqual({f["address"] for f in st["look_next"]}, {hex(JB)})
        item = json.loads(annotate.lookup(self.conn, None, {"address": hex(TOKEN)}))
        self.assertEqual(item["callers"], [f"Foo.AuthMgr.login() @{hex(LOGIN)}"])
        self.assertTrue(navigate.BOILERPLATE.match("___swift_instantiateConcreteTypeFromMangledName"))
        self.assertFalse(navigate.BOILERPLATE.match("AppSecurity.checkForceUpdate(showAlertIfNeeded:_:)"))


class PartialMapTests(Corpus):
    mapped = False

    def test_tells_the_model_how_to_map_everything(self):
        r = self.search(query="bearer")
        self.assertEqual(next(iter(r)), "map_required")  # first key: the model reads the top of the answer
        self.assertIn("export_map.py", r["map_required"])
        st = json.loads(navigate.status(self.conn, None, {}))
        self.assertTrue(st["map"].startswith("partial"))
        self.assertEqual(next(iter(st)), "map_required")


class StatusTests(Corpus):
    def test_overview(self):
        st = json.loads(navigate.status(self.conn, None, {}))
        self.assertEqual(st["functions_total"], 5)
        self.assertEqual(st["coverage_by_stage"]["decompiled"], 1)
        self.assertEqual(st["explanations"]["hypothesis"], 1)
        nxt = {f["address"]: f for f in st["look_next"]}
        self.assertEqual(set(nxt), {hex(TOKEN), hex(JB)})  # STUB is a tiny thunk; BIG has no analyzed caller
        self.assertEqual(nxt[hex(JB)]["called_from_analyzed_functions"], 1)

    def test_bundle_section_and_next_steps(self):
        st = json.loads(navigate.status(self.conn, None, {}))
        bins = {b["name"]: b for b in st["app_bundle"]["binaries"]}
        self.assertEqual(bins["Foo"]["status"], "this binary")
        self.assertEqual(bins["Net"]["status"], "not analyzed yet")
        self.assertEqual(bins["Net"]["binary"], "Frameworks/Net.framework/Net")  # relative to app_root
        self.assertEqual(st["app_bundle"]["app_root"], str(self.app))
        # stubs pointing into Net: LOGIN and STUB; the only caller of either is LOGIN (calls STUB)
        self.assertEqual(bins["Net"]["functions_here_that_use_it"], 1)
        self.assertEqual(bins["Crypto"]["functions_here_that_use_it"], 1)  # TOKEN holds the Crypto import; LOGIN calls it
        self.assertTrue(any("use Net" in s for s in st["next_steps"]))

    def test_framework_gets_marked_analyzed_once_recorded(self):
        net = self.app / "Frameworks" / "Net.framework" / "Net"
        ingest.upsert_database(self.conn, str(net) + ".i64", {"input_path": str(net), "sha256": "cd" * 32})
        self.conn.execute("INSERT INTO sessions(id, db_id) VALUES ('s1', ?)", (self.db,))  # a session working on Foo
        st = json.loads(navigate.status(self.conn, "s1", {}))
        self.assertEqual({b["name"]: b["status"] for b in st["app_bundle"]["binaries"]}["Net"], "analyzed in idamap")
        self.assertFalse(any("use Net" in s for s in st["next_steps"]))


class LookupHintTests(Corpus):
    def test_stub_forwarding_to_a_bundled_framework(self):
        item = json.loads(annotate.lookup(self.conn, None, {"address": hex(STUB)}))
        self.assertEqual(item["bundled_frameworks"][0]["name"], "Net")
        self.assertIn("Tiny stub", item["note"])
        self.assertIn("Net", item["note"])
        big = json.loads(annotate.lookup(self.conn, None, {"address": hex(LOGIN)}))
        self.assertNotIn("note", big)  # not a stub

    def test_no_hints_without_an_app_bundle(self):
        other = Path(self.tmp.name) / "plainbin"
        other.write_bytes(b"x")
        db = ingest.upsert_database(self.conn, str(other) + ".i64", {"input_path": str(other), "sha256": "ee" * 32})
        ingest.upsert_functions(self.conn, db, [{"start": 0x10, "name": "f", "size": 8}], 1)
        item = json.loads(annotate.lookup(self.conn, None, {"address": "0x10", "database_id": "nope"}))
        self.assertEqual(item.get("known"), True)
        self.assertNotIn("bundled_frameworks", item)


class BundleUnitTests(unittest.TestCase):
    def test_swift_module(self):
        self.assertEqual(bundle.swift_module("_$s3Foo7AuthMgrC5loginyyF"), "Foo")
        self.assertEqual(bundle.swift_module("$sSa7SomeLibs5UInt8VRszlE6base64"), "SomeLib")
        self.assertIsNone(bundle.swift_module("_objc_msgSend"))
        self.assertIsNone(bundle.swift_module("$s99Short"))  # declared length longer than the name

    def test_app_root_is_the_outermost_app(self):
        self.assertEqual(bundle.app_root("/x/Payload/A.app/Watch/W.app/W"), Path("/x/Payload/A.app"))
        self.assertIsNone(bundle.app_root("/x/plain/binary"))
        self.assertIsNone(bundle.app_root(None))

    def test_index_resolution(self):
        info = {"members": [{"name": "Foo", "current": True}, {"name": "Net"}, {"name": "SomeLib"}]}
        idx = bundle.Index(info)
        self.assertEqual(idx.modules_in(["type metadata accessor for Net.Request", "_$s7SomeLib3AESCMa",
                                         "Foo.AuthMgr.login()", "Network.Reachability.init()"]), ["Net", "SomeLib"])
        self.assertEqual(idx.modules_in([None, ""]), [])
        self.assertFalse(bundle.Index(None))

    def test_scan_reads_bundle_executable_from_plist(self):
        with tempfile.TemporaryDirectory() as t:
            app = Path(t) / "Bar.app"
            (app / "Frameworks" / "X.framework").mkdir(parents=True)
            import plistlib
            (app / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "BarExe"}))
            (app / "BarExe").write_bytes(b"1")
            (app / "Frameworks" / "X.framework" / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "XImpl"}))
            (app / "Frameworks" / "X.framework" / "XImpl").write_bytes(b"1")
            got = {m["name"]: Path(m["path"]).name for m in bundle.scan(app)}
            self.assertEqual(got, {"BarExe": "BarExe", "X": "XImpl"})


class ProxyEndToEnd(Corpus):
    """The tools are offered, answered locally and recorded like any other call."""

    def test_through_the_proxy(self):
        srv = Path(self.tmp.name) / "fake_server.py"
        srv.write_text("import sys, json\nfor line in sys.stdin:\n    m = json.loads(line)\n"
                       "    if 'id' in m:\n        r = {'tools': [{'name': 'decompile'}]} if m['method'] == 'tools/list' else {}\n"
                       "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': r}) + '\\n'); sys.stdout.flush()\n")
        env = {**os.environ, "IDAMAP_HOME": self.tmp.name, "PYTHONPATH": str(ROOT)}
        p = subprocess.Popen([sys.executable, "-m", "idamap", "proxy", "--annotate-tools", "--", sys.executable, str(srv)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

        def call(msg):
            p.stdin.write(json.dumps(msg).encode() + b"\n")
            p.stdin.flush()
            return json.loads(p.stdout.readline())

        tools = call({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})["result"]["tools"]
        self.assertEqual([t["name"] for t in tools][-2:], ["idamap_search", "idamap_status"])
        res = call({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "idamap_search", "arguments": {"query": "bearer"}}})["result"]
        self.assertFalse(res["isError"])
        self.assertEqual(json.loads(res["content"][0]["text"])["results"][0]["address"], hex(TOKEN))
        res = call({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "idamap_status", "arguments": {}}})["result"]
        self.assertIn("look_next", json.loads(res["content"][0]["text"]))
        bad = call({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "idamap_search", "arguments": {"query": "error"}}})["result"]  # a query that says "error" is not an error
        self.assertFalse(bad["isError"])
        p.stdin.close()
        p.wait(timeout=30)
        p.stdout.close()
        p.stderr.close()
        rows = self.conn.execute("SELECT tool, category, status FROM calls WHERE tool LIKE 'idamap_s%' ORDER BY id").fetchall()
        self.assertEqual([(r[0], r[1], r[2]) for r in rows],
                         [("idamap_search", "idamap", "ok"), ("idamap_status", "idamap", "ok"), ("idamap_search", "idamap", "ok")])


FAKE_IDA = r"""
import json, os, sys
LOG = os.environ["FAKE_LOG"]
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m or m.get("method") != "tools/call":
        if "id" in m:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {}}) + "\n"); sys.stdout.flush()
        continue
    name = m["params"]["name"]
    with open(LOG, "a") as fh:
        fh.write(json.dumps({"tool": name, "id": m["id"], "args": m["params"].get("arguments"), "meta": m["params"].get("_meta")}) + "\n")
    if name == "open_idb":
        text, err = json.dumps({"path": os.environ["FAKE_IDB"], "function_count": 5, "processor": "ARM"}), False
    elif name == "run_script" and os.environ.get("FAKE_MODE") == "readonly":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "unknown tool run_script"}}) + "\n")
        sys.stdout.flush(); continue
    elif name == "run_script":
        text, err = json.dumps({"stdout": "IDAMAP_EXPORT_FILE=%s functions=5 edges=3 refs=4 (0.1s)\n" % os.environ["FAKE_EXPORT"], "success": True}), False
    else:
        text, err = "{}", False
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"content": [{"type": "text", "text": text}], "isError": err}}) + "\n")
    sys.stdout.flush()
"""


class AutoMapTests(unittest.TestCase):
    """The first idamap_search / idamap_status maps the binary by calling ida-mcp itself."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name)
        self.app = make_app(self.t)
        main = self.app / "Foo"
        (self.t / "exports").mkdir()
        (self.t / "exports" / "export.json").write_text(json.dumps({
            "idb_path": str(main) + ".i64", "input_path": str(main), "sha256": "ab" * 32, "processor": "ARM", "bits": 64,
            "functions": FUNCS, "edges": EDGES, "refs": {str(k): v for k, v in REFS.items()}, "segments": []}))
        (self.t / "fake_ida.py").write_text(FAKE_IDA)
        self.log = self.t / "calls.log"
        self.env = {**os.environ, "IDAMAP_HOME": str(self.t), "PYTHONPATH": str(ROOT), "FAKE_LOG": str(self.log),
                    "FAKE_IDB": str(main) + ".i64", "FAKE_EXPORT": str(self.t / "exports" / "export.json")}

    def tearDown(self):
        self.tmp.cleanup()

    def session(self, *flags, mode=None, calls):
        env = {**self.env, **({"FAKE_MODE": mode} if mode else {})}
        p = subprocess.Popen([sys.executable, "-m", "idamap", "proxy", *flags, "--", sys.executable, str(self.t / "fake_ida.py")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        replies = []
        for i, (name, args) in enumerate(calls, 1):
            p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                      "params": {"name": name, "arguments": args}}).encode() + b"\n")
            p.stdin.flush()
            msg = json.loads(p.stdout.readline())
            self.assertEqual(msg["id"], i, "a reply the client did not ask for leaked through")
            replies.append(msg["result"] if "result" in msg else msg)
        p.stdin.close()
        p.wait(timeout=30)
        p.stdout.close()
        p.stderr.close()
        return replies

    def internal_calls(self):
        rows = [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []
        return [r for r in rows if r["tool"] == "run_script"]

    def text(self, reply):
        return json.loads(reply["content"][0]["text"])

    def test_first_search_maps_the_binary_once(self):
        r = self.session("--annotate-tools", calls=[
            ("open_idb", {"path": "x"}), ("idamap_search", {"query": "bearer"}),
            ("idamap_status", {}), ("idamap_search", {"query": "cydia"})])
        first = self.text(r[1])
        self.assertIn("indexed the binary just now", first["auto_map"])
        self.assertNotIn("map_required", first)
        self.assertEqual(first["results"][0]["address"], hex(TOKEN))
        self.assertNotIn("auto_map", self.text(r[2]))  # only the call that did the work says so
        self.assertEqual(self.text(r[3])["results"][0]["address"], hex(JB))
        calls = self.internal_calls()
        self.assertEqual(len(calls), 1)                  # once, not per call
        self.assertTrue(calls[0]["args"]["file"].endswith("export_map.py"))
        self.assertTrue(calls[0]["id"].startswith("idamap-int-"))
        conn = store.connect(self.t / "idamap.db")
        row = conn.execute("SELECT tool, status FROM calls WHERE tool='idamap_map'").fetchone()
        self.assertEqual(tuple(row), ("idamap_map", "ok"))  # visible in the timeline, not hidden

    def test_internal_call_reuses_the_clients_protocol_metadata(self):
        meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "claude-code", "version": "1"}, "claudecode/toolUseId": "toolu_1"}
        p = subprocess.Popen([sys.executable, "-m", "idamap", "proxy", "--annotate-tools", "--", sys.executable, str(self.t / "fake_ida.py")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        for i, (name, args) in enumerate([("open_idb", {"path": "x"}), ("idamap_status", {})], 1):
            p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                      "params": {"name": name, "arguments": args, "_meta": meta}}).encode() + b"\n")
            p.stdin.flush()
            self.assertEqual(json.loads(p.stdout.readline())["id"], i)
        p.stdin.close(); p.wait(timeout=30); p.stdout.close(); p.stderr.close()
        sent = self.internal_calls()[0]["meta"]
        self.assertEqual(sent["io.modelcontextprotocol/protocolVersion"], "2026-07-28")
        self.assertNotIn("claudecode/toolUseId", sent)  # not the client's own call

    def test_failure_is_reported_and_not_retried(self):
        r = self.session("--annotate-tools", mode="readonly", calls=[
            ("open_idb", {"path": "x"}), ("idamap_search", {"query": "bearer"}), ("idamap_search", {"query": "bearer"})])
        first = self.text(r[1])
        self.assertIn("automatic mapping failed", first["auto_map"])
        self.assertIn("map_required", first)           # falls back to asking the model to run the script
        self.assertEqual(len(self.internal_calls()), 1)  # a failed attempt is not repeated on every call

    def test_no_attempt_before_a_binary_is_open(self):
        r = self.session("--annotate-tools", calls=[("idamap_status", {}), ("idamap_search", {"query": "x"})])
        self.assertIn("open a binary", self.text(r[0])["error"])  # not a made-up 'unknown' database
        self.assertTrue(r[1]["isError"])
        self.assertEqual(self.internal_calls(), [])
        conn = store.connect(self.t / "idamap.db")
        self.assertEqual(conn.execute("SELECT count(*) FROM databases").fetchone()[0], 0)  # no 'unknown' placeholder
        self.assertEqual(conn.execute("SELECT count(*) FROM calls WHERE tool LIKE 'idamap_%'").fetchone()[0], 2)

    def test_can_be_switched_off(self):
        (self.t / "config.json").write_text(json.dumps({"auto_map": False}))
        r = self.session("--annotate-tools", calls=[("open_idb", {"path": "x"}), ("idamap_status", {})])
        self.assertEqual(self.internal_calls(), [])
        self.assertIn("map_required", self.text(r[1]))


    def test_http_proxy_maps_on_the_clients_session(self):
        """Same behaviour through the Streamable-HTTP proxy, with the SSE framing ida-mcp serve-http uses."""
        import threading
        import urllib.request
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen = []
        export = str(self.t / "exports" / "export.json")
        idb = str(self.app / "Foo") + ".i64"

        class Up(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                m = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((m["params"]["name"], m["id"], self.headers.get("Mcp-Session-Id")))
                name = m["params"]["name"]
                text = (json.dumps({"path": idb, "function_count": 5}) if name == "open_idb" else
                        json.dumps({"stdout": f"IDAMAP_EXPORT_FILE={export} functions=5 edges=3 refs=4 (0.1s)\n"}))
                body = ("event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {
                    "content": [{"type": "text", "text": text}], "isError": False}}) + "\n\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Mcp-Session-Id", "sess-9")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        up = ThreadingHTTPServer(("127.0.0.1", 0), Up)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        from idamap import proxy
        os.environ["IDAMAP_HOME"] = str(self.t)
        px = proxy.make_http_proxy("127.0.0.1:0", f"http://127.0.0.1:{up.server_port}/", virtual_tools=True)
        threading.Thread(target=px.serve_forever, daemon=True).start()

        def post(i, name, args, sid=None):
            hdr = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
            if sid:
                hdr["Mcp-Session-Id"] = sid
            req = urllib.request.Request(f"http://127.0.0.1:{px.server_port}/", json.dumps({
                "jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}).encode(), hdr)
            with urllib.request.urlopen(req) as r:
                data = r.read().decode()
                return r.headers.get("Mcp-Session-Id"), data

        sid, _ = post(1, "open_idb", {"path": "x"})
        _, data = post(2, "idamap_search", {"query": "bearer"}, sid)
        res = json.loads(json.loads(data)["result"]["content"][0]["text"])
        self.assertIn("indexed the binary just now", res["auto_map"])
        self.assertEqual(res["results"][0]["address"], hex(TOKEN))
        internal = [x for x in seen if x[0] == "run_script"]
        self.assertEqual(len(internal), 1)
        self.assertTrue(internal[0][1].startswith("idamap-int-"))
        self.assertEqual(internal[0][2], "sess-9")  # on the client's own MCP session
        px.recorder.close()
        px.shutdown(); px.server_close()
        up.shutdown(); up.server_close()
        os.environ.pop("IDAMAP_HOME", None)


if __name__ == "__main__":
    unittest.main()
