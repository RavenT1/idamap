"""Ingestion tests driven by real ida-mcp outputs (captured from ida-mcp against a
tiny arm64 Mach-O: main -> check_key -> strcmp, main -> decrypt, puts)."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from idamap import ingest, parse, store

FIX = Path(__file__).parent / "fixtures"

MAIN, DECRYPT, CHECK, PUTS, STRCMP = 0x100000514, 0x1000004B0, 0x1000005CC, 0x100000600, 0x100000618

LIST_FUNCS = {"functions": [
    {"address": "0x1000004b0", "name": "_decrypt", "size": 100},
    {"address": "0x100000514", "name": "_main", "size": 184},
    {"address": "0x1000005cc", "name": "_check_key", "size": 52},
    {"address": "0x100000600", "name": "_puts", "size": 12},
    {"address": "0x10000060c", "name": "___stack_chk_fail", "size": 12},
    {"address": "0x100000618", "name": "_strcmp", "size": 12}], "total": 6}

MAIN_DECOMP = "int __fastcall main(int argc, const char **argv, const char **envp)\n{\n  return 0;\n}\n"


def text(obj):
    return [{"type": "text", "text": obj if isinstance(obj, str) else json.dumps(obj)}]


class Harness:
    def __init__(self, conn):
        self.conn = conn
        self.n = 0

    def call(self, tool, inp, out=None, error=None, session="s1", prompt="p1"):
        self.n += 1
        base = {"session_id": session, "prompt_id": prompt, "tool_name": f"mcp__ida__{tool}",
                "tool_input": inp, "tool_use_id": f"tu{self.n}", "cwd": "/tmp",
                "transcript_path": None}
        ingest.handle(self.conn, {**base, "hook_event_name": "PreToolUse"})
        if error is None:
            ingest.handle(self.conn, {**base, "hook_event_name": "PostToolUse",
                                      "tool_response": text(out), "duration_ms": 5})
        else:
            ingest.handle(self.conn, {**base, "hook_event_name": "PostToolUseFailure", "error": error})
        return self.conn.execute("SELECT * FROM calls WHERE tool_use_id=?", (base["tool_use_id"],)).fetchone()

    def func(self, addr, db=None):
        db = db or self.conn.execute("SELECT id FROM databases ORDER BY last_seen DESC").fetchone()[0]
        return self.conn.execute("SELECT * FROM functions WHERE db_id=? AND start_i=?",
                                 (db, store.to_i(addr))).fetchone()


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.connect(Path(self.tmp.name) / "t.db")
        self.h = Harness(self.conn)
        self.h.call("open_idb", {"path": "/x/t"}, {"path": "/x/t.i64", "processor": "ARM Little-endian",
                                                   "bits": 64, "file_type": "MACHO", "function_count": 6})

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_real_hook_payloads(self):
        for line in (FIX / "hook_payloads.jsonl").read_text().splitlines():
            if line.strip():
                ingest.handle(self.conn, json.loads(line))
        rows = self.conn.execute("SELECT tool, status, error FROM calls WHERE session_id != 's1' ORDER BY id").fetchall()
        self.assertEqual([r["tool"] for r in rows], ["open_idb", "decompile", "decompile", "close_idb"])
        self.assertEqual([r["status"] for r in rows], ["ok", "ok", "error", "ok"])
        self.assertIn("Invalid address format", rows[2]["error"])
        db = self.conn.execute("SELECT * FROM databases WHERE key LIKE '%t2.i64'").fetchone()
        self.assertEqual(db["func_total"], 6)
        stub = self.h.func(MAIN, db["id"])
        self.assertEqual(stub["name"], "main")          # parsed from Hex-Rays signature
        self.assertIsNone(stub["size"])                  # extent unknown yet
        self.assertEqual(store.stage_of(stub["flags"]), "decompiled")

    def test_stub_merges_into_real_function(self):
        self.h.call("decompile", {"address": "0x100000514"}, MAIN_DECOMP)
        self.h.call("disasm", {"address": "0x10000057c", "count": 3}, "0x10000057c:\tBL _decrypt")
        self.h.call("list_functions", {}, LIST_FUNCS)
        f = self.h.func(MAIN)
        self.assertEqual(f["size"], 184)
        self.assertEqual(f["name"], "_main")
        self.assertTrue(f["flags"] & store.F_DECOMP and f["flags"] & store.F_DISASM)
        self.assertEqual(f["touch_count"], 2)
        n = self.conn.execute("SELECT count(*) FROM functions WHERE size IS NULL").fetchone()[0]
        self.assertEqual(n, 0)

    def test_callees_and_xrefs_build_graph(self):
        self.h.call("list_functions", {}, LIST_FUNCS)
        self.h.call("callees", {"address": "0x100000514"}, [
            {"address": "0x1000005cc", "name": "_check_key", "size": 52},
            {"address": "0x1000004b0", "name": "_decrypt", "size": 100}])
        self.h.call("xrefs_to", {"address": ["0x1000004b0", "0x1000005cc"]}, {"results": [
            {"address": "0x1000004b0", "truncated": False, "xrefs": [
                {"from": "0x10000057c", "is_code": True, "to": "0x1000004b0", "type": "Code(NearCall)"},
                {"from": "0x1000000b0", "is_code": False, "to": "0x1000004b0", "type": "Data(Offset)"}]},
            {"address": "0x1000005cc", "truncated": False, "xrefs": [
                {"from": "0x100000554", "is_code": True, "to": "0x1000005cc", "type": "Code(NearCall)"}]}]})
        edges = {(r[0], r[1]) for r in self.conn.execute("SELECT src, dst FROM edges")}
        self.assertEqual(edges, {("0x100000514", "0x1000005cc"), ("0x100000514", "0x1000004b0")})
        self.assertEqual(store.stage_of(self.h.func(MAIN)["flags"]), "explored")
        self.assertEqual(store.stage_of(self.h.func(DECRYPT)["flags"]), "explored")
        self.assertEqual(store.stage_of(self.h.func(STRCMP)["flags"]), "unseen")

    def test_rename_and_comment_history(self):
        self.h.call("list_functions", {}, LIST_FUNCS)
        self.h.call("rename", {"address": "0x1000004b0", "name": "xor_decrypt_buf"},
                    {"address": "0x1000004b0", "flags": 0, "name": "xor_decrypt_buf"})
        self.h.call("set_comments", {"address": "0x1000005d8", "comment": "key check"},
                    {"address": "0x1000005d8", "comment": "key check", "repeatable": False})
        f = self.h.func(DECRYPT)
        self.assertEqual((f["name"], f["orig_name"]), ("xor_decrypt_buf", "_decrypt"))
        self.assertEqual(store.stage_of(f["flags"]), "annotated")
        r = self.conn.execute("SELECT old_name, new_name FROM renames").fetchone()
        self.assertEqual(tuple(r), ("_decrypt", "xor_decrypt_buf"))
        c = self.conn.execute("SELECT func_i, text FROM comments").fetchone()
        self.assertEqual((c["func_i"], c["text"]), (store.to_i(CHECK), "key check"))
        # a later listing (IDA now reports the new name) keeps the original name
        LIST2 = json.loads(json.dumps(LIST_FUNCS))
        LIST2["functions"][0]["name"] = "xor_decrypt_buf"
        self.h.call("list_functions", {}, LIST2)
        self.assertEqual(self.h.func(DECRYPT)["orig_name"], "_decrypt")

    def test_failed_call_marks_nothing(self):
        self.h.call("list_functions", {}, LIST_FUNCS)
        c = self.h.call("decompile", {"address": "main"}, error="Invalid address format: main")
        self.assertEqual(c["status"], "error")
        self.assertEqual(self.h.func(MAIN)["flags"], 0)

    def test_batch_decompile_partial_error(self):
        self.h.call("list_functions", {}, LIST_FUNCS)
        self.h.call("decompile", {"address": ["0x1000004b0", "0xdeadbeef"]}, {"results": [
            {"address": "0x1000004b0", "decompile": "__int64 __fastcall decrypt(__int64 a1)\n{}"},
            {"address": "0xdeadbeef", "error": "Function not found at address 0xdeadbeef"}]})
        self.assertEqual(store.stage_of(self.h.func(DECRYPT)["flags"]), "decompiled")
        self.assertIsNone(self.h.func(0xDEADBEEF))

    def test_string_xrefs_and_name_targets(self):
        self.h.call("list_functions", {}, LIST_FUNCS)
        self.h.call("xrefs_to_string", {"query": "S3CR"}, {"strings": [
            {"address": "0x100000633", "content": "S3CR3T\u0000", "xrefs": ["0x1000005e0"], "xref_count": 1}],
            "total": 1})
        t = self.conn.execute("SELECT func_i, detail FROM touches WHERE kind='string_ref'").fetchone()
        self.assertEqual((t["func_i"], t["detail"]), (store.to_i(CHECK), "S3CR3T"))
        self.h.call("disasm_by_name", {"name": "main", "count": 5}, "0x100000514:\tSUB SP, SP, #0x30")
        self.assertTrue(self.h.func(MAIN)["flags"] & store.F_DISASM)

    def test_export_import_via_run_script(self):
        os.environ["IDAMAP_HOME"] = self.tmp.name
        self.addCleanup(os.environ.pop, "IDAMAP_HOME", None)
        (Path(self.tmp.name) / "exports").mkdir()
        exp = Path(self.tmp.name) / "exports" / "exp.json"
        exp.write_text(json.dumps({
            "idb_path": "/x/t.i64", "sha256": "ab", "processor": "ARM", "bits": 64,
            "segments": [{"name": "__text", "start": 0x1000004B0, "end": 0x100000600, "perms": "r-x", "type": "CODE"}],
            "functions": [[0x1000004B0, 0x100000514, "_decrypt"], [0x100000514, 0x1000005CC, "_main"],
                          [0x1000005CC, 0x100000600, "_check_key"]],
            "edges": [[0x100000514, 0x1000004B0], [0x100000514, 0x1000005CC]]}))
        self.h.call("disasm", {"address": "0x1000005d0"}, "0x1000005d0: STP")  # unresolved at first
        self.h.call("run_script", {"file": "export_map.py"},
                    {"stdout": f"IDAMAP_EXPORT_FILE={exp} functions=3 edges=2\n", "stderr": "", "success": True})
        db = self.conn.execute("SELECT * FROM databases WHERE key='/x/t.i64'").fetchone()
        self.assertIsNotNone(db["map_imported_at"])
        self.assertEqual(db["func_total"], 3)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM edges").fetchone()[0], 2)
        self.assertTrue(self.h.func(CHECK)["flags"] & store.F_DISASM)  # re-resolved

    def test_kernel_addresses(self):
        a = 0xFFFFFFF007004000
        self.assertEqual(store.from_i(store.to_i(a)), a)
        self.h.call("decompile", {"address": hex(a)}, "void __fastcall start(void)\n{}")
        self.assertEqual(self.h.func(a)["name"], "start")

    def test_session_db_switch(self):
        self.h.call("open_idb", {"path": "/y/other"}, {"path": "/y/other.i64", "function_count": 1})
        c = self.h.call("decompile", {"address": "0x10"}, "int f(void)\n{}")
        key = self.conn.execute("SELECT key FROM databases WHERE id=?", (c["db_id"],)).fetchone()[0]
        self.assertEqual(key, "/y/other.i64")


    def test_workspace_database_ids(self):
        self.h.call("open_idb", {"path": "/a/one"}, {"path": "/a/one.i64", "database_id": "ws-1"})
        self.h.call("open_idb", {"path": "/b/two"}, {"path": "/b/two.i64", "database_id": "ws-2"})
        c = self.h.call("decompile", {"address": "0x10", "database_id": "ws-1"}, "int f(void)\n{}")
        key = self.conn.execute("SELECT key FROM databases WHERE id=?", (c["db_id"],)).fetchone()[0]
        self.assertEqual(key, "/a/one.i64")

    def test_search_plain_address_list(self):
        self.h.call("list_functions", {}, LIST_FUNCS)
        self.h.call("search", {"kind": "text", "targets": ["S3CR"]}, {"matches": ["0x1000005e0"], "count": 1})
        self.assertTrue(self.h.func(CHECK)["flags"] & store.F_SEEN)


    def test_same_binary_in_two_idbs_is_one_record(self):
        raw = Path(self.tmp.name) / "app"
        raw.write_bytes(b"\xcf\xfa\xed\xfe" + b"x" * 100)
        db1 = self.h.call("open_idb", {"path": "/x/t"}, {"path": "/x/t.i64"})["db_id"]
        self.h.call("idb_meta", {}, {"sha256": __import__("hashlib").sha256(raw.read_bytes()).hexdigest()})
        self.h.call("list_functions", {}, LIST_FUNCS)
        self.h.call("decompile", {"address": "0x100000514"}, MAIN_DECOMP)
        from idamap import queries
        queries.set_human(self.conn, db1, MAIN, note="first IDB note", set_note=True)
        # the same binary opened from another place creates another IDB path
        c = self.h.call("open_idb", {"path": str(raw)}, {"path": str(raw) + ".i64"})
        self.assertEqual(c["db_id"], db1)
        self.h.call("rename", {"address": "0x1000004b0", "name": "decrypt_buf"},
                    {"address": "0x1000004b0", "name": "decrypt_buf"})
        dbs = self.conn.execute("SELECT id FROM databases").fetchall()
        self.assertEqual([r[0] for r in dbs], [db1])
        f = self.h.func(MAIN, db1)
        self.assertEqual((f["note"], store.stage_of(f["flags"])), ("first IDB note", "decompiled"))
        self.assertEqual(self.h.func(DECRYPT, db1)["name"], "decrypt_buf")
        # reopening the second path resolves to the same record
        self.assertEqual(ingest.upsert_database(self.conn, str(raw) + ".i64"), db1)

    def test_merge_when_hash_arrives_later(self):
        a = self.h.call("open_idb", {"path": "/a/t.i64"}, {"path": "/a/t.i64"})["db_id"]
        self.h.call("idb_meta", {}, {"sha256": "ab" * 32})
        self.h.call("list_functions", {}, LIST_FUNCS)
        self.h.call("decompile", {"address": "0x100000514"}, MAIN_DECOMP)
        b = self.h.call("open_idb", {"path": "/b/t.i64"}, {"path": "/b/t.i64"})["db_id"]
        self.assertNotEqual(a, b)
        self.h.call("list_functions", {}, LIST_FUNCS)
        self.h.call("disasm", {"address": "0x100000514"}, "0x100000514: SUB")
        self.h.call("idb_meta", {}, {"sha256": "ab" * 32})  # now we know it is the same binary
        self.assertEqual(self.conn.execute("SELECT count(*) FROM databases WHERE key IN ('/a/t.i64', '/b/t.i64')").fetchone()[0], 1)
        f = self.h.func(MAIN, a)
        self.assertTrue(f["flags"] & store.F_DECOMP and f["flags"] & store.F_DISASM)
        self.assertEqual(f["touch_count"], 2)
        c = self.h.call("decompile", {"address": "0x1000004b0"}, "int d(void)\n{}")
        self.assertEqual(c["db_id"], a)  # the session follows the merged record


class ParseTests(unittest.TestCase):
    def test_decompiled_name(self):
        self.assertEqual(parse.decompiled_name(MAIN_DECOMP), "main")
        self.assertEqual(parse.decompiled_name("__int64 __fastcall sub_1000(__int64 a1)\n{"), "sub_1000")
        self.assertEqual(parse.decompiled_name("void __cdecl -[Foo bar:](Foo *self, SEL a2)\n{"), None)

    def test_parse_addr(self):
        self.assertEqual(parse.parse_addr("0x10"), 16)
        self.assertEqual(parse.parse_addr(16), 16)
        self.assertIsNone(parse.parse_addr("main"))

    def test_describe(self):
        self.assertEqual(parse.describe_target("rename", {"address": "0x10", "name": "foo"}), "0x10 → foo")


if __name__ == "__main__":
    unittest.main()
