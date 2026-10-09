"""The "guidance followed" measurement: what compliance.compute counts from recorded calls."""

import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from idamap import annotate, compliance, ingest, store

MAIN, DECRYPT, CHECK = 0x100000514, 0x1000004B0, 0x1000005CC
FUNCS = {"functions": [{"address": hex(a), "name": n, "size": 100}
                       for a, n in ((DECRYPT, "_decrypt"), (MAIN, "_main"), (CHECK, "_check_key"))], "total": 3}
OPEN = {"path": "/x/t.i64", "processor": "ARM", "bits": 64, "file_type": "MACHO", "function_count": 3}


def txt(obj):
    return [{"type": "text", "text": obj if isinstance(obj, str) else json.dumps(obj)}]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["IDAMAP_HOME"] = self.tmp.name          # the server in RouteTests reads the same database
        self.conn = store.connect()
        self.n = 0
        self.start("setup", offered=None)
        self.call("setup", "list_functions", {"limit": 99}, FUNCS, offered=None)
        self.db = self.conn.execute("SELECT id FROM databases").fetchone()[0]

    def tearDown(self):
        self.conn.close()
        os.environ.pop("IDAMAP_HOME", None)
        self.tmp.cleanup()

    def call(self, session, tool, inp, out=None, offered=True, error=None):
        """Record one call the way the proxy does (offered: True / False / None = not reported)."""
        self.n += 1
        p = {"session_id": session, "tool_use_id": f"{session}:{self.n}", "tool_name": f"mcp__ida__{tool}",
             "tool_input": inp, "harness": "testclient", "source": "proxy-stdio", "cwd": "/tmp"}
        if offered is not None:
            p["tools_offered"] = offered
        ingest.on_pre(self.conn, p)
        if error is None:
            ingest.on_post(self.conn, {**p, "tool_response": txt({} if out is None else out), "duration_ms": 1}, ok=True)
        else:
            ingest.on_post(self.conn, {**p, "error": error}, ok=False)

    def start(self, session, offered=True):
        self.call(session, "open_idb", {"path": "/x/t"}, OPEN, offered=offered)

    # the calls the guidance is about
    def status(self, s, offered=True):
        self.call(s, "idamap_status", {}, {"binary": "t"}, offered)

    def search(self, s, offered=True):
        self.call(s, "idamap_search", {"query": "key"}, {"results": []}, offered)

    def lookup(self, s, addr, offered=True):
        self.call(s, "idamap_lookup", {"address": [hex(addr)]}, {"results": [{"address": hex(addr), "known": True}]}, offered)

    def decompile(self, s, addr, offered=True):
        self.call(s, "decompile", {"address": hex(addr)}, "int f()\n{\n  return 0;\n}\n", offered)

    def annotate(self, s, addr, offered=True):
        self.call(s, "idamap_annotate", {"address": hex(addr), "summary": "does a thing"}, "Recorded.", offered)

    def result(self):
        return compliance.compute(self.conn, self.db)

    def session(self, r, sid):
        return next(x for x in r["sessions"] if x["id"] == sid)


class MeasureTests(Base):
    def test_a_session_that_follows_the_guidance(self):
        self.start("good")
        self.status("good")
        self.search("good")
        self.lookup("good", MAIN)
        self.decompile("good", MAIN)
        self.annotate("good", MAIN)
        r = self.result()
        s = self.session(r, "good")
        self.assertEqual((s["status"], s["analyzed"], s["looked"], s["explained"], s["searches"], s["guessed"]),
                         ("first", 1, 1, 1, 1, 0))
        self.assertEqual(r["status"], {"first": 1, "late": 0, "never": 0, "of": 1})
        self.assertEqual((r["lookup"], r["explained"]), ({"yes": 1, "of": 1}, {"yes": 1, "of": 1}))
        self.assertEqual(r["search"], {"idamap_search": 1, "guessed_filters": 0})

    def test_a_session_that_ignores_it(self):
        self.start("bad")
        self.call("bad", "list_functions", {"filter": "key"}, FUNCS)       # a guessed filter
        self.call("bad", "list_functions", {"limit": 50}, FUNCS)           # plain enumeration: not counted
        self.decompile("bad", MAIN)
        self.decompile("bad", CHECK)
        r = self.result()
        s = self.session(r, "bad")
        self.assertEqual((s["status"], s["analyzed"], s["looked"], s["explained"], s["searches"], s["guessed"]),
                         ("never", 2, 0, 0, 0, 1))
        self.assertEqual(r["search"], {"idamap_search": 0, "guessed_filters": 1})

    def test_status_after_the_first_investigative_call_is_late(self):
        self.start("late")
        self.decompile("late", MAIN)
        self.status("late")
        self.assertEqual(self.session(self.result(), "late")["status"], "late")

    def test_status_before_a_database_is_open_still_counts_as_first(self):
        self.status("early")                       # called before open_idb: no database yet
        self.start("early")
        self.decompile("early", MAIN)
        self.assertEqual(self.session(self.result(), "early")["status"], "first")

    def test_session_that_never_investigated_has_no_status_verdict(self):
        self.start("idle")
        self.search("idle")                        # idamap's own tools and housekeeping are not "investigating"
        self.start("busy")
        self.status("busy")
        self.decompile("busy", MAIN)
        r = self.result()
        self.assertEqual(self.session(r, "idle")["status"], "na")
        self.assertEqual(r["status"], {"first": 1, "late": 0, "never": 0, "of": 1})

    def test_a_lookup_after_the_analysis_does_not_count(self):
        self.start("order")
        self.decompile("order", MAIN)
        self.lookup("order", MAIN)
        self.assertEqual(self.session(self.result(), "order")["looked"], 0)

    def test_an_explanation_before_the_analysis_does_not_count(self):
        self.start("order")
        self.annotate("order", MAIN)
        self.decompile("order", MAIN)
        self.assertEqual(self.session(self.result(), "order")["explained"], 0)

    def test_only_the_function_that_was_looked_up_counts(self):
        self.start("two")
        self.lookup("two", MAIN)
        self.decompile("two", MAIN)
        self.decompile("two", CHECK)
        s = self.session(self.result(), "two")
        self.assertEqual((s["analyzed"], s["looked"]), (2, 1))

    def test_failed_analysis_is_not_counted(self):
        self.start("err")
        self.call("err", "decompile", {"address": hex(MAIN)}, error="decompilation failed")
        self.assertEqual(self.session(self.result(), "err")["analyzed"], 0)

    def test_numbers_add_up_across_sessions(self):
        for sid, look in (("a", True), ("b", False)):
            self.start(sid)
            self.status(sid)
            if look:
                self.lookup(sid, MAIN)
            self.decompile(sid, MAIN)
        r = self.result()
        self.assertEqual((r["measured"], r["lookup"]), (2, {"yes": 1, "of": 2}))


class WhoIsMeasuredTests(Base):
    def test_sessions_without_idamap_tools_are_left_out(self):
        self.start("off", offered=False)           # a proxy without the tools
        self.decompile("off", MAIN, offered=False)
        self.start("hook", offered=None)           # origin unknown, never used an idamap tool
        self.decompile("hook", CHECK, offered=None)
        r = self.result()
        self.assertEqual(r["measured"], 0)
        self.assertEqual(r["unmeasured"], 3)       # these two and the setup session

    def test_offered_but_unused_counts_as_not_following(self):
        self.start("ignored", offered=True)        # tools were on, the model never touched them
        self.decompile("ignored", MAIN, offered=True)
        r = self.result()
        self.assertEqual((r["measured"], r["inferred"]), (1, 0))
        self.assertEqual(self.session(r, "ignored")["status"], "never")

    def test_old_sessions_count_only_if_they_used_a_tool_and_are_flagged_inferred(self):
        self.start("old", offered=None)
        self.status("old", offered=None)
        self.decompile("old", MAIN, offered=None)
        r = self.result()
        self.assertEqual((r["measured"], r["inferred"]), (1, 1))
        self.assertTrue(self.session(r, "old")["inferred"])

    def test_offer_is_never_downgraded(self):
        self.start("s", offered=True)
        self.decompile("s", MAIN, offered=False)   # a later call that says "not offered" must not erase it
        self.assertEqual(self.conn.execute("SELECT tools_offered FROM sessions WHERE id='s'").fetchone()[0], 1)

    def test_offer_reaches_the_hook_session_of_a_duplicate_call(self):
        """Claude Code hooks + proxy: the proxy's copy of a call is dropped, its offer must still be kept."""
        hook = {"session_id": "cc", "prompt_id": "p", "tool_name": "mcp__ida__decompile", "tool_input": {"address": hex(MAIN)},
                "tool_use_id": "toolu_1", "cwd": "/tmp", "transcript_path": None, "hook_event_name": "PreToolUse"}
        ingest.handle(self.conn, hook)
        self.assertIsNone(self.conn.execute("SELECT tools_offered FROM sessions WHERE id='cc'").fetchone()[0])
        proxy = {"session_id": "stdio-1", "tool_use_id": "stdio-1:1", "tool_name": "mcp__ida__decompile",
                 "tool_input": {"address": hex(MAIN)}, "source": "proxy-stdio", "harness": "claude-code",
                 "host_tool_use_id": "toolu_1", "tools_offered": True}
        self.assertIsNone(ingest.on_pre(self.conn, proxy))                 # recognised as the hook's call
        self.assertEqual(self.conn.execute("SELECT tools_offered FROM sessions WHERE id='cc'").fetchone()[0], 1)
        self.assertIsNone(self.conn.execute("SELECT 1 FROM sessions WHERE id='stdio-1'").fetchone())


class KnownFunctionTests(Base):
    def explain(self, addr):
        """An explanation recorded by an earlier session."""
        self.start("before")
        annotate.store_annotation(self.conn, "before", "testclient", {"address": hex(addr), "summary": "does a thing"}, None)
        time.sleep(0.02)                              # later sessions must start after it

    def test_re_reading_an_explained_function_blind(self):
        self.explain(MAIN)
        self.start("blind")
        self.decompile("blind", MAIN)
        self.start("careful")
        self.lookup("careful", MAIN)
        self.decompile("careful", MAIN)
        r = self.result()
        self.assertEqual(r["known"], {"of": 2, "looked_up": 1, "blind": 1})
        self.assertEqual((self.session(r, "blind")["known"], self.session(r, "blind")["known_looked"]), (1, 0))

    def test_a_rejected_explanation_is_not_known(self):
        self.explain(CHECK)
        self.conn.execute("UPDATE annotations SET status='rejected'")
        self.start("later")
        self.decompile("later", CHECK)
        self.assertEqual(self.result()["known"]["of"], 0)

    def test_an_explanation_made_during_the_session_is_not_a_missed_lookup(self):
        self.start("same")
        self.decompile("same", MAIN)
        annotate.store_annotation(self.conn, "same", "testclient", {"address": hex(MAIN), "summary": "x"}, None)
        self.decompile("same", MAIN)
        self.assertEqual(self.result()["known"]["of"], 0)


class RobustnessTests(Base):
    def test_calls_whose_session_row_is_missing_do_not_break_it(self):
        self.start("gone")
        self.status("gone")
        self.decompile("gone", MAIN)
        self.conn.execute("DELETE FROM sessions WHERE id='gone'")
        self.assertEqual(self.result()["measured"], 0)


class StorageTests(unittest.TestCase):
    def test_old_database_gains_the_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            raw = sqlite3.connect(path)
            raw.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY, harness TEXT, source TEXT, cwd TEXT, "
                        "transcript_path TEXT, db_id INTEGER, started_at REAL, last_seen REAL)")
            raw.execute("INSERT INTO sessions(id, started_at) VALUES ('s', 1)")
            raw.commit()
            raw.close()
            conn = store.connect(path)
            cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
            self.assertIn("tools_offered", cols)
            self.assertIsNone(conn.execute("SELECT tools_offered FROM sessions").fetchone()[0])
            conn.close()

    def test_empty_database_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.connect(Path(tmp) / "e.db")
            r = compliance.compute(conn, 1)
            self.assertEqual((r["measured"], r["unmeasured"], r["sessions"]), (0, 0, []))
            conn.close()


class RouteTests(Base):
    def test_compliance_endpoint(self):
        from idamap import server

        self.start("good")
        self.status("good")
        self.decompile("good", MAIN)
        httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{httpd.server_port}/api/db/{self.db}/compliance") as resp:
                data = json.load(resp)
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(data["measured"], 1)
        self.assertEqual(data["status"]["first"], 1)


if __name__ == "__main__":
    unittest.main()
