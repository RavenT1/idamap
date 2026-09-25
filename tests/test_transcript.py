"""Intent attribution against a synthetic transcript shaped like Claude Code's JSONL."""

import json
import tempfile
import unittest

from idamap import transcript as T


def entry(kind, content, **kw):
    return {"type": kind, "message": {"role": kind, "content": content}, **kw}


ROWS = [
    entry("user", "reverse the decryptor", promptId="p1"),
    entry("assistant", [{"type": "text", "text": "Opening the database."}]),
    entry("assistant", [{"type": "tool_use", "id": "t_open", "name": "mcp__ida__open_idb"}]),
    entry("user", [{"type": "tool_result", "tool_use_id": "t_open"}]),
    entry("assistant", [{"type": "text", "text": "Decompiling both candidates in parallel."}]),
    entry("assistant", [{"type": "tool_use", "id": "t_a", "name": "mcp__ida__decompile"}]),
    entry("assistant", [{"type": "tool_use", "id": "t_b", "name": "mcp__ida__decompile"}]),
    entry("user", [{"type": "tool_result", "tool_use_id": "t_a"}]),
    entry("user", [{"type": "tool_result", "tool_use_id": "t_b"}]),
    entry("assistant", [{"type": "tool_use", "id": "t_silent", "name": "mcp__ida__xrefs_to"}]),
]


class TranscriptTests(unittest.TestCase):
    def setUp(self):
        self.f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        for r in ROWS:
            self.f.write(json.dumps(r) + "\n")
        self.f.close()

    def test_intent_is_text_of_same_round(self):
        self.assertEqual(T.intent_for(self.f.name, "t_open"), "Opening the database.")
        self.assertEqual(T.intent_for(self.f.name, "t_a"), "Decompiling both candidates in parallel.")
        self.assertEqual(T.intent_for(self.f.name, "t_b"), "Decompiling both candidates in parallel.")

    def test_no_text_in_round_means_no_intent(self):
        # must not inherit the previous round's sentence
        self.assertIsNone(T.intent_for(self.f.name, "t_silent"))

    def test_tool_use_not_written_yet(self):
        # PreToolUse fires before the assistant message reaches the transcript
        self.assertIsNone(T.intent_for(self.f.name, "t_future"))

    def test_prompt_text(self):
        self.assertEqual(T.prompt_text(self.f.name, "p1"), "reverse the decryptor")


if __name__ == "__main__":
    unittest.main()
