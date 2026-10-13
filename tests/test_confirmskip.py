import json
import os
import tempfile
import unittest
from pathlib import Path

from confirmskip.core import analyze, load, load_dangerous_list
from confirmskip.cli import main

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


class TestCore(unittest.TestCase):
    def test_safe_trace_no_findings(self):
        r = analyze(load(str(EXAMPLES / "safe.jsonl")))
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["dangerous_calls"], 1)

    def test_unsafe_trace_findings(self):
        r = analyze(load(str(EXAMPLES / "unsafe.jsonl")))
        tools = {f["tool"] for f in r["findings"]}
        self.assertIn("send_email", tools)
        self.assertIn("deploy", tools)
        self.assertIn("shell", tools)
        # shell with rm -rf should be high
        shell = next(f for f in r["findings"] if f["tool"] == "shell")
        self.assertEqual(shell["severity"], "high")

    def test_lookback_too_small_misses_confirm(self):
        # confirmation is 1 event before the tool call in safe.jsonl;
        # lookback=0 means no prior events count -> finding
        r = analyze(load(str(EXAMPLES / "safe.jsonl")), lookback=0)
        self.assertTrue(any(f["tool"] == "send_email" for f in r["findings"]))

    def test_explicit_approval_event(self):
        events = [
            {"role": "user", "content": "email them", "_line": 1},
            {"type": "approval", "_line": 2},
            {"tool": "send_email", "args": {"to": "a@b.c"}, "role": "assistant", "_line": 3},
        ]
        r = analyze(events, lookback=5)
        self.assertEqual(r["findings"], [])

    def test_approval_flag(self):
        events = [
            {"role": "user", "content": "whatever", "approval": True, "_line": 1},
            {"role": "assistant", "tool_calls": [{"name": "deploy", "args": {}}], "_line": 2},
        ]
        r = analyze(events)
        self.assertEqual(r["findings"], [])

    def test_custom_dangerous_list(self):
        events = [
            {"role": "user", "content": "read the file", "_line": 1},
            {"tool": "read_file", "args": {"path": "x"}, "_line": 2},
        ]
        r = analyze(events, dangerous=["read_file"])
        self.assertEqual(len(r["findings"]), 1)
        self.assertEqual(r["findings"][0]["matched_rule"], "read_file")

    def test_shell_medium_without_destructive_args(self):
        events = [
            {"role": "user", "content": "list files", "_line": 1},
            {"tool": "shell", "args": {"cmd": "ls -la"}, "_line": 2},
        ]
        r = analyze(events)
        self.assertEqual(len(r["findings"]), 1)
        self.assertEqual(r["findings"][0]["severity"], "medium")

    def test_load_dangerous_list(self):
        names = load_dangerous_list(str(EXAMPLES / "dangerous.txt"))
        self.assertEqual(names, ["send_email", "deploy", "merge_pr"])

    def test_skips_tool_result_lines(self):
        events = [
            {"role": "tool", "tool": "send_email", "result": "ok", "_line": 1},
        ]
        r = analyze(events)
        self.assertEqual(r["tool_calls"], 0)
        self.assertEqual(r["findings"], [])

    def test_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write("{not json\n")
            path = f.name
        try:
            with self.assertRaises(ValueError):
                load(path)
        finally:
            os.unlink(path)


class TestCLI(unittest.TestCase):
    def test_cli_safe_exit_0(self):
        self.assertEqual(main([str(EXAMPLES / "safe.jsonl")]), 0)

    def test_cli_unsafe_fail_on_high(self):
        self.assertEqual(main([str(EXAMPLES / "unsafe.jsonl"), "--fail-on", "high"]), 1)

    def test_cli_json_output(self):
        # smoke: should not crash; capture via analyzing again
        code = main([str(EXAMPLES / "safe.jsonl"), "--json", "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_cli_custom_dangerous_file(self):
        # with only send_email/deploy/merge_pr, shell in unsafe.jsonl is ignored
        code = main([
            str(EXAMPLES / "unsafe.jsonl"),
            "--dangerous-file", str(EXAMPLES / "dangerous.txt"),
            "--fail-on", "high",
        ])
        self.assertEqual(code, 1)  # send_email + deploy still high


if __name__ == "__main__":
    unittest.main()
