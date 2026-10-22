import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class InvestigatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai = load_module("ai_investigator_safe_test", "ai_investigator.py")
        cls.ingest = load_module("ingest_evidence_safe_test", "ingest_evidence.py")

    def test_search_and_details_are_local(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.json"
            path.write_text(json.dumps({"records": [
                {"event_id": "4624", "username": "alice", "source_file": "Security.evtx",
                 "source_row": 1, "message": "logon"},
                {"event_id": "4688", "username": "bob", "source_file": "Security.evtx",
                 "source_row": 2, "message": "process"}
            ]}), encoding="utf-8")
            previous = self.ai.DATA_PATH
            self.ai.DATA_PATH = path
            try:
                found = self.ai.search_events(event_id="4624", limit=99)
                self.assertEqual(found["total_matches"], 1)
                self.assertEqual(found["returned"][0]["username"], "alice")
                self.assertTrue(self.ai.get_event_details("Security.evtx", 2)["found"])
                self.assertTrue(self.ai.build_timeline(limit=1)["truncated"])
            finally:
                self.ai.DATA_PATH = previous

    def test_usage_accounting_and_output_cap_without_network(self):
        class FakeResponse:
            output = []
            output_text = "mock result"
            usage = types.SimpleNamespace(input_tokens=123, output_tokens=45, total_tokens=168)

        class FakeResponses:
            kwargs = None
            def create(self, **kwargs):
                self.kwargs = kwargs
                return FakeResponse()

        fake_responses = FakeResponses()
        class FakeClient:
            def __init__(self):
                self.responses = fake_responses

        previous_openai, previous_data = self.ai.OpenAI, self.ai.DATA_PATH
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.json"
            path.write_text(json.dumps({"records": [{"event_id": "4624"}]}), encoding="utf-8")
            self.ai.DATA_PATH = path
            self.ai.OpenAI = FakeClient
            try:
                answer = self.ai.investigate("summarise one event")
                self.assertEqual(answer, "mock result")
                self.assertEqual(fake_responses.kwargs["max_output_tokens"], self.ai.MAX_OUTPUT_TOKENS)
                self.assertEqual(self.ai.LAST_USAGE["input_tokens"], 123)
                self.assertEqual(self.ai.LAST_USAGE["output_tokens"], 45)
            finally:
                self.ai.OpenAI, self.ai.DATA_PATH = previous_openai, previous_data

    def test_report_includes_usage_metadata(self):
        previous_reports, previous_data = self.ai.REPORTS_DIR, self.ai.DATA_PATH
        with tempfile.TemporaryDirectory() as td:
            self.ai.REPORTS_DIR = Path(td)
            data_path = Path(td) / "events.json"
            data_path.write_text(json.dumps({"records": []}), encoding="utf-8")
            self.ai.DATA_PATH = data_path
            try:
                report_path = self.ai._write_report(
                    "test question", "test finding",
                    {"model": "test-model", "requests": 1, "input_tokens": 20,
                     "output_tokens": 5, "estimated_cost_usd": 0.0012,
                     "cost_note": "test cost note"},
                )
                content = report_path.read_text(encoding="utf-8")
                self.assertIn("## API usage", content)
                self.assertIn("Input tokens reported", content)
                self.assertIn("$0.001200", content)
            finally:
                self.ai.REPORTS_DIR, self.ai.DATA_PATH = previous_reports, previous_data

    def test_evtx_bad_record_is_skipped_and_reported(self):
        class FakeRecord:
            def __init__(self, bad=False):
                self.bad = bad
            def xml(self):
                if self.bad:
                    raise ValueError("mock malformed event")
                return (
                    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                    '<System><Provider Name="Test"/><EventID>4624</EventID>'
                    '<EventRecordID>12</EventRecordID><Channel>Security</Channel>'
                    '<Computer>HOST</Computer>'
                    '<TimeCreated SystemTime="2026-10-22T20:00:00Z"/></System>'
                    '<EventData><Data Name="TargetUserName">alice</Data></EventData></Event>'
                )
        class FakeLog:
            def __init__(self, path):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def records(self):
                return iter([FakeRecord(True), FakeRecord(False)])

        previous_evtx = self.ingest.Evtx
        self.ingest.Evtx = FakeLog
        try:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td) / "collection"
                root.mkdir()
                (root / "test.evtx").write_bytes(b"mock")
                messages = []
                result = self.ingest.ingest_collection(
                    root, Path(td) / "reports" / "events.json",
                    progress_callback=messages.append,
                )
                self.assertEqual(result["record_count"], 1)
                self.assertTrue(any("XML errors skipped: 1" in message for message in messages))
        finally:
            self.ingest.Evtx = previous_evtx


if __name__ == "__main__":
    unittest.main(verbosity=2)
