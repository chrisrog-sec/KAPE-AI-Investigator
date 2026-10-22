import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import recover_checkpoints


class RecoveryTests(unittest.TestCase):
    def make_checkpoint(self, root: Path, checkpoints: Path, rel: str, content: bytes, records=1):
        source = root.joinpath(*rel.split("/"))
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        recs = [{
            "timestamp": "2026-01-01T00:00:00+00:00",
            "source_file": rel,
            "source_sha256": digest,
            "source_record_id": i + 1,
            "evidence_format": "EVTX",
        } for i in range(records)]
        cp = {
            "checkpoint_version": 1,
            "source_file": rel,
            "source_sha256": digest,
            "summary": {
                "source_file": rel,
                "format": "evtx",
                "sha256": digest,
                "records_parsed": records,
                "status": "parsed",
            },
            "records": recs,
        }
        name = hashlib.sha256(rel.encode("utf-8")).hexdigest() + ".json"
        (checkpoints / name).write_text(json.dumps(cp), encoding="utf-8")
        return source, name

    def test_recovers_only_hash_valid_checkpoints_and_preserves_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "evidence"
            checkpoints = base / "reports" / ".ingestion_checkpoints"
            checkpoints.mkdir(parents=True)
            self.make_checkpoint(root, checkpoints, "C/Windows/a.evtx", b"evidence", 3)
            source, name = self.make_checkpoint(root, checkpoints, "C/Windows/b.evtx", b"other", 2)
            source.write_bytes(b"changed after checkpoint")
            output = base / "reports" / "events_normalized.json"

            payload = recover_checkpoints.recover(root, checkpoints, output)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["record_count"], 3)
            self.assertEqual(saved["record_count"], 3)
            self.assertEqual(saved["schema_version"], 2)
            self.assertEqual(saved["source_file_count"], 1)
            self.assertTrue(any(name in issue and "SHA-256 mismatch" in issue
                                for issue in saved["ingestion"]["checkpoint_issues"]))
            self.assertTrue(all(r["source_file"] == "C/Windows/a.evtx" for r in saved["records"]))

    def test_existing_output_is_backed_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "evidence"
            checkpoints = base / "checkpoints"
            checkpoints.mkdir()
            self.make_checkpoint(root, checkpoints, "a.evtx", b"evidence", 1)
            output = base / "events.json"
            output.write_text('{"old": true}', encoding="utf-8")

            payload = recover_checkpoints.recover(root, checkpoints, output)
            backup = Path(payload["ingestion"]["output_backup"])
            self.assertTrue(backup.is_file())
            self.assertEqual(json.loads(backup.read_text(encoding="utf-8")), {"old": True})
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["record_count"], 1)

    def test_no_valid_checkpoint_does_not_touch_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "evidence"
            checkpoints = base / "checkpoints"
            checkpoints.mkdir()
            self.make_checkpoint(root, checkpoints, "a.evtx", b"evidence", 1)
            (root / "a.evtx").write_bytes(b"modified")
            output = base / "events.json"
            output.write_text('{"keep": true}', encoding="utf-8")

            with self.assertRaises(ValueError):
                recover_checkpoints.recover(root, checkpoints, output)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"keep": True})


if __name__ == "__main__":
    unittest.main()
