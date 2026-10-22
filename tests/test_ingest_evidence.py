import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ingest_evidence as ingest

SAMPLE_XML = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
 <Provider Name="Microsoft-Windows-Security-Auditing"/>
 <EventID>4625</EventID><Level>0</Level>
 <TimeCreated SystemTime="2026-10-20T09:14:00.000Z"/>
 <EventRecordID>1234</EventRecordID><Channel>Security</Channel><Computer>LAB-WIN10</Computer>
</System>
<EventData>
 <Data Name="TargetUserName">analyst</Data><Data Name="IpAddress">192.0.2.44</Data>
 <Data Name="LogonType">3</Data>
</EventData></Event>'''


class IngestEvidenceTests(unittest.TestCase):
    def test_evtx_xml_normalisation_preserves_citations(self):
        record = ingest.normalise_evtx_xml(
            SAMPLE_XML, source_file='Windows/System.evtx', source_record=7,
            source_sha256='a' * 64,
        )
        self.assertIsNotNone(record)
        self.assertEqual(record['event_id'], '4625')
        self.assertEqual(record['username'], 'analyst')
        self.assertEqual(record['source_ip'], '192.0.2.44')
        self.assertEqual(record['source_file'], 'Windows/System.evtx')
        self.assertEqual(record['source_row'], 7)
        self.assertEqual(record['source_record_id'], 1234)
        self.assertEqual(record['source_sha256'], 'a' * 64)
        self.assertEqual(record['timestamp'], '2026-10-20T09:14:00+00:00')

    def test_ingest_csv_writes_file_hash_and_record_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'collection'
            root.mkdir()
            source = root / 'Export.csv'
            source.write_text(
                'Timestamp,Computer,Channel,Provider,EventID,Username,SourceIP,Message\n'
                '2026-10-20T09:14:00Z,LAB-WIN10,Security,Test,4625,analyst,192.0.2.44,Failed login\n',
                encoding='utf-8',
            )
            output = Path(td) / 'reports' / 'events_normalized.json'
            result = ingest.ingest_collection(root, output)
            self.assertEqual(result['record_count'], 1)
            record = result['records'][0]
            self.assertEqual(record['source_file'], 'Export.csv')
            self.assertEqual(record['source_row'], 2)
            self.assertEqual(record['event_id'], '4625')
            self.assertEqual(record['source_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(json.loads(output.read_text(encoding='utf-8'))['record_count'], 1)

    def test_unsupported_files_are_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'collection'
            root.mkdir()
            (root / 'notes.txt').write_text('not an event log', encoding='utf-8')
            result = ingest.ingest_collection(root, Path(td) / 'out.json')
            self.assertEqual(result['source_file_count'], 0)
            self.assertEqual(result['record_count'], 0)

    def test_evtx_dependency_error_is_reported_per_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'collection'
            root.mkdir()
            (root / 'Security.evtx').write_bytes(b'not a real evtx')
            with patch.object(ingest, 'Evtx', None):
                result = ingest.ingest_collection(root, Path(td) / 'out.json')
            self.assertEqual(result['record_count'], 0)
            self.assertEqual(result['source_files'][0]['status'], 'error')
            self.assertIn('python -m pip install -r requirements.txt', result['source_files'][0]['error'])


if __name__ == '__main__':
    unittest.main()
