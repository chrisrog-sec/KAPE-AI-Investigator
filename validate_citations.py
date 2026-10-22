from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx


PROJECT = Path(__file__).resolve().parent
REPORTS = PROJECT / "reports"
DEFAULT_REPORT = REPORTS / "ai_investigation_report_20261022_232252.md"
DATA_FILE = REPORTS / "events_normalized.json"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def norm_path(value: str) -> str:
    """Normalize evidence paths for comparisons across Windows/Python formats."""
    value = value.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.casefold()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def timestamp_equal(expected: object, actual: object) -> bool:
    """Compare timestamps as datetimes, not as differently formatted strings."""
    expected_dt = datetime.fromisoformat(str(expected).strip().replace("Z", "+00:00"))
    actual_dt = datetime.fromisoformat(str(actual).strip().replace("Z", "+00:00"))
    return expected_dt == actual_dt


def extract_citations(report: str) -> list[tuple[str, int]]:
    """
    Extract EVTX citations from common report formats:
      * a file and source_row on the same line
      * a shared EVTX file line followed by a table of source_row values

    This is deliberately conservative. It does not claim to find citations
    that use an unrecognized format.
    """
    citations: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    current_file: str | None = None

    file_pattern = re.compile(r"`([^`\r\n]+\.evtx)`", re.IGNORECASE)
    row_pattern = re.compile(r"\bsource_row\s+(\d+)\b", re.IGNORECASE)

    for line in report.splitlines():
        file_match = file_pattern.search(line)
        if file_match:
            current_file = file_match.group(1).strip()

        row_matches = row_pattern.findall(line)
        if not row_matches or not current_file:
            continue

        for row_text in row_matches:
            citation = (current_file, int(row_text))
            if citation not in seen:
                seen.add(citation)
                citations.append(citation)

    return citations


def parse_original_event(xml_text: str) -> dict[str, object]:
    root = ET.fromstring(xml_text)
    system = root.find("e:System", NS)
    if system is None:
        raise ValueError("Missing System element")

    provider = system.find("e:Provider", NS)
    time_created = system.find("e:TimeCreated", NS)

    return {
        "source_record_id": system.findtext("e:EventRecordID", namespaces=NS),
        "event_id": system.findtext("e:EventID", namespaces=NS),
        "provider": provider.attrib.get("Name") if provider is not None else None,
        "channel": system.findtext("e:Channel", namespaces=NS),
        "computer": system.findtext("e:Computer", namespaces=NS),
        "timestamp": time_created.attrib.get("SystemTime") if time_created is not None else None,
    }


def main() -> int:
    report_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_REPORT

    if not report_path.is_file():
        print(f"ERROR: Report not found: {report_path}")
        return 2
    if not DATA_FILE.is_file():
        print(f"ERROR: Normalized dataset not found: {DATA_FILE}")
        return 2

    report = report_path.read_text(encoding="utf-8", errors="replace")
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    evidence_root = Path(data["source_root"])

    inventory = {
        norm_path(item["source_file"]): item
        for item in data.get("source_files", [])
        if item.get("source_file")
    }

    records_by_key: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for record in data.get("records", []):
        try:
            key = (norm_path(record["source_file"]), int(record["source_row"]))
            records_by_key[key].append(record)
        except (KeyError, TypeError, ValueError):
            continue

    citations = extract_citations(report)
    if not citations:
        print("UNVERIFIED: No explicit EVTX source_file/source_row citations were extracted.")
        print("Report:", report_path)
        print("No evidence files were changed.")
        return 1

    # Caches prevent hashing and parsing the same original log for every citation.
    hash_cache: dict[str, str] = {}
    evtx_cache: dict[str, dict[int, list[str]]] = {}
    results: list[tuple[str, str, int, list[str]]] = []

    for source_file, source_row in citations:
        key = (norm_path(source_file), source_row)
        normalized_matches = records_by_key.get(key, [])

        if len(normalized_matches) != 1:
            status = "FAIL" if len(normalized_matches) > 1 else "UNVERIFIED"
            results.append((
                status, source_file, source_row,
                [f"Expected exactly one normalized record; found {len(normalized_matches)}."]
            ))
            continue

        record = normalized_matches[0]
        inventory_item = inventory.get(norm_path(source_file))
        if not inventory_item:
            results.append(("UNVERIFIED", source_file, source_row,
                            ["No matching source inventory entry."]))
            continue

        relative_path = Path(*source_file.replace("\\", "/").split("/"))
        original_path = evidence_root / relative_path
        if not original_path.is_file():
            results.append(("UNVERIFIED", source_file, source_row,
                            [f"Original file not found: {original_path}"]))
            continue

        file_key = str(original_path).casefold()
        if file_key not in hash_cache:
            hash_cache[file_key] = sha256_file(original_path)

        actual_hash = hash_cache[file_key]
        expected_hash = str(inventory_item.get("sha256", "")).lower()

        if not expected_hash or actual_hash != expected_hash:
            results.append(("FAIL", source_file, source_row,
                            ["Original file SHA-256 does not match the inventory."]))
            continue

        if str(record.get("source_sha256", "")).lower() != actual_hash:
            results.append(("FAIL", source_file, source_row,
                            ["Normalized record SHA-256 does not match the original file."]))
            continue

        try:
            target_record_id = int(record["source_record_id"])
        except (KeyError, TypeError, ValueError):
            results.append(("UNVERIFIED", source_file, source_row,
                            ["Normalized record has no usable source_record_id."]))
            continue

        if file_key not in evtx_cache:
            records_by_id: dict[int, list[str]] = defaultdict(list)
            with Evtx(str(original_path)) as log:
                for evtx_record in log.records():
                    records_by_id[evtx_record.record_num()].append(evtx_record.xml())
            evtx_cache[file_key] = records_by_id

        xml_matches = evtx_cache[file_key].get(target_record_id, [])
        if len(xml_matches) != 1:
            results.append((
                "UNVERIFIED", source_file, source_row,
                [f"Original EVTX EventRecordID {target_record_id}: found {len(xml_matches)} matches."]
            ))
            continue

        try:
            original = parse_original_event(xml_matches[0])
        except Exception as exc:
            results.append(("UNVERIFIED", source_file, source_row,
                            [f"Could not parse original EVTX XML: {exc}"]))
            continue

        mismatches = []
        for field, actual in original.items():
            expected = record.get(field)
            if expected is None or actual is None:
                mismatches.append(f"{field}: missing value (normalized={expected!r}, original={actual!r})")
            elif field == "timestamp":
                try:
                    if not timestamp_equal(expected, actual):
                        mismatches.append(
                            f"{field}: normalized={expected!r}, original={actual!r}"
                        )
                except (TypeError, ValueError):
                    mismatches.append(
                        f"{field}: timestamp parse failed (normalized={expected!r}, original={actual!r})"
                    )
            elif str(expected).strip() != str(actual).strip():
                mismatches.append(
                    f"{field}: normalized={expected!r}, original={actual!r}"
                )

        if mismatches:
            results.append(("FAIL", source_file, source_row, mismatches))
        else:
            results.append((
                "PASS", source_file, source_row,
                ["Normalized citation, original file SHA-256, and original EVTX system fields match."]
            ))

    print("KAPE AI Investigator | Citation Validation")
    print("=" * 60)
    print("Report:", report_path.name)
    print("Evidence root:", evidence_root)
    print("Normalized records:", len(data.get("records", [])))
    print("Unique citations extracted:", len(citations))
    print()

    counts = {"PASS": 0, "FAIL": 0, "UNVERIFIED": 0}
    for status, source_file, source_row, notes in results:
        counts[status] += 1
        print(f"[{status}] {source_file} | source_row {source_row}")
        for note in notes:
            print("       " + note)

    print()
    print("SUMMARY")
    print("PASS:", counts["PASS"])
    print("FAIL:", counts["FAIL"])
    print("UNVERIFIED:", counts["UNVERIFIED"])
    print("API calls: 0")
    print("Evidence writes: 0")
    print()
    print("PASS verifies extracted citations, file hashes, and original EVTX system fields.")
    print("It does not verify the analyst's interpretation or every XML payload field.")
    print("Review the report manually for citations the parser may not have extracted.")

    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
