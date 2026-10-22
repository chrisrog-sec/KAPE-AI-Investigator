"""
KAPE AI Investigator - Step 3
Read-only CSV event normaliser and search tool.

This is a starter for structured CSV exports. It does not parse raw EVTX files.
It reads CSVs under evidence/ and writes a separate JSON file under reports/.
"""
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = (PROJECT_DIR / "evidence").resolve()
REPORTS_DIR = PROJECT_DIR / "reports"

# Map common CSV header variants to our canonical field names.
ALIASES = {
    "timestamp": {"timestamp", "timecreated", "time_created", "datetime", "date_time", "time"},
    "computer": {"computer", "hostname", "host", "system"},
    "channel": {"channel", "logname", "log_name"},
    "provider": {"provider", "source", "eventsource", "event_source"},
    "event_id": {"eventid", "event_id", "id"},
    "level": {"level", "severity", "eventlevel", "event_level"},
    "username": {"username", "user", "account", "targetusername", "target_user_name"},
    "source_ip": {"sourceip", "source_ip", "ipaddress", "ip_address", "clientip"},
    "process_name": {"processname", "process_name", "image", "process"},
    "message": {"message", "description", "details", "eventdata", "event_data"},
}

def clean_header(value: str) -> str:
    return "".join(ch.lower() for ch in value.strip() if ch.isalnum() or ch == "_")

def canonicalise_headers(headers: list[str]) -> dict[str, str]:
    result = {}
    alias_to_field = {}
    for field, aliases in ALIASES.items():
        for alias in aliases:
            alias_to_field[clean_header(alias)] = field
    for header in headers:
        key = clean_header(header)
        if key in alias_to_field and alias_to_field[key] not in result:
            result[alias_to_field[key]] = header
    return result

def parse_timestamp(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    candidate = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(candidate)
        if dt.tzinfo is None:
            # Preserve ambiguity instead of silently assuming local time.
            return "UNSPECIFIED_TIMEZONE:" + value
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return "UNPARSED_TIMESTAMP:" + value

def normalise_csv(path: Path) -> list[dict]:
    records = []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return records
        mapping = canonicalise_headers(reader.fieldnames)
        if not mapping:
            return records

        for row_number, row in enumerate(reader, start=2):
            record = {
                "source_file": str(path.relative_to(EVIDENCE_DIR)),
                "source_row": row_number,
            }
            for field, header in mapping.items():
                value = (row.get(header) or "").strip()
                if field == "timestamp":
                    record[field] = parse_timestamp(value)
                elif field == "event_id":
                    record[field] = value
                else:
                    record[field] = value[:4000]
            records.append(record)
    return records

def load_records() -> list[dict]:
    all_records = []
    for path in sorted(EVIDENCE_DIR.rglob("*.csv")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            resolved = path.resolve()
            if not resolved.is_relative_to(EVIDENCE_DIR):
                continue
            all_records.extend(normalise_csv(resolved))
        except (OSError, ValueError, csv.Error) as exc:
            print(f"Warning: skipped {path}: {type(exc).__name__}: {exc}")
    return all_records

def main() -> int:
    parser = argparse.ArgumentParser(description="Normalise/search CSV event exports")
    parser.add_argument("--query", help="Case-insensitive search across normalised fields")
    parser.add_argument("--event-id", help="Filter by event ID")
    parser.add_argument("--user", help="Filter by username")
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()

    if args.limit < 1 or args.limit > 500:
        parser.error("--limit must be between 1 and 500")
    if not EVIDENCE_DIR.is_dir():
        parser.error(f"Evidence directory not found: {EVIDENCE_DIR}")

    records = load_records()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = REPORTS_DIR / "events_normalized.json"
    output_path.write_text(
        json.dumps({
            "schema_version": 1,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "record_count": len(records),
            "records": records,
            "note": "Normalised from CSV only. Original source files are not modified.",
        }, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    matches = records
    if args.event_id:
        matches = [r for r in matches if r.get("event_id", "").casefold() == args.event_id.casefold()]
    if args.user:
        matches = [r for r in matches if args.user.casefold() in r.get("username", "").casefold()]
    if args.query:
        query = args.query.casefold()
        matches = [
            r for r in matches
            if query in json.dumps(r, ensure_ascii=False).casefold()
        ]

    print(f"Normalised records: {len(records)}")
    print(f"Matching records: {len(matches)}")
    for record in matches[:args.limit]:
        print(json.dumps(record, ensure_ascii=False))
    print(f"JSON output: {output_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
