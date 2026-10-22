"""Safely normalise supported KAPE outputs (EVTX and structured CSV) with provenance."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    from Evtx.Evtx import Evtx  # provided by the optional python-evtx package
except ImportError:  # clear error only if an EVTX file is actually encountered
    Evtx = None  # type: ignore[assignment,misc]

EVTX_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
ALIASES = {
    "timestamp": {"timestamp", "timecreated", "time_created", "datetime", "date_time", "time"},
    "computer": {"computer", "hostname", "host", "system"},
    "channel": {"channel", "logname", "log_name"},
    "provider": {"provider", "source", "eventsource", "event_source"},
    "event_id": {"eventid", "event_id", "id"},
    "level": {"level", "severity", "eventlevel", "event_level"},
    "username": {"username", "user", "account", "targetusername", "target_user_name", "subjectusername"},
    "source_ip": {"sourceip", "source_ip", "ipaddress", "ip_address", "clientip"},
    "process_name": {"processname", "process_name", "image", "process", "newprocessname"},
    "message": {"message", "description", "details", "eventdata", "event_data", "commandline"},
}


def _clean(value: str) -> str:
    return "".join(c.lower() for c in value.strip() if c.isalnum() or c == "_")


def _canonical_headers(headers: list[str]) -> dict[str, str]:
    lookup = {_clean(alias): field for field, aliases in ALIASES.items() for alias in aliases}
    result: dict[str, str] = {}
    for header in headers:
        field = lookup.get(_clean(header))
        if field and field not in result:
            result[field] = header
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return "UNSPECIFIED_TIMEZONE:" + value
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return "UNPARSED_TIMESTAMP:" + value


def _event_data(root: ET.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in root.findall(".//e:EventData/e:Data", EVTX_NS):
        name = node.attrib.get("Name", "").strip()
        value = "".join(node.itertext()).strip()
        if name:
            values[name] = value[:4000]
    # UserData varies by provider. Preserve leaf values by their XML local-name.
    for node in root.findall(".//e:UserData//*", EVTX_NS):
        if list(node):
            continue
        key = node.tag.rsplit("}", 1)[-1]
        value = "".join(node.itertext()).strip()
        if key and value and key not in values:
            values[key] = value[:4000]
    return values


def normalise_evtx_xml(xml_text: str, *, source_file: str, source_record: int,
                        source_sha256: str) -> dict[str, Any] | None:
    """Parse one EVTX event's XML into the project's common event schema."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    system = root.find("e:System", EVTX_NS)
    if system is None:
        return None
    provider_node = system.find("e:Provider", EVTX_NS)
    time_node = system.find("e:TimeCreated", EVTX_NS)
    event_id_node = system.find("e:EventID", EVTX_NS)
    record_id_node = system.find("e:EventRecordID", EVTX_NS)
    computer_node = system.find("e:Computer", EVTX_NS)
    channel_node = system.find("e:Channel", EVTX_NS)
    level_node = system.find("e:Level", EVTX_NS)
    data = _event_data(root)

    def text_of(node: ET.Element | None) -> str:
        return "".join(node.itertext()).strip() if node is not None else ""

    # Preserve raw provider field names in addition to the most useful common fields.
    lower_data = {k.casefold(): v for k, v in data.items()}
    username = next((lower_data[k] for k in (
        "targetusername", "subjectusername", "username", "accountname", "user"
    ) if lower_data.get(k)), "")
    source_ip = next((lower_data[k] for k in (
        "ipaddress", "sourceaddress", "clientaddress", "sourceip"
    ) if lower_data.get(k)), "")
    process_name = next((lower_data[k] for k in (
        "newprocessname", "image", "processname", "application", "processname"
    ) if lower_data.get(k)), "")
    message = " | ".join(f"{k}={v}" for k, v in data.items())[:4000]
    record_id = text_of(record_id_node)
    try:
        record_id_value: int | str = int(record_id) if record_id else source_record
    except ValueError:
        record_id_value = record_id

    return {
        "timestamp": _utc_timestamp(time_node.attrib.get("SystemTime") if time_node is not None else None),
        "computer": text_of(computer_node),
        "channel": text_of(channel_node),
        "provider": provider_node.attrib.get("Name", "") if provider_node is not None else "",
        "event_id": text_of(event_id_node),
        "level": text_of(level_node),
        "username": username,
        "source_ip": source_ip,
        "process_name": process_name,
        "message": message,
        "event_data": data,
        "source_file": source_file.replace("\\", "/"),
        "source_row": source_record,
        "source_record_id": record_id_value,
        "source_sha256": source_sha256,
        "evidence_format": "EVTX",
    }


def _normalise_csv(path: Path, root: Path, digest: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            return output
        mapping = _canonical_headers(reader.fieldnames)
        if not mapping:
            return output
        relative = path.relative_to(root).as_posix()
        for row_num, row in enumerate(reader, start=2):
            record: dict[str, Any] = {
                "source_file": relative,
                "source_row": row_num,
                "source_record_id": row_num,
                "source_sha256": digest,
                "evidence_format": "CSV",
            }
            for field, header in mapping.items():
                value = (row.get(header) or "").strip()[:4000]
                record[field] = _utc_timestamp(value) if field == "timestamp" else value
            output.append(record)
    return output


def _normalise_evtx(
    path: Path, root: Path, digest: str, *,
    progress_callback: Callable[[str], None] | None = None,
    progress_every: int = 500,
    progress_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    if Evtx is None:
        raise RuntimeError(
            "Found .evtx files, but the EVTX parser is not installed. Run: "
            "python -m pip install -r requirements.txt"
        )
    output: list[dict[str, Any]] = []
    relative = path.relative_to(root).as_posix()
    started = time.perf_counter()
    last_report = started
    seen = 0
    xml_errors = 0
    with Evtx(str(path)) as log:
        for ordinal, record in enumerate(log.records(), start=1):
            seen = ordinal
            try:
                xml_text = record.xml()
            except Exception:
                # Preserve the rest of the log, but report how many records failed XML rendering.
                xml_errors += 1
                continue
            normalised = normalise_evtx_xml(
                xml_text, source_file=relative, source_record=ordinal, source_sha256=digest
            )
            if normalised is not None:
                output.append(normalised)
            now = time.perf_counter()
            if progress_callback is not None and (ordinal % progress_every == 0 or now - last_report >= progress_seconds):
                progress_callback(
                    f"    EVTX progress: {path.name}: scanned {ordinal:,} records, "
                    f"normalised {len(output):,}; elapsed {now - started:.1f}s."
                )
                last_report = now
    if progress_callback is not None:
        progress_callback(
            f"    EVTX complete: {path.name}: scanned {seen:,} records, "
            f"normalised {len(output):,} in {time.perf_counter() - started:.1f}s; "
            f"XML errors skipped: {xml_errors:,}."
        )
    return output


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON via a sibling temporary file so interrupted writes do not corrupt it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def ingest_collection(
    source: Path,
    output_path: Path,
    *,
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_dir: Path | None = None,
) -> dict[str, Any]:
    """Parse supported files with live progress and per-file resumable checkpoints.

    Completed files are cached outside the source collection. On a later run, a
    checkpoint is reused only when the current source file SHA-256 still matches.
    A file interrupted while parsing is retried, while earlier completed files
    remain available. Source evidence is read-only.
    """
    def report(message: str) -> None:
        if progress_callback is not None:
            progress_callback(message)

    source = source.expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f"Collection folder does not exist or is not a folder: {source}")
    output_path = output_path.expanduser().resolve()
    checkpoint_dir = (checkpoint_dir or (output_path.parent / ".ingestion_checkpoints")).expanduser().resolve()
    if checkpoint_dir == source or source in checkpoint_dir.parents:
        raise ValueError("Checkpoint directory must be outside the source evidence collection.")

    report("Step 1 of 4: scanning the collection folder for .evtx and .csv files...")
    supported: list[Path] = []
    folders_scanned = 0
    files_seen = 0
    import os as _os
    for current, dirnames, filenames in _os.walk(source, followlinks=False):
        folders_scanned += 1
        dirnames[:] = [name for name in dirnames if not (Path(current) / name).is_symlink()]
        for filename in filenames:
            path = Path(current) / filename
            files_seen += 1
            if path.is_symlink() or not path.is_file() or path.suffix.casefold() not in {".evtx", ".csv"}:
                continue
            try:
                resolved = path.resolve()
                if resolved.is_relative_to(source):
                    supported.append(resolved)
            except (OSError, ValueError):
                continue
        if folders_scanned == 1 or folders_scanned % 10 == 0:
            report(f"Scanning... checked {folders_scanned} folders and {files_seen} files; found {len(supported)} supported candidate(s).")

    supported.sort(key=lambda p: str(p).casefold())
    report(f"Step 2 of 4: scan complete. Found {len(supported)} supported candidate file(s) among {files_seen} files.")
    if not supported:
        report("No .evtx or .csv files were found. Other collected artefacts are not parsed by this version.")

    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    file_summary: list[dict[str, Any]] = []
    cache_hits = 0
    overall_started = time.perf_counter()

    for index, path in enumerate(supported, start=1):
        relative = path.relative_to(source).as_posix()
        report(f"Step 3 of 4: parsing file {index}/{len(supported)}: {relative}")
        file_started = time.perf_counter()
        try:
            digest = _sha256(path)
            checkpoint_name = hashlib.sha256(relative.encode("utf-8")).hexdigest() + ".json"
            checkpoint_path = checkpoint_dir / checkpoint_name
            cached: dict[str, Any] | None = None
            if checkpoint_path.is_file():
                try:
                    candidate = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                    if candidate.get("source_file") == relative and candidate.get("source_sha256") == digest and isinstance(candidate.get("records"), list) and isinstance(candidate.get("summary"), dict):
                        cached = candidate
                except (OSError, json.JSONDecodeError):
                    cached = None

            if cached is not None:
                current_records = cached["records"]
                summary = cached["summary"]
                cache_hits += 1
                report(f"  Reused checkpoint: {relative} ({len(current_records):,} records).")
            else:
                if path.suffix.casefold() == ".evtx":
                    current_records = _normalise_evtx(path, source, digest, progress_callback=report)
                else:
                    current_records = _normalise_csv(path, source, digest)
                parsed_count = len(current_records)
                summary = {
                    "source_file": relative,
                    "format": path.suffix.casefold().lstrip("."),
                    "sha256": digest,
                    "records_parsed": parsed_count,
                    "status": "parsed" if parsed_count else "no_supported_records",
                }
                _atomic_write_json(checkpoint_path, {
                    "checkpoint_version": 1,
                    "source_file": relative,
                    "source_sha256": digest,
                    "summary": summary,
                    "records": current_records,
                })
                report(f"  Checkpoint saved: {relative} ({parsed_count:,} records, {time.perf_counter() - file_started:.1f}s).")

            records.extend(current_records)
            file_summary.append(summary)
            report(f"  Progress: {index}/{len(supported)} files complete; {len(records):,} total records; {time.perf_counter() - overall_started:.1f}s elapsed.")
        except Exception as exc:
            summary = {
                "source_file": relative,
                "format": path.suffix.casefold().lstrip("."),
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }
            file_summary.append(summary)
            report(f"  Could not parse {relative}: {type(exc).__name__}: {exc}")

    payload = {
        "schema_version": 2,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_root": str(source),
        "record_count": len(records),
        "source_file_count": len(file_summary),
        "source_files": file_summary,
        "records": records,
        "ingestion": {
            "checkpoint_directory": str(checkpoint_dir),
            "checkpoints_reused": cache_hits,
            "files_processed_this_run": len(supported) - cache_hits,
            "elapsed_seconds": round(time.perf_counter() - overall_started, 2),
        },
        "note": (
            "Only EVTX and structured CSV are parsed. source_file is relative to source_root; "
            "source_row is the parser ordinal (CSV row number for CSV). source_record_id is the "
            "Windows EventRecordID when available. Source SHA-256 values are included for validation. "
            "Completed source files are checkpointed outside the evidence collection and reused only "
            "when their SHA-256 matches."
        ),
    }
    report("Step 4 of 4: writing the normalised evidence report; original collected files are not modified.")
    _atomic_write_json(output_path, payload)
    report(f"Evidence report saved to: {output_path}")
    report(f"Resume cache: {cache_hits} completed file(s) reused; {len(supported) - cache_hits} file(s) processed this run.")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalise supported KAPE EVTX/CSV output")
    parser.add_argument("source", type=Path, help="KAPE collection output folder")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "reports" / "events_normalized.json")
    args = parser.parse_args()
    try:
        result = ingest_collection(args.source, args.output, progress_callback=print)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f"Supported files found: {result['source_file_count']}")
    print(f"Normalised records: {result['record_count']}")
    print(f"Output: {args.output.resolve()}")
    for item in result["source_files"]:
        print(f"  {item['status']}: {item['source_file']} ({item.get('records_parsed', 0)} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
