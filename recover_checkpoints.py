"""Recover normalized KAPE records from validated per-file ingestion checkpoints.

This tool never edits source evidence or checkpoint files. It validates each checkpoint
against the corresponding source file SHA-256, then atomically writes the combined report.
If an output already exists, a timestamped backup is made before replacement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_path_for(root: Path, relative: str) -> Path | None:
    """Resolve a checkpoint's POSIX relative source path safely under root."""
    if not isinstance(relative, str) or not relative.strip():
        return None
    normalized = relative.replace("\\", "/")
    posix = PurePosixPath(normalized)
    if posix.is_absolute() or any(part in ("..", "") for part in posix.parts):
        return None
    candidate = root.joinpath(*posix.parts).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def load_checkpoints(source: Path, checkpoint_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    recovered: list[dict[str, Any]] = []
    issues: list[str] = []
    seen_sources: set[str] = set()

    if not checkpoint_dir.is_dir():
        raise FileNotFoundError(f"Checkpoint directory not found: {checkpoint_dir}")

    files = sorted(checkpoint_dir.glob("*.json"))
    if not files:
        raise ValueError(f"No JSON checkpoints found in {checkpoint_dir}")

    for checkpoint in files:
        try:
            data = json.loads(checkpoint.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            issues.append(f"{checkpoint.name}: unreadable JSON ({exc})")
            continue

        relative = data.get("source_file")
        digest = data.get("source_sha256")
        records = data.get("records")
        summary = data.get("summary")
        if data.get("checkpoint_version") != 1:
            issues.append(f"{checkpoint.name}: unsupported checkpoint version")
            continue
        if not isinstance(relative, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            issues.append(f"{checkpoint.name}: missing/invalid source path or SHA-256")
            continue
        if not isinstance(records, list) or not isinstance(summary, dict):
            issues.append(f"{checkpoint.name}: missing records list or summary")
            continue
        rel = PurePosixPath(relative.replace("\\", "/")).as_posix()
        if rel in seen_sources:
            issues.append(f"{checkpoint.name}: duplicate checkpoint for {rel}; skipped")
            continue

        src = source_path_for(source, rel)
        if src is None or not src.is_file():
            issues.append(f"{checkpoint.name}: source file not found safely under evidence root ({rel})")
            continue

        try:
            actual_digest = sha256_file(src)
        except OSError as exc:
            issues.append(f"{checkpoint.name}: could not hash source ({exc})")
            continue
        if actual_digest.casefold() != digest.casefold():
            issues.append(f"{checkpoint.name}: SHA-256 mismatch for {rel}; skipped")
            continue
        if summary.get("source_file") != relative or str(summary.get("sha256", "")).casefold() != digest.casefold():
            issues.append(f"{checkpoint.name}: checkpoint summary does not match its header; skipped")
            continue

        # Require record provenance to point back to this exact source and digest.
        valid_records = []
        malformed = 0
        for record in records:
            if not isinstance(record, dict):
                malformed += 1
                continue
            record_source = record.get("source_file")
            if not isinstance(record_source, str) or record_source.replace("\\", "/") != rel:
                malformed += 1
                continue
            if str(record.get("source_sha256", "")).casefold() != digest.casefold():
                malformed += 1
                continue
            valid_records.append(record)
        if malformed:
            issues.append(f"{checkpoint.name}: excluded {malformed} record(s) with invalid provenance")
        # Never claim more records than are actually valid in the checkpoint.
        recovered_summary = dict(summary)
        recovered_summary["source_file"] = rel
        recovered_summary["sha256"] = digest
        recovered_summary["records_parsed"] = len(valid_records)
        recovered_summary["status"] = "recovered" if valid_records else "no_valid_records"
        recovered_summary["checkpoint_file"] = checkpoint.name
        recovered.append({
            "source_file": rel,
            "source_sha256": digest,
            "records": valid_records,
            "summary": recovered_summary,
        })
        seen_sources.add(rel)

    return recovered, issues


def backup_path_for_existing_output(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = path.with_name(f"{path.name}.backup_{stamp}")
    counter = 1
    while backup_path.exists():
        backup_path = path.with_name(f"{path.name}.backup_{stamp}_{counter}")
        counter += 1
    return backup_path


def atomic_write_json(path: Path, payload: dict[str, Any], backup_path: Path | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if backup_path is not None:
        shutil.copy2(path, backup_path)

    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temp_name).replace(path)
    except Exception:
        try:
            Path(temp_name).unlink(missing_ok=True)
        except OSError:
            pass
        raise


def recover(source: Path, checkpoint_dir: Path, output: Path) -> dict[str, Any]:
    source = source.expanduser().resolve()
    checkpoint_dir = checkpoint_dir.expanduser().resolve()
    output = output.expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f"Evidence source folder does not exist: {source}")
    # Checkpoints must remain outside the evidence collection.
    if checkpoint_dir == source or source in checkpoint_dir.parents:
        raise ValueError("Checkpoint directory must be outside the source evidence collection.")

    recovered, issues = load_checkpoints(source, checkpoint_dir)
    if not recovered:
        details = "\n".join(issues[:12])
        raise ValueError("No checkpoints passed source-hash and provenance validation. Output not changed.\n" + details)

    records: list[dict[str, Any]] = []
    source_files: list[dict[str, Any]] = []
    for item in recovered:
        records.extend(item["records"])
        source_files.append(item["summary"])

    payload = {
        "schema_version": 2,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_root": str(source),
        "record_count": len(records),
        "source_file_count": len(source_files),
        "source_files": source_files,
        "records": records,
        "ingestion": {
            "recovery_method": "validated_per_file_checkpoints",
            "checkpoint_directory": str(checkpoint_dir),
            "checkpoints_validated": len(recovered),
            "records_recovered": len(records),
            "checkpoint_issues": issues,
        },
        "note": (
            "Recovered from completed per-file checkpoints. Each included source file was "
            "SHA-256 validated against the evidence currently at source_root. Records with "
            "missing or mismatched provenance were excluded. Source evidence and checkpoints "
            "were not modified."
        ),
    }
    backup = backup_path_for_existing_output(output)
    payload["ingestion"]["output_backup"] = str(backup) if backup else None
    atomic_write_json(output, payload, backup)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Recover normalized evidence from validated KAPE ingestion checkpoints")
    parser.add_argument("--source", type=Path, required=True, help="KAPE evidence root, e.g. E:\\KAPE-Output-2")
    parser.add_argument("--checkpoints", type=Path, default=Path("reports/.ingestion_checkpoints"))
    parser.add_argument("--output", type=Path, default=Path("reports/events_normalized.json"))
    args = parser.parse_args()
    try:
        payload = recover(args.source, args.checkpoints, args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Evidence root: {payload['source_root']}")
    print(f"Validated checkpoints: {payload['ingestion']['checkpoints_validated']}")
    print(f"Recovered records: {payload['record_count']:,}")
    print(f"Source files represented: {payload['source_file_count']}")
    print(f"Output: {args.output.resolve()}")
    if payload["ingestion"]["output_backup"]:
        print(f"Previous output backed up to: {payload['ingestion']['output_backup']}")
    issues = payload["ingestion"]["checkpoint_issues"]
    print(f"Checkpoint/record issues: {len(issues)}")
    for issue in issues[:20]:
        print(f"  WARNING: {issue}")
    if len(issues) > 20:
        print(f"  ... and {len(issues) - 20} more issue(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
