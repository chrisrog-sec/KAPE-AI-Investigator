r"""
KAPE AI Investigator - Step 2
Read-only evidence inventory for authorised KAPE output folders.

Usage:
    python inventory.py
    python inventory.py --source r"C:\\path\\to\\KAPE\\output"
    python inventory.py --source evidence --output reports\inventory.json

This script reads files, calculates SHA-256 hashes, and writes a separate
inventory report. It does not execute evidence files or modify source files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_SOURCE = PROJECT_DIR / "evidence"
DEFAULT_OUTPUT = PROJECT_DIR / "reports" / "inventory.json"

# Skip symlinks and common reparse-point cases; never follow directory symlinks.
def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def inventory(source: Path) -> dict:
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError(f"Source is not a directory: {source}")

    records = []
    skipped = []

    for current, dirs, filenames in os.walk(source, followlinks=False):
        current_path = Path(current)

        # Prevent traversal through directory symlinks.
        dirs[:] = [
            d for d in dirs
            if not (current_path / d).is_symlink()
        ]

        for filename in filenames:
            path = current_path / filename
            try:
                if path.is_symlink():
                    skipped.append({
                        "path": str(path.relative_to(source)),
                        "reason": "symlink skipped",
                    })
                    continue

                stat_before = path.stat()
                if not path.is_file():
                    continue

                relative = str(path.relative_to(source))
                file_hash = sha256_file(path)
                stat_after = path.stat()

                # Flag a file that appears to have changed while being read.
                changed_during_read = (
                    stat_before.st_size != stat_after.st_size
                    or stat_before.st_mtime_ns != stat_after.st_mtime_ns
                )

                records.append({
                    "relative_path": relative,
                    "size_bytes": stat_after.st_size,
                    "modified_time_utc": datetime.fromtimestamp(
                        stat_after.st_mtime, timezone.utc
                    ).isoformat(),
                    "sha256": file_hash,
                    "changed_during_read": changed_during_read,
                })
            except (OSError, ValueError) as exc:
                skipped.append({
                    "path": str(path),
                    "reason": f"{type(exc).__name__}: {exc}",
                })

    records.sort(key=lambda item: item["relative_path"].lower())

    return {
        "schema_version": 1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_directory": str(source),
        "file_count": len(records),
        "skipped_count": len(skipped),
        "files": records,
        "skipped": skipped,
        "limitations": [
            "An inventory is not proof that evidence is authentic or complete.",
            "Filesystem timestamps can be altered and may not reflect event time.",
            "Hashing reads file contents but does not modify them.",
            "Run against a forensic working copy or authorised KAPE output.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only KAPE evidence inventory")
    parser.add_argument(
        "--source", type=Path, default=DEFAULT_SOURCE,
        help="Directory containing authorised KAPE output (default: ./evidence)",
    )
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT,
        help="Path for JSON inventory report (default: ./reports/inventory.json)",
    )
    args = parser.parse_args()

    try:
        result = inventory(args.source)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except (OSError, ValueError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")
        return 1

    print(f"Inventory complete: {result['file_count']} file(s)")
    print(f"Skipped: {result['skipped_count']} item(s)")
    print(f"Source: {result['source_directory']}")
    print(f"Report: {args.output.resolve()}")
    if any(item["changed_during_read"] for item in result["files"]):
        print("WARNING: One or more files changed while being hashed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
