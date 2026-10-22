# KAPE checkpoint recovery helper

This helper reconstructs `reports/events_normalized.json` from completed per-file checkpoints, without editing source evidence or checkpoint files.

## Run from your project root

First close the investigator and ingestion process. Keep a copy of the project folder if practical. Then run:

```powershell
python .\recover_checkpoints.py --source "E:\KAPE-Output-2" --checkpoints ".\reports\.ingestion_checkpoints" --output ".\reports\events_normalized.json"
```

The helper:
- checks each checkpoint's source file exists under the chosen evidence root;
- hashes each source file and includes a checkpoint only when its SHA-256 matches;
- verifies each record's source path and hash provenance;
- keeps the schema expected by the current ingestion/investigator code;
- makes a timestamped backup of an existing output before replacing it;
- never changes source evidence or checkpoint files;
- reports skipped checkpoints and records.

If it reports zero valid checkpoints, it does not change the output. Do not delete or move your existing checkpoints.

## Test

Copy the helper and `test_recover_checkpoints.py` into the project root, then run:

```powershell
python -m unittest .\test_recover_checkpoints.py -v
```

Tests use synthetic temporary evidence and make no API calls.
