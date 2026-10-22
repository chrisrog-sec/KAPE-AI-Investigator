## Recovering interrupted ingestion

If an ingestion run was interrupted, `recover_checkpoints.py` can rebuild `reports/events_normalized.json` using completed, valid per-file checkpoints. This avoids reprocessing every evidence file unnecessarily.

### Prerequisites

- Python installed and the project's dependencies available.
- The original KAPE evidence output still available.
- Existing checkpoint files in `reports/.ingestion_checkpoints/`.
- The project scripts and directory structure intact.

### Run the recovery helper

From the project root, activate your virtual environment if you use one:

```powershell
.\.venv\Scripts\Activate.ps1
```

Then run:

```powershell
python .\recover_checkpoints.py --source "E:\KAPE-Output-2" --checkpoints ".\reports\.ingestion_checkpoints" --output ".\reports\events_normalized.json"
```

Replace `E:\KAPE-Output-2` with the path to your own evidence directory.

### What happens?

The helper checks source-file existence and SHA-256 hashes, validates checkpoint provenance, and reconstructs the normalized event file from eligible checkpoints. If an output already exists, it creates a timestamped backup before replacing it.

- **Valid checkpoints found:** eligible records are recovered into the normalized output.
- **Some checkpoints rejected:** the helper reports skipped checkpoints and records.
- **No valid checkpoints found:** the existing output is left unchanged.

The helper does not modify the original evidence or checkpoint files. Close any running ingestion or investigation processes before recovery, and keep a backup of your project where practical.

### Run the tests

From the project root:

```powershell
python -m unittest .\test_recover_checkpoints.py -v
```

The tests use synthetic temporary evidence and do not make API calls.

### Important limitations

Recovery depends on the checkpoint format and schema expected by the current project code. A matching source hash helps verify provenance, but does not independently establish that the evidence or checkpoint contents are trustworthy.
