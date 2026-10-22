# KAPE-AI-Investigator

A Python-based digital forensics proof of concept for processing KAPE-collected evidence, normalizing events, recovering interrupted ingestion from checkpoints, and supporting AI-assisted investigation.

## Overview

KAPE-AI-Investigator combines evidence-processing workflows with an AI-assisted investigation interface. It is designed to explore how structured forensic data, provenance validation, and language models can work together to support investigation and analysis.

The project includes tools for:

- Inventorying collected evidence.
- Processing evidence into normalized event records.
- Resuming recovery from completed ingestion checkpoints.
- Validating source references and citations.
- Supporting AI-assisted investigation using a configured OpenAI API model.
- Testing ingestion and recovery functionality using synthetic test data.

This is a proof of concept, not a replacement for a forensic examination platform or an investigator's professional judgement.

## Features

### Evidence processing

The ingestion and parsing scripts process supported evidence files and produce normalized event records for subsequent investigation.

### Checkpoint recovery

The recovery helper can reconstruct the normalized event output from eligible per-file checkpoints, avoiding unnecessary reprocessing when compatible checkpoints are available.

### Provenance validation

The project includes checks designed to associate normalized records with their source files and validate relevant provenance information.

### AI-assisted investigation

The investigator can use a configured OpenAI API model to help analyze normalized forensic events. API access requires a valid API key and may incur charges.

AI-generated findings should be treated as investigative leads that require independent verification against the underlying evidence.

### Testing

The repository includes tests for ingestion, checkpoint recovery, collection functionality, and safe updates. Recovery tests use synthetic temporary evidence and do not make API calls.

## Project structure

The repository contains the following main files:

```text
KAPE-AI-Investigator/
├── .gitignore
├── README.md
├── INSTALL_UPGRADE.ps1
├── ai_investigator.py
├── ingest_evidence.py
├── inventory.py
├── kape_collection.py
├── parse_events.py
├── recover_checkpoints.py
├── requirements.txt
├── test_ingest_evidence.py
├── test_kape_collection.py
├── test_recover_checkpoints.py
├── validate_citations.py
└── tests/
    ├── test_ingest_evidence.py
    ├── test_kape_collection.py
    └── test_safe_update.py
```

The project also uses local working directories for generated reports, normalized events, and ingestion checkpoints. These are not included in the public repository because they may contain sensitive forensic information.

## Requirements

- Windows is the primary example environment for the commands in this guide.
- Python installed and available from PowerShell.
- The dependencies listed in `requirements.txt`.
- KAPE and suitable evidence files if you intend to run the collection or evidence-processing workflows.
- A valid OpenAI API key if you intend to use the AI-assisted investigation functionality.

Exact compatibility depends on the installed Python version, dependencies, evidence formats, and local configuration.

## Installation

### 1. Clone the repository

Open PowerShell and run:

```powershell
git clone https://github.com/chrisrog-sec/KAPE-AI-Investigator.git
cd KAPE-AI-Investigator
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell prevents activation because of its execution policy, use an approved environment-specific workaround or run the Python executable inside `.venv` directly. Avoid changing system-wide security settings unnecessarily.

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure API access if required

The AI investigator uses environment-based configuration for API credentials. Set your API key in your local environment rather than hardcoding it into the source code.

For the current PowerShell session:

```powershell
$env:OPENAI_API_KEY = "YOUR_API_KEY"
```

Replace `YOUR_API_KEY` locally with your actual key. Never commit the real key, share it in screenshots, or publish it in your README.

If the application supports model selection through `OPENAI_MODEL`, configure that variable according to the model supported by your implementation.

API use can incur costs. Review your usage and budget settings before running investigations.

## Working with evidence

Use evidence collected and stored in an environment you are authorized to examine.

The scripts support different stages of the workflow, including inventory, ingestion, parsing, and investigation. Refer to each script's command-line help or the relevant implementation for its available arguments.

Keep original evidence separate from generated project data.

For example:

```text
Evidence location:
E:\KAPE-Output-2\

Project location:
C:\Users\YourUser\KAPE-AI-Investigator\

Generated working data:
KAPE-AI-Investigator\
└── reports\
    ├── events_normalized.json
    └── .ingestion_checkpoints\
```

These are example paths. Use the paths that match your environment.

The `reports` directory and its contents are local working data. They may be created or populated by the project's workflow, depending on the script implementation. Do not assume that cloning the repository provides existing reports or checkpoints.

## Recovering interrupted ingestion

The `recover_checkpoints.py` helper reconstructs `reports/events_normalized.json` from completed per-file ingestion checkpoints. It is intended for situations where ingestion was interrupted or the normalized event output needs to be recovered without unnecessarily processing every source file again.

### How it works

The recovery helper:

- Checks that each checkpoint's source file exists under the selected evidence directory.
- Calculates the source file's SHA-256 hash and compares it with the checkpoint.
- Validates record source paths and hash provenance.
- Reconstructs the normalized event output using the schema expected by the current project code.
- Creates a timestamped backup of an existing output before replacing it.
- Reports skipped checkpoints and records.

The helper is designed not to modify the original evidence files or checkpoint files. Recovery does not require API calls.

### Prerequisites

Before running recovery, make sure you have:

- Python installed.
- The project files available locally.
- The original KAPE evidence directory.
- Completed checkpoint files from a previous ingestion run.
- Any dependencies required by the project scripts.

### Required files and folders

Run the helper from the project root. The relevant local structure should resemble:

```text
KAPE-AI-Investigator/
├── recover_checkpoints.py
├── requirements.txt
└── reports/
    ├── .ingestion_checkpoints/
    │   └── [existing checkpoint files]
    └── events_normalized.json
```

The normalized output file may not exist yet. It is shown because it is the expected recovery destination.

The original evidence directory is separate:

```text
E:\
└── KAPE-Output-2\
    └── [original KAPE evidence files]
```

The `reports` and checkpoint directories may need to be created locally if they do not already exist. Their exact creation behaviour depends on the implementation of the recovery and ingestion scripts.

**Important:** Do not create empty checkpoint files and expect recovery to reconstruct data from them. Use compatible checkpoints generated by a previous ingestion run. Do not delete or move existing checkpoints before recovery.

### Step 1: Open the project directory

Open PowerShell and change to your local project root. For example:

```powershell
cd "C:\Users\YourUser\KAPE-AI-Investigator"
```

Replace the example path with your actual project location.

### Step 2: Activate the virtual environment

If you created the virtual environment described above:

```powershell
.\.venv\Scripts\Activate.ps1
```

If you are not using a virtual environment, ensure Python and the required dependencies are available in your active Python environment.

### Step 3: Check the evidence and checkpoint paths

Confirm that:

- The original evidence directory exists.
- The source files referenced by the checkpoints are still present.
- The checkpoint directory contains checkpoints from an earlier ingestion run.
- You have enough disk space for the reconstructed output and any backup.

Close running ingestion or investigation processes before recovery. Keep a backup of your project where practical.

### Step 4: Run recovery

From the project root, run:

```powershell
python .\recover_checkpoints.py --source "E:\KAPE-Output-2" --checkpoints ".\reports\.ingestion_checkpoints" --output ".\reports\events_normalized.json"
```

Replace `E:\KAPE-Output-2` with the location of your own evidence directory.

The command-line arguments are:

| Argument | Purpose |
|---|---|
| `--source` | Root directory containing the original evidence files |
| `--checkpoints` | Directory containing existing ingestion checkpoints |
| `--output` | Destination for the reconstructed normalized event file |

### Step 5: Review the results

Review the console output to see which checkpoints and records were accepted or skipped.

Expected outcomes include:

- **Valid checkpoints found:** eligible records are reconstructed into the normalized output.
- **Some checkpoints rejected:** the helper reports skipped checkpoints or records.
- **No valid checkpoints found:** the helper is intended to leave the existing output unchanged.

If recovery does not produce the expected output, verify the evidence path, checkpoint directory, source-file hashes, and checkpoint compatibility before trying again.

Do not delete checkpoints simply because some were rejected. Investigate the reported reason first.

### Step 6: Run the recovery tests

From the project root:

```powershell
python -m unittest .\test_recover_checkpoints.py -v
```

The tests use synthetic temporary evidence and do not make API calls.

Review the test output and investigate failures before relying on recovery for important work.

## Running the tests

To run the recovery tests:

```powershell
python -m unittest .\test_recover_checkpoints.py -v
```

Other tests are included in the repository. Their exact invocation may depend on the test layout and the current Python environment.

Run tests against synthetic or otherwise non-sensitive data whenever possible.

## Security and forensic considerations

Forensic workflows require careful handling of evidence and generated artifacts.

- Preserve original evidence and avoid modifying source files during analysis.
- Keep generated event data, checkpoint files, investigation reports, and case-specific information out of public repositories.
- Never commit API keys, access tokens, or other credentials.
- Review `.gitignore` and `git status` before committing changes. Remember that `.gitignore` does not automatically untrack files already committed.
- Treat AI-generated findings as hypotheses that require validation.
- Verify findings against the original evidence and preserve the context necessary to reproduce investigative conclusions.
- A matching SHA-256 hash supports file-integrity checking but does not, by itself, establish that evidence or checkpoint contents are trustworthy.
- Use the tool only on systems and evidence you are authorized to examine.

## Limitations

This project is a proof of concept. It is not presented as a certified forensic tool or a substitute for established forensic procedures.

Recovery depends on compatibility between the checkpoint format, normalized event schema, and current implementation. Successful recovery does not independently guarantee that every relevant event was collected or that every recovered record is accurate.

AI-generated analysis may contain errors, omit relevant context, or misinterpret forensic artifacts. Important findings must be independently verified.

Command-line options, supported file types, directory creation, and error-handling behaviour should be confirmed against the current source code.

## Future improvements

Potential areas for further development include:

- Expanded automated test coverage.
- Additional supported forensic artifact types.
- Improved structured logging and error reporting.
- More comprehensive validation of recovered records.
- Reproducible test fixtures and sample data that contain no sensitive evidence.
- Improved documentation for the complete ingestion-to-investigation workflow.

## Disclaimer

This project is intended for educational, research, and authorized defensive-security use. The user is responsible for ensuring that evidence handling, API usage, and investigative activities comply with applicable laws, organizational policies, and data-protection requirements.

## Author

**GitHub:** [@chrisrog-sec](https://github.com/chrisrog-sec)

Repository: [KAPE-AI-Investigator](https://github.com/chrisrog-sec/KAPE-AI-Investigator)
