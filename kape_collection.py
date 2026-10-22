"""Guided, conservative KAPE collection workflow for KAPE AI Investigator.

Only KAPE target collection is supported here. KAPE modules are intentionally
not executed because modules may launch additional tools or scripts.
"""
from __future__ import annotations
import hashlib, json, os, re, subprocess, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

CATEGORIES = {
    "eventlogs": ("Windows event logs", ("eventlog", "event_log", "event logs", "evtx")),
    "execution": ("Execution artefacts", ("prefetch", "amcache", "shimcache", "userassist", "execution")),
    "registry": ("Registry artefacts", ("registry", "hive", "ntuser", "system")),
    "filesystem": ("File system artefacts", ("mft", "usn", "filesystem", "file_system", "lnk", "jumplist")),
    "network": ("Network-related artefacts", ("network", "firewall", "dns", "hosts", "arp", "rdp")),
}

class KapeError(RuntimeError):
    pass

def find_kape_executable(candidate: str | Path) -> Path:
    """Accept only an existing kape.exe file, never shell command text."""
    p = Path(candidate).expanduser().resolve()
    if not p.is_file() or p.name.casefold() != "kape.exe":
        raise KapeError("Select the actual kape.exe executable, not gkape.exe or a command string.")
    return p

def discover_targets(kape_exe: str | Path) -> list[Path]:
    exe = find_kape_executable(kape_exe)
    target_dir = exe.parent / "Targets"
    if not target_dir.is_dir():
        raise KapeError(f"KAPE Targets folder was not found beside the executable: {target_dir}")
    # Target definitions are data files. We only enumerate them; never execute modules.
    targets = sorted((p.resolve() for p in target_dir.rglob("*.tkape") if p.is_file()), key=lambda p: str(p).casefold())
    if not targets:
        raise KapeError(f"No .tkape target definitions found under {target_dir}")
    # Reject symlinks resolving outside the trusted Targets directory.
    base = target_dir.resolve()
    safe = []
    for p in targets:
        try: p.relative_to(base)
        except ValueError: continue
        safe.append(p)
    return safe

def discover_modules(kape_exe: str | Path) -> list[Path]:
    """Enumerate installed .mkape module definitions for visibility only.

    This project intentionally never passes --module to KAPE and never executes
    module definitions. Enumeration is not a trust verdict or safety guarantee.
    """
    exe = find_kape_executable(kape_exe)
    module_dir = exe.parent / "Modules"
    if not module_dir.is_dir():
        return []
    base = module_dir.resolve()
    found=[]
    for p in sorted(module_dir.rglob("*.mkape"), key=lambda x: str(x).casefold()):
        if not p.is_file():
            continue
        resolved=p.resolve()
        try: resolved.relative_to(base)
        except ValueError: continue
        found.append(resolved)
    return found

def categorise_targets(target_files: Sequence[Path]) -> dict[str, list[Path]]:
    out = {k: [] for k in CATEGORIES}
    for path in target_files:
        text = (path.stem + " " + str(path.parent)).casefold().replace("-", "_")
        for category, (_, needles) in CATEGORIES.items():
            if any(n.replace("-", "_") in text for n in needles):
                out[category].append(path)
    return out

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

def hash_output_tree(output_dir: Path) -> list[dict]:
    rows=[]
    for p in sorted(output_dir.rglob("*"), key=lambda x: str(x).casefold()):
        if p.is_file():
            try: rows.append({"path": str(p.relative_to(output_dir)), "size_bytes": p.stat().st_size, "sha256": sha256_file(p)})
            except OSError as e: rows.append({"path": str(p.relative_to(output_dir)), "error": str(e)})
    return rows

def build_command(kape_exe: Path, source: str, destination: Path, targets: Sequence[Path]) -> list[str]:
    """Build argv without shell parsing; only verified target stems are passed."""
    exe = find_kape_executable(kape_exe)
    if not re.fullmatch(r"[A-Za-z]:\\?", source.strip()):
        raise KapeError("Source must be a Windows drive root such as C:\\")
    if not targets:
        raise KapeError("Select at least one available target.")
    available = discover_targets(exe)
    available_resolved = {p.resolve() for p in available}
    selected=[]
    for target in targets:
        p=Path(target).resolve()
        if p not in available_resolved or p.suffix.casefold() != ".tkape":
            raise KapeError(f"Target is not a verified .tkape file under the installed KAPE Targets folder: {target}")
        # Target names are derived from installed files, not user-entered command fragments.
        name=p.stem
        if not re.fullmatch(r"[A-Za-z0-9_. -]{1,120}", name):
            raise KapeError(f"Target filename contains unsupported characters: {name}")
        selected.append(name)
    dest=destination.resolve()
    return [str(exe), "--tsource", source.strip().rstrip("\\") + "\\", "--tdest", str(dest), "--target", ",".join(selected)]

def run_collection(kape_exe: str | Path, source: str, destination: str | Path,
                   targets: Sequence[Path], *, confirmed: bool,
                   runner: Callable = subprocess.run, timeout: int = 3600) -> dict:
    """Run a confirmed target-only collection; runner is injectable for tests."""
    if not confirmed:
        raise KapeError("Collection cancelled: explicit confirmation is required.")
    exe=find_kape_executable(kape_exe)
    dest=Path(destination).expanduser().resolve()
    if dest.exists() and any(dest.iterdir()):
        raise KapeError(f"Destination must be new or empty: {dest}")
    # Avoid collecting into the KAPE install folder or project folder.
    dest.mkdir(parents=True, exist_ok=True)
    argv=build_command(exe, source, dest, targets)
    dest_base=dest.resolve()
    log_dir=dest_base / "_kape_ai_logs"
    log_dir.mkdir(exist_ok=True)
    started=datetime.now(timezone.utc).isoformat()
    record={"started_utc":started,"executable":str(exe),"source":source,"destination":str(dest),
            "selected_targets":[Path(p).stem for p in targets],"modules_executed":False,
            "command_argv":argv,"command_display":" ".join(json.dumps(a) for a in argv)}
    (log_dir/"collection_command.json").write_text(json.dumps(record,indent=2),encoding="utf-8")
    try:
        completed=runner(argv, cwd=str(exe.parent), capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=timeout, shell=False, check=False)
        record.update({"returncode":completed.returncode,"stdout":completed.stdout or "","stderr":completed.stderr or "",
                       "finished_utc":datetime.now(timezone.utc).isoformat()})
    except subprocess.TimeoutExpired as e:
        record.update({"error":"timeout","timeout_seconds":timeout,"stdout":str(e.stdout or ""),"stderr":str(e.stderr or "")})
        (log_dir/"collection_result.json").write_text(json.dumps(record,indent=2),encoding="utf-8")
        raise KapeError(f"KAPE timed out after {timeout} seconds. See {log_dir / 'collection_result.json'}") from e
    except OSError as e:
        record.update({"error":str(e)})
        (log_dir/"collection_result.json").write_text(json.dumps(record,indent=2),encoding="utf-8")
        raise KapeError(f"Could not launch KAPE: {e}") from e
    (log_dir/"collection_result.json").write_text(json.dumps(record,indent=2),encoding="utf-8")
    if completed.returncode != 0:
        raise KapeError(f"KAPE exited with code {completed.returncode}. See {log_dir / 'collection_result.json'}")
    hashes=hash_output_tree(dest)
    manifest={"generated_utc":datetime.now(timezone.utc).isoformat(),"source":source,
              "kape_executable":str(exe),"targets":record["selected_targets"],"files":hashes}
    (log_dir/"sha256_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    return {"result":record,"manifest":manifest,"log_dir":log_dir}

def _ask(prompt: str, input_fn=input) -> str:
    return input_fn(prompt).strip()

def run_wizard(project_dir: Path, *, input_fn=input, output_fn=print, runner=subprocess.run) -> Path | None:
    """Interactive wizard. Type BACK at prompts to return to the previous step."""
    output_fn("\nKAPE COLLECTION WIZARD")
    output_fn("This performs a live collection. Use only on a system you are authorised to examine.")
    output_fn("Tip: type BACK at any prompt to return one step. Type BACK at the first prompt to exit.")

    exe = None
    targets: list[Path] = []
    grouped: dict[str, list[Path]] = {}
    modules: list[Path] = []
    category_keys = list(CATEGORIES.keys())
    chosen_by_category: dict[str, list[Path]] = {key: [] for key in category_keys}
    source = "C:\\"
    dest_raw = ""

    # Steps: 0 executable, 1..N category selection, N+1 source, N+2 destination, N+3 confirmation.
    step = 0
    source_step = len(category_keys) + 1
    destination_step = source_step + 1
    confirmation_step = destination_step + 1

    while True:
        if step == 0:
            raw = _ask("Path to KAPE kape.exe (or BACK to exit): ", input_fn)
            if raw.casefold() == "back":
                output_fn("Wizard cancelled. No KAPE process was started.")
                return None
            try:
                exe = find_kape_executable(raw)
                targets = discover_targets(exe)
            except KapeError as e:
                output_fn(f"Setup error: {e}")
                continue
            grouped = categorise_targets(targets)
            modules = discover_modules(exe)
            # A new executable can have a different target set, so reset category choices.
            chosen_by_category = {key: [] for key in category_keys}
            output_fn(f"Verified executable: {exe}")
            output_fn(f"Available target definitions: {len(targets)}")
            output_fn(f"Installed module definitions detected: {len(modules)} (visibility only; none will be executed)")
            step += 1
            continue

        if 1 <= step <= len(category_keys):
            key = category_keys[step - 1]
            label, _ = CATEGORIES[key]
            matches = grouped[key]
            output_fn(f"\n{key}: {label}")
            if not matches:
                output_fn("  No targets matched this category by filename/path.")
                chosen_by_category[key] = []
                step += 1
                continue
            for i, target in enumerate(matches, 1):
                output_fn(f"  {i}. {target.relative_to(exe.parent / 'Targets')}")
            raw = _ask("Select numbers separated by commas, Enter to skip, or BACK: ", input_fn)
            if raw.casefold() == "back":
                step -= 1
                continue
            if not raw:
                chosen_by_category[key] = []
                step += 1
                continue
            selected_for_category = []
            invalid = False
            for bit in raw.split(","):
                bit = bit.strip()
                if not bit.isdigit() or not 1 <= int(bit) <= len(matches):
                    invalid = True
                    break
                selected_for_category.append(matches[int(bit) - 1])
            if invalid:
                output_fn("Invalid selection. Enter valid numbers, press Enter to skip, or type BACK.")
                continue
            # Remove duplicates while preserving the user's chosen order.
            chosen_by_category[key] = list(dict.fromkeys(selected_for_category))
            step += 1
            continue

        if step == source_step:
            raw = _ask(f"Source drive (for example C:\\) [{source}] or BACK: ", input_fn)
            if raw.casefold() == "back":
                step -= 1
                continue
            if raw:
                source = raw
            if not re.fullmatch(r"[A-Za-z]:\\?", source.strip()):
                output_fn("Please enter a Windows drive root such as C:\\, or type BACK.")
                continue
            source = source.strip().rstrip("\\") + "\\"
            step += 1
            continue

        if step == destination_step:
            raw = _ask("New/empty destination folder (or BACK to change source): ", input_fn)
            if raw.casefold() == "back":
                step -= 1
                continue
            if not raw:
                output_fn("Enter a destination folder, or type BACK.")
                continue
            dest_raw = raw
            dest = Path(dest_raw).expanduser().resolve()
            if dest.exists() and any(dest.iterdir()):
                output_fn(f"Destination must be new or empty: {dest}")
                continue
            step += 1
            continue

        if step == confirmation_step:
            chosen = [p for key in category_keys for p in chosen_by_category[key]]
            # De-duplicate targets selected through overlapping category heuristics.
            chosen = list(dict.fromkeys(chosen))
            if not chosen:
                output_fn("No targets selected. Nothing was collected.")
                return None
            dest = Path(dest_raw).expanduser().resolve()
            output_fn("\nCOLLECTION PREVIEW")
            output_fn(f"Executable: {exe}")
            output_fn(f"Source: {source}")
            output_fn(f"Destination: {dest}")
            output_fn("Targets: " + ", ".join(p.stem for p in chosen))
            output_fn("Modules: NONE. Only installed .tkape target definitions will be passed to KAPE.")
            output_fn("This can collect sensitive personal data. Confirm authorisation and destination handling.")
            confirmation = _ask('Type COLLECT to begin, BACK to edit the destination, or anything else to cancel: ', input_fn)
            if confirmation.casefold() == "back":
                step = destination_step
                continue
            if confirmation != "COLLECT":
                output_fn("Collection cancelled. No KAPE process was started.")
                return None
            try:
                result = run_collection(exe, source, dest, chosen, confirmed=True, runner=runner)
            except KapeError as e:
                output_fn(f"Collection failed: {e}")
                return None
            output_fn(f"Collection completed. SHA-256 manifest: {result['log_dir'] / 'sha256_manifest.json'}")
            output_fn(f"Command/result logs: {result['log_dir']}")
            output_fn("Next: parse supported exported logs, then run AI analysis. Collection itself does not automatically guarantee parsers exist for every artefact.")
            return dest
