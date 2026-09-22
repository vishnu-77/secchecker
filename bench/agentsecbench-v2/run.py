#!/usr/bin/env python3
import csv
import json
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
MANIFEST = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
WORK = ROOT / ".work"
RAW = ROOT / "results" / "raw"
META = ROOT / "results" / "scan_meta.tsv"

shutil.rmtree(WORK, ignore_errors=True)
shutil.rmtree(ROOT / "results", ignore_errors=True)
WORK.mkdir(parents=True, exist_ok=True)
RAW.mkdir(parents=True, exist_ok=True)

rows = []

def run(cmd, cwd=None, check=True, timeout=None):
    print("+", " ".join(str(x) for x in cmd), flush=True)
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )

for target in MANIFEST["repositories"]:
    target_id = target["id"]
    dest = WORK / target_id

    print(f"\n=== {target['repository']} @ {target['commit']} ===", flush=True)
    dest.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "-q"], cwd=dest)
    run(["git", "remote", "add", "origin", target["url"]], cwd=dest)
    run(["git", "fetch", "--depth", "1", "origin", target["commit"]], cwd=dest, timeout=900)
    run(["git", "checkout", "--detach", "-q", "FETCH_HEAD"], cwd=dest)
    actual = run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
    if actual != target["commit"]:
        raise SystemExit(f"pin mismatch for {target_id}: expected {target['commit']}, got {actual}")

    shutil.rmtree(dest / ".git", ignore_errors=True)

    out = RAW / f"{target_id}.json"
    started = time.perf_counter()
    proc = run(
        [
            "secchecker", "scan", str(dest),
            "--type", MANIFEST["scanner"]["scan_type"],
            "--format", "json",
            "--output", str(out),
            "--severity-threshold", MANIFEST["scanner"]["severity_threshold"],
        ],
        cwd=REPO_ROOT,
        check=False,
        timeout=1200,
    )
    elapsed = time.perf_counter() - started
    print(proc.stdout[-8000:], flush=True)

    rows.append({
        "id": target_id,
        "repository": target["repository"],
        "commit": actual,
        "elapsed_seconds": f"{elapsed:.4f}",
        "exit_code": str(proc.returncode),
    })

    if proc.returncode not in (0, 1):
        raise SystemExit(f"scanner failed for {target_id} with exit code {proc.returncode}")
    if not out.exists():
        raise SystemExit(f"scanner produced no JSON result for {target_id}")

with META.open("w", encoding="utf-8", newline="") as fh:
    writer = csv.DictWriter(
        fh,
        fieldnames=["id", "repository", "commit", "elapsed_seconds", "exit_code"],
        delimiter="\t",
    )
    writer.writeheader()
    writer.writerows(rows)

shutil.rmtree(WORK, ignore_errors=True)
print("\nBenchmark collection complete.", flush=True)
