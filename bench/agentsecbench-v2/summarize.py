#!/usr/bin/env python3
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
RAW = ROOT / "results" / "raw"
META = ROOT / "results" / "scan_meta.tsv"
OUT = ROOT / "results"

meta = {}
if META.exists():
    with META.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for row in reader:
            meta[row["id"]] = row

summary_rows = []
triage_rows = []

for target in MANIFEST["repositories"]:
    target_id = target["id"]
    path = RAW / f"{target_id}.json"
    if not path.exists():
        m = meta.get(target_id, {})
        exit_code = int(m["exit_code"]) if m.get("exit_code") else None
        summary_rows.append({
            "id": target_id,
            "repository": target["repository"],
            "commit": target["commit"],
            "status": "clean" if exit_code == 0 else "missing-result",
            "files_with_findings": 0,
            "finding_categories": 0,
            "total_matches": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "elapsed_seconds": float(m["elapsed_seconds"]) if m.get("elapsed_seconds") else None,
            "scanner_exit_code": exit_code,
        })
        continue

    data = json.loads(path.read_text(encoding="utf-8"))
    findings = data.get("findings", {})
    severity_counts = data.get("summary", {}).get("severity_counts", {})
    total_matches = int(data.get("summary", {}).get("total_matches", 0) or 0)

    categories = set()
    for file_path, file_findings in findings.items():
        for category, detail in file_findings.items():
            categories.add(category)
            triage_rows.append({
                "repository": target["repository"],
                "commit": target["commit"],
                "file": file_path,
                "rule": category,
                "severity": detail.get("severity", ""),
                "match_count": detail.get("count", len(detail.get("matches", []))),
                "classification": "",
                "evidence": "",
                "root_cause": "",
                "reviewer": "",
            })

    m = meta.get(target_id, {})
    summary_rows.append({
        "id": target_id,
        "repository": target["repository"],
        "commit": target["commit"],
        "status": "scanned",
        "files_with_findings": len(findings),
        "finding_categories": len(categories),
        "total_matches": total_matches,
        "critical": int(severity_counts.get("CRITICAL", 0) or 0),
        "high": int(severity_counts.get("HIGH", 0) or 0),
        "medium": int(severity_counts.get("MEDIUM", 0) or 0),
        "low": int(severity_counts.get("LOW", 0) or 0),
        "elapsed_seconds": float(m["elapsed_seconds"]) if m.get("elapsed_seconds") else None,
        "scanner_exit_code": int(m["exit_code"]) if m.get("exit_code") else None,
    })

OUT.mkdir(parents=True, exist_ok=True)
(OUT / "summary.json").write_text(
    json.dumps({
        "benchmark": MANIFEST["name"],
        "frozen_at": MANIFEST["frozen_at"],
        "scanner": MANIFEST["scanner"],
        "repositories": summary_rows,
        "note": "Raw finding counts only. Precision/recall are not computed until independent/manual triage is complete."
    }, indent=2) + "\n",
    encoding="utf-8",
)

with (OUT / "triage.csv").open("w", encoding="utf-8", newline="") as fh:
    fields = [
        "repository", "commit", "file", "rule", "severity", "match_count",
        "classification", "evidence", "root_cause", "reviewer",
    ]
    writer = csv.DictWriter(fh, fieldnames=fields)
    writer.writeheader()
    writer.writerows(triage_rows)

lines = [
    "# AgentSecBench v2 — raw first-pass summary",
    "",
    "This table is scanner output only. It is **not** an accuracy score. Findings must be triaged before precision is calculated, and false negatives require targeted review.",
    "",
    "| Repository | Files with findings | Matches | Critical | High | Medium | Low | Seconds | Exit |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
]
for row in summary_rows:
    secs = "" if row["elapsed_seconds"] is None else f'{row["elapsed_seconds"]:.2f}'
    exit_code = "" if row["scanner_exit_code"] is None else str(row["scanner_exit_code"])
    lines.append(
        f'| {row["repository"]} | {row["files_with_findings"]} | {row["total_matches"]} | '
        f'{row["critical"]} | {row["high"]} | {row["medium"]} | {row["low"]} | {secs} | {exit_code} |'
    )

lines += [
    "",
    "## Scoring discipline",
    "",
    "- Do not change SecChecker while first-pass results are being collected or triaged.",
    "- A scanner finding is not automatically a true positive.",
    "- Record TP / FP / UNCERTAIN in the triage ledger with code evidence.",
    "- Record false negatives separately during targeted framework/trust-boundary review.",
    "- Only compute precision/recall after the labels are frozen.",
    "",
]
(OUT / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")
