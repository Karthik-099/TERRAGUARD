#!/usr/bin/env python3
"""Rule regression evals for TerraGuard.

Each evals/cases/*.tf declares ground truth in header comments:
    # expect: TG-AWS-S3-001, TG-SEC-001   -> must fire (recall)
    # forbid: TG-AWS-IAM-001              -> must NOT fire (false positives)

Runs the CLI on every case and reports per-rule recall and false positives.
Exits 1 on any miss or false positive, so CI blocks regressions.
Stdlib only.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
from collections import defaultdict

CASES = pathlib.Path(__file__).parent / "cases"
HEADER = re.compile(r"^#\s*(expect|forbid):\s*(.+)$", re.M)


def ground_truth(path):
    truth = {"expect": set(), "forbid": set()}
    for kind, ids in HEADER.findall(path.read_text()):
        truth[kind].update(i.strip() for i in ids.split(",") if i.strip())
    return truth


def fired(binary, path):
    out = subprocess.run(
        [binary, "scan", str(path), "--format", "json", "--fail-on", "NONE"],
        capture_output=True, text=True, check=False,
    )
    if out.returncode >= 2:
        sys.exit(f"{path.name}: terraguard error: {out.stderr.strip()}")
    report = json.loads(out.stdout)
    return {f["rule_id"] for f in report["findings"] if not f.get("waived")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="bin/terraguard")
    ap.add_argument("--json", help="write results to this file")
    args = ap.parse_args()

    stats = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    failures = []
    cases = sorted(CASES.glob("*.tf"))
    for case in cases:
        truth, got = ground_truth(case), fired(args.binary, case)
        for rule in truth["expect"]:
            hit = rule in got
            stats[rule]["tp" if hit else "fn"] += 1
            if not hit:
                failures.append(f"MISS  {case.name}: expected {rule}")
        for rule in truth["forbid"]:
            bad = rule in got
            stats[rule]["fp" if bad else "tn"] += 1
            if bad:
                failures.append(f"FALSE POSITIVE  {case.name}: {rule} fired")

    tp = sum(s["tp"] for s in stats.values())
    fn = sum(s["fn"] for s in stats.values())
    fp = sum(s["fp"] for s in stats.values())
    recall = tp / (tp + fn) if tp + fn else 1.0
    precision = tp / (tp + fp) if tp + fp else 1.0

    print(f"{'rule':<18} {'tp':>3} {'fn':>3} {'fp':>3} {'tn':>3}")
    for rule in sorted(stats):
        s = stats[rule]
        print(f"{rule:<18} {s['tp']:>3} {s['fn']:>3} {s['fp']:>3} {s['tn']:>3}")
    print(f"\n{len(cases)} cases · {len(stats)} rules · recall {recall:.0%} · precision {precision:.0%}")
    for f in failures:
        print(f)
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(
            {"cases": len(cases), "recall": recall, "precision": precision, "rules": stats, "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
