#!/usr/bin/env python3
"""Benchmark free LLMs as Terraform reviewers against TerraGuard's labelled cases.

For each case the model gets the rule catalog and the .tf file and must answer
with the rule IDs that apply. Scored against the same expect/forbid labels as
run_evals.py, so you can see where an LLM alone misses or hallucinates — which
is why TerraGuard uses deterministic rules for gating and the LLM for
explanation.

Usage:
  GROQ_API_KEY=... python3 evals/llm_eval.py --provider groq [--model openai/gpt-oss-120b]
Providers: groq, gemini, openrouter (OpenAI-compatible endpoints). Stdlib only.
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

from run_evals import CASES, ground_truth

PROVIDERS = {
    "groq": ("https://api.groq.com/openai/v1", "openai/gpt-oss-120b", "GROQ_API_KEY"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.5-flash", "GEMINI_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "nvidia/nemotron-3-super-120b-a12b:free", "OPENROUTER_API_KEY"),
}


def chat(base, key, model, system, user, retries=3):
    body = json.dumps({"model": model, "temperature": 0, "messages": [
        {"role": "system", "content": system}, {"role": "user", "content": user}]}).encode()
    for attempt in range(retries):
        req = urllib.request.Request(f"{base}/chat/completions", data=body, headers={
            "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries - 1:  # free tiers rate-limit; back off
                time.sleep(10 * (attempt + 1))
                continue
            raise


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=PROVIDERS, required=True)
    ap.add_argument("--model")
    ap.add_argument("--binary", default="bin/terraguard")
    ap.add_argument("--summary", help="append a markdown table to this file (e.g. $GITHUB_STEP_SUMMARY)")
    args = ap.parse_args()

    base, default_model, key_env = PROVIDERS[args.provider]
    key = os.environ.get(key_env) or sys.exit(f"{key_env} is not set")
    model = args.model or default_model
    rules = json.loads(subprocess.run([args.binary, "rules", "--format", "json"], capture_output=True, text=True, check=True).stdout)
    catalog = "\n".join(f"{r['id']}: {r['title']}" for r in rules)
    system = ("You are a Terraform security and correctness reviewer. Given a rule catalog and a Terraform file, "
              "answer ONLY with a JSON array of the rule IDs that the file violates. No prose.")

    tp = fn = fp = tn = 0
    rows = []
    for case in sorted(CASES.glob("*.tf")):
        truth = ground_truth(case)
        src = re.sub(r"^#.*$", "", case.read_text(), flags=re.M)  # hide labels from the model
        t0 = time.time()
        try:
            answer = chat(base, key, model, system, f"Rule catalog:\n{catalog}\n\nTerraform ({case.name}):\n{src}")
            got = set(json.loads(answer[answer.index("["): answer.rindex("]") + 1]))
        except Exception as e:  # noqa: BLE001 — a malformed answer counts as no detections
            got, answer = set(), f"error: {e}"
        miss, false_pos = truth["expect"] - got, truth["forbid"] & got
        tp += len(truth["expect"] & got)
        fn += len(miss)
        fp += len(false_pos)
        tn += len(truth["forbid"] - got)
        rows.append((case.name, sorted(miss), sorted(false_pos), round(time.time() - t0, 1)))
        print(f"{case.name:<28} miss={sorted(miss)} fp={sorted(false_pos)}")

    recall = tp / (tp + fn) if tp + fn else 1
    precision = tp / (tp + fp) if tp + fp else 1
    line = f"**{args.provider} · {model}** — recall {recall:.0%}, precision {precision:.0%} ({tp} tp, {fn} fn, {fp} fp, {tn} tn)"
    print("\n" + line)
    if args.summary:
        with open(args.summary, "a") as f:
            f.write(f"### LLM-as-reviewer eval\n\n{line}\n\n| case | missed | false positives | seconds |\n|---|---|---|---|\n")
            for name, miss, fpos, sec in rows:
                f.write(f"| {name} | {', '.join(miss) or '—'} | {', '.join(fpos) or '—'} | {sec} |\n")
            f.write("\nDeterministic engine on the same cases: see `make evals` (100% is the CI gate).\n")


if __name__ == "__main__":
    main()
