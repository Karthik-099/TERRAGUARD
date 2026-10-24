#!/usr/bin/env bash
# Fails if anything that looks like a real credential is tracked by git.
# Used by CI and as a pre-commit hook:  ln -s ../../scripts/check-secrets.sh .git/hooks/pre-commit
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

patterns=(
  'gsk_[A-Za-z0-9]{40,}'                 # Groq
  'sk-or-v1-[a-f0-9]{40,}'               # OpenRouter
  'sk-(proj-)?[A-Za-z0-9_-]{32,}'        # OpenAI
  'AIza[0-9A-Za-z_-]{35}'                # Google
  'gh[pousr]_[A-Za-z0-9]{36}'            # GitHub
  'xox[baprs]-[A-Za-z0-9-]{10,}'         # Slack
  '(AKIA|ASIA)[0-9A-Z]{16}'              # AWS access key id
  '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'
)
# Files staged for commit (pre-commit) or all tracked files (CI).
if [ "${1:-}" = "--all" ] || [ -z "$(git diff --cached --name-only)" ]; then
  files=$(git ls-files)
else
  files=$(git diff --cached --name-only --diff-filter=ACM)
fi

fail=0
# .env must never be tracked.
if echo "$files" | grep -qE '(^|/)\.env$'; then echo "✗ .env is tracked by git"; fail=1; fi
for f in $files; do
  [ -f "$f" ] || continue
  [ "$f" = scripts/check-secrets.sh ] && continue
  case "$f" in
    examples/*|evals/cases/*) allow='AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI' ;;  # AWS's documented fake keys in test fixtures
    *) allow='^$' ;;
  esac
  for p in "${patterns[@]}"; do
    if grep -nE -- "$p" "$f" 2>/dev/null | grep -vE -- "$allow" | grep -q .; then
      echo "✗ possible secret in $f (pattern: $p)"
      fail=1
    fi
  done
done
[ $fail -eq 0 ] && echo "✓ no secrets found in $(echo "$files" | wc -l) files"
exit $fail
