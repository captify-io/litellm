#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 0 ]; then
  echo 'FATAL: no container scan reports supplied.' >&2
  exit 1
fi
for report in "$@"; do
  if ! jq -e '
    (.scan.status == "success") and
    (.vulnerabilities | type == "array") and
    all(.vulnerabilities[]; .severity | IN("Critical", "High", "Medium", "Low", "Info", "Unknown"))
  ' "$report" >/dev/null; then
    echo "FATAL: missing, invalid, or unsuccessful container scan report: $report" >&2
    exit 1
  fi
done
count=$(jq -s '[.[].vulnerabilities[] | select(.severity == "Critical" or .severity == "High")] | length' "$@")
if [ "$count" -gt 0 ]; then
  echo "FATAL: $count High/Critical vulnerabilities in candidate images; deployment blocked."
  jq -sr '.[].vulnerabilities[] | select(.severity == "Critical" or .severity == "High") | "\(.severity): \(.name // .cve // .id) -> \(.solution // "no published fix")"' "$@"
  exit 1
fi
echo 'Vulnerability gate PASS: every report succeeded and no High/Critical findings remain.'
