#!/usr/bin/env bash
# Fail if total statement coverage in a Go cover profile is below a threshold.
set -euo pipefail
profile=${1:?profile}
min=${2:?min}
total=$(go tool cover -func="$profile" | awk '/^total:/ {gsub("%","",$3); print $3}')
echo "core coverage: ${total}% (minimum ${min}%)"
awk -v t="$total" -v m="$min" 'BEGIN { exit (t+0 >= m+0) ? 0 : 1 }' || { echo "coverage below ${min}%"; exit 1; }
