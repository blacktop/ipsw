#!/usr/bin/env bash
# Require measured result lines, not merely a benchmark announcement or SKIP.
set -euo pipefail
if (($# == 0)); then
	echo "usage: $0 output [output ...]" >&2
	exit 2
fi
expected="$(dirname "$0")/expected-benchmarks.txt"
for output in "$@"; do
	awk '
    NR == FNR { if (NF) expected[$0] = 1; next }
    $1 ~ /^Benchmark/ && $2 ~ /^[0-9]+$/ && $2 > 0 && $4 == "ns/op" {
      name = $1
      sub(/-[0-9]+$/, "", name)
      seen[name] = 1
    }
    END {
      for (name in expected) {
        if (!(name in seen)) {
          print FILENAME ": missing benchmark " name > "/dev/stderr"
          failed = 1
        }
      }
      exit failed
    }
  ' "$expected" "$output"
done
