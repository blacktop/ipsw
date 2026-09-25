#!/usr/bin/env bash
# Called from the candidate checkout. Artifacts live outside both source trees.
set -euo pipefail
if (($# != 3)); then
	echo "usage: $0 candidate base results" >&2
	exit 2
fi
candidate=$(cd "$1" && pwd)
base=$(cd "$2" && pwd)
mkdir -p "$3"
results=$(cd "$3" && pwd)
bench='Benchmark(GetDylibPrebuiltLoader|SlidePointer|A2S|NormalizeSymbolForDiff|DiffNormalizedSymbols|GenerateDiffInfo|DiffInfoEquivalentDSC|IsMachO|DiffInfoGobRoundTrip)'
packages=(./pkg/dyld ./internal/commands/macho)
: >"$results/base.txt"
: >"$results/candidate.txt"
echo 'Comparison unavailable; see raw outputs and job logs.' >"$results/benchstat.txt"

# Some benchmarks and their transitive helpers live in ordinary _test.go files.
# Replace the test surface in these two packages to avoid stale/duplicate units.
for package in "${packages[@]}"; do
	find "$base/$package" -maxdepth 1 -name '*_test.go' -type f -delete
	cp "$candidate/$package/"*_test.go "$base/$package/"
done

# Always capture candidate results, even when the old API cannot build the tests.
cd "$candidate"
go test -run '^$' -bench "$bench" -benchmem -count=10 "${packages[@]}" 2>&1 | tee "$results/candidate.txt"
"$candidate/hack/bench/assert-ran.sh" "$results/candidate.txt"

cd "$base"
comparable=true
for package in "${packages[@]}"; do
	binary="$results/$(basename "$package").test"
	if ! go test -c -o "$binary" "$package" >>"$results/base.txt" 2>&1; then
		comparable=false
	fi
	rm -f "$binary"
done
if [[ $comparable == false ]]; then
	echo 'base not comparable' >"$results/benchstat.txt"
	exit 0
fi
go test -run '^$' -bench "$bench" -benchmem -count=10 "${packages[@]}" 2>&1 | tee "$results/base.txt"
"$candidate/hack/bench/assert-ran.sh" "$results/base.txt" "$results/candidate.txt"
cd "$candidate"
# Reporting only: benchstat has no timing or allocation thresholds.
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20260908200009-22c9c6c9d4da \
	"$results/base.txt" "$results/candidate.txt" >"$results/benchstat.txt"
