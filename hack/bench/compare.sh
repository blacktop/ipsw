#!/usr/bin/env bash
# Called from the candidate checkout. Artifacts live outside both source trees.
set -euo pipefail
if (($# != 3 && $# != 4)) || [[ ${4:-} != '' && ${4:-} != '-count=1' ]]; then
	echo "usage: $0 candidate base results [-count=1]" >&2
	exit 2
fi
candidate=$(cd "$1" && pwd)
base=$(cd "$2" && pwd)
mkdir -p "$3"
results=$(cd "$3" && pwd)
bench='Benchmark(GetDylibPrebuiltLoader|SlidePointer|A2S|NormalizeSymbolForDiff|DiffNormalizedSymbols|GenerateDiffInfo|DiffInfoEquivalentDSC|IsMachO|DiffInfoGobRoundTrip)'
packages=(./pkg/dyld ./internal/commands/macho)
rounds=5
count=2
if [[ ${4:-} == '-count=1' ]]; then
	rounds=1
	count=1
fi
: >"$results/base.txt"
: >"$results/candidate.txt"
echo 'Comparison unavailable; see raw outputs and job logs.' >"$results/benchstat.txt"
printf 'Samples: %d per benchmark per tree; %d rounds, %d per invocation\n' \
	"$((rounds * count))" "$rounds" "$count" >>"$results/metadata.txt"

# Overlay only the self-contained benchmark closure, preserving ordinary tests.
# Pre-transition bases still declare some benchmarks in ordinary test files.
# Their duplicate declarations make the base not comparable once; after this
# layout lands on master, later bases can compare without rewriting their tests.
shopt -s nullglob
for package in "${packages[@]}"; do
	find "$base/$package" -maxdepth 1 -type f \( -name '*_bench_test.go' -o -name 'bench_*_test.go' \) -delete
	files=("$candidate/$package/"*_bench_test.go "$candidate/$package/"bench_*_test.go)
	cp "${files[@]}" "$base/$package/"
done

# Compile once per package per tree before any measurement. Candidate failures
# are fatal; base API/layout incompatibilities still leave candidate results.
comparable=true
for side in candidate base; do
	if [[ $side == candidate ]]; then cd "$candidate"; else cd "$base"; fi
	for package in "${packages[@]}"; do
		binary="$results/$side-$(basename "$package").test"
		if ! go test -c -o "$binary" "$package" >>"$results/$side.txt" 2>&1; then
			if [[ $side == candidate ]]; then
				cat "$results/candidate.txt" >&2
				exit 1
			fi
			comparable=false
		fi
	done
done

for ((round = 1; round <= rounds; round++)); do
	order=(candidate base)
	if ((round % 2 == 0)); then order=(base candidate); fi
	if [[ $comparable == false ]]; then order=(candidate); fi
	printf 'Round %d: %s\n' "$round" "${order[*]}" >>"$results/metadata.txt"
	for side in "${order[@]}"; do
		if [[ $side == candidate ]]; then cd "$candidate"; else cd "$base"; fi
		for package in "${packages[@]}"; do
			# Direct test binaries omit the package annotation emitted by go test.
			printf 'pkg: github.com/blacktop/ipsw/%s\n' "${package#./}" >>"$results/$side.txt"
			"$results/$side-$(basename "$package").test" -test.run '^$' \
				-test.bench "$bench" -test.benchmem -test.count="$count" 2>&1 | tee -a "$results/$side.txt"
		done
	done
done
"$candidate/hack/bench/assert-ran.sh" "$results/candidate.txt"
if [[ $comparable == false ]]; then
	{
		echo 'base not comparable: go test -c failed (API or benchmark-layout incompatibility).'
		cat "$results/base.txt"
	} >"$results/benchstat.txt"
	exit 0
fi
"$candidate/hack/bench/assert-ran.sh" "$results/base.txt" "$results/candidate.txt"
cd "$candidate"
# Reporting only: benchstat has no timing or allocation thresholds.
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20260908200009-22c9c6c9d4da \
	"$results/base.txt" "$results/candidate.txt" >"$results/benchstat.txt"
