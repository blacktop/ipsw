package xref

import "testing"

var (
	benchmarkResult       Result
	benchmarkResults      []Result
	benchmarkInstructions []Instruction
)

func BenchmarkDecodeFunction(b *testing.B) {
	data := referenceBenchData(512, 0)
	base := uint64(0x100000000)

	b.ReportAllocs()
	for b.Loop() {
		benchmarkInstructions = Decode(data, base)
	}
}

func BenchmarkScanFunctionReferencesNoMatch(b *testing.B) {
	data := referenceBenchData(512, 0)
	base := uint64(0x100000000)
	target := uint64(0x100080000)
	opts := Options{
		Targets: NewTargetSet(target),
		Mode:    ModeReferences,
	}

	b.ReportAllocs()
	for b.Loop() {
		benchmarkResults = ScanFunction(data, base, opts)
	}
}

func BenchmarkScanFunctionReferencesFirstMatch(b *testing.B) {
	base := uint64(0x100000000)
	target := uint64(0x100080000)
	data := referenceBenchData(512, target)
	opts := Options{
		Targets: NewTargetSet(target),
		Mode:    ModeReferences,
	}

	b.ReportAllocs()
	for b.Loop() {
		benchmarkResults = ScanFunction(data, base, opts)
	}
}

func BenchmarkScanFunctionReferencesFirstMatchOnly(b *testing.B) {
	base := uint64(0x100000000)
	target := uint64(0x100080000)
	data := referenceBenchData(512, target)
	opts := Options{
		Targets:        NewTargetSet(target),
		Mode:           ModeReferences,
		FirstMatchOnly: true,
	}

	b.ReportAllocs()
	for b.Loop() {
		benchmarkResults = ScanFunction(data, base, opts)
	}
}

func BenchmarkScannerReferencesNoMatch(b *testing.B) {
	data := referenceBenchData(512, 0)
	base := uint64(0x100000000)
	target := uint64(0x100080000)
	opts := Options{
		Targets: NewTargetSet(target),
		Mode:    ModeReferences,
	}
	var scanner Scanner

	b.ReportAllocs()
	for b.Loop() {
		benchmarkResults = scanner.ScanFunction(data, base, opts)
	}
}

func BenchmarkScannerReferencesFirstMatchOnly(b *testing.B) {
	base := uint64(0x100000000)
	target := uint64(0x100080000)
	data := referenceBenchData(512, target)
	opts := Options{
		Targets:        NewTargetSet(target),
		Mode:           ModeReferences,
		FirstMatchOnly: true,
	}
	var scanner Scanner

	b.ReportAllocs()
	for b.Loop() {
		benchmarkResults = scanner.ScanFunction(data, base, opts)
	}
}

func BenchmarkScannerFirstFunctionReferences(b *testing.B) {
	base := uint64(0x100000000)
	target := uint64(0x100080000)
	data := referenceBenchData(512, target)
	opts := Options{
		Targets: NewTargetSet(target),
		Mode:    ModeReferences,
	}
	var scanner Scanner

	b.ReportAllocs()
	for b.Loop() {
		var ok bool
		benchmarkResult, ok = scanner.ScanFirstFunction(data, base, opts)
		if !ok {
			b.Fatal("expected match")
		}
	}
}

func referenceBenchData(instructions int, matchTarget uint64) []byte {
	base := uint64(0x100000000)
	other := uint64(0x100040000)
	out := make([]uint32, 0, instructions)
	for len(out) < instructions {
		pc := base + uint64(len(out))*4
		target := other
		if matchTarget != 0 && len(out) == 16 {
			target = matchTarget
		}
		out = append(out, encADRP(16, pc, target))
		if len(out) >= instructions {
			break
		}
		out = append(out, encADDImm(16, 16, target&0xfff))
		for range 14 {
			if len(out) >= instructions {
				break
			}
			out = append(out, encNOP())
		}
	}
	return words(out...)
}
