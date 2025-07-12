/*
Copyright © 2025 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package profile

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

// BenchmarkResult holds the results of a benchmark run
type BenchmarkResult struct {
	Name          string
	Duration      time.Duration
	MemAllocated  uint64
	MemDelta      int64
	TotalAlloc    uint64
	GCRuns        uint32
	Goroutines    int
	Error         error
}

// Benchmark represents a benchmark test
type Benchmark struct {
	name     string
	startTime time.Time
	startMem  runtime.MemStats
	endMem    runtime.MemStats
}

// NewBenchmark creates a new benchmark with the given name
func NewBenchmark(name string) *Benchmark {
	return &Benchmark{
		name: name,
	}
}

// Start begins the benchmark timing and memory measurement
func (b *Benchmark) Start() {
	runtime.GC()
	runtime.ReadMemStats(&b.startMem)
	b.startTime = time.Now()
}

// Stop ends the benchmark and returns the results
func (b *Benchmark) Stop() BenchmarkResult {
	duration := time.Since(b.startTime)
	runtime.ReadMemStats(&b.endMem)
	
	return BenchmarkResult{
		Name:          b.name,
		Duration:      duration,
		MemAllocated:  b.endMem.Alloc,
		MemDelta:      int64(b.endMem.Alloc) - int64(b.startMem.Alloc),
		TotalAlloc:    b.endMem.TotalAlloc - b.startMem.TotalAlloc,
		GCRuns:        b.endMem.NumGC - b.startMem.NumGC,
		Goroutines:    runtime.NumGoroutine(),
	}
}

// PrintResult prints the benchmark result in a formatted way
func (r BenchmarkResult) PrintResult() {
	fmt.Printf("\n=== Benchmark Results: %s ===\n", r.Name)
	fmt.Printf("Duration: %v\n", r.Duration)
	fmt.Printf("Memory allocated: %v MB\n", r.MemAllocated/1024/1024)
	fmt.Printf("Memory delta: %+v MB\n", r.MemDelta/1024/1024)
	fmt.Printf("Total allocated: %v MB\n", r.TotalAlloc/1024/1024)
	fmt.Printf("GC runs: %v\n", r.GCRuns)
	fmt.Printf("Goroutines: %v\n", r.Goroutines)
	if r.Error != nil {
		fmt.Printf("Error: %v\n", r.Error)
	}
	fmt.Printf("Performance: %.2f MB/s\n", float64(r.TotalAlloc)/1024/1024/r.Duration.Seconds())
}

// BenchmarkSuite holds multiple benchmark results
type BenchmarkSuite struct {
	results []BenchmarkResult
}

// NewBenchmarkSuite creates a new benchmark suite
func NewBenchmarkSuite() *BenchmarkSuite {
	return &BenchmarkSuite{
		results: make([]BenchmarkResult, 0),
	}
}

// Add adds a benchmark result to the suite
func (bs *BenchmarkSuite) Add(result BenchmarkResult) {
	bs.results = append(bs.results, result)
}

// PrintSummary prints a summary of all benchmark results
func (bs *BenchmarkSuite) PrintSummary() {
	if len(bs.results) == 0 {
		return
	}
	
	fmt.Printf("\n=== Benchmark Suite Summary ===\n")
	fmt.Printf("%-30s %-12s %-12s %-12s %-8s\n", "Name", "Duration", "Memory", "GC Runs", "Status")
	fmt.Printf("%-30s %-12s %-12s %-12s %-8s\n", "----", "--------", "------", "-------", "------")
	
	var totalDuration time.Duration
	var totalMem uint64
	var totalGC uint32
	
	for _, result := range bs.results {
		status := "OK"
		if result.Error != nil {
			status = "ERROR"
		}
		
		fmt.Printf("%-30s %-12v %-12s %-12d %-8s\n", 
			result.Name, 
			result.Duration, 
			fmt.Sprintf("%.1fMB", float64(result.TotalAlloc)/1024/1024),
			result.GCRuns,
			status)
		
		totalDuration += result.Duration
		totalMem += result.TotalAlloc
		totalGC += result.GCRuns
	}
	
	fmt.Printf("%-30s %-12s %-12s %-12s %-8s\n", "----", "--------", "------", "-------", "------")
	fmt.Printf("%-30s %-12v %-12s %-12d %-8s\n", 
		"TOTAL", 
		totalDuration, 
		fmt.Sprintf("%.1fMB", float64(totalMem)/1024/1024),
		totalGC,
		"")
}

// SaveToFile saves the benchmark results to a file
func (bs *BenchmarkSuite) SaveToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	fmt.Fprintf(file, "# Benchmark Results\n")
	fmt.Fprintf(file, "Generated: %s\n\n", time.Now().Format(time.RFC3339))
	
	for _, result := range bs.results {
		fmt.Fprintf(file, "## %s\n", result.Name)
		fmt.Fprintf(file, "- Duration: %v\n", result.Duration)
		fmt.Fprintf(file, "- Memory Allocated: %v MB\n", result.MemAllocated/1024/1024)
		fmt.Fprintf(file, "- Memory Delta: %+v MB\n", result.MemDelta/1024/1024)
		fmt.Fprintf(file, "- Total Allocated: %v MB\n", result.TotalAlloc/1024/1024)
		fmt.Fprintf(file, "- GC Runs: %v\n", result.GCRuns)
		fmt.Fprintf(file, "- Goroutines: %v\n", result.Goroutines)
		if result.Error != nil {
			fmt.Fprintf(file, "- Error: %v\n", result.Error)
		}
		fmt.Fprintf(file, "\n")
	}
	
	return nil
}

// BenchmarkFunc runs a function and returns benchmark results
func BenchmarkFunc(name string, fn func() error) BenchmarkResult {
	b := NewBenchmark(name)
	b.Start()
	
	err := fn()
	
	result := b.Stop()
	result.Error = err
	
	return result
}