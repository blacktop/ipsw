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
	"runtime/pprof"
	"runtime/trace"
	"time"
)

// Config represents profiling configuration
type Config struct {
	CPUProfile    string
	MemProfile    string
	GoroutineProf string
	BlockProf     string
	MutexProf     string
	TraceFile     string
	MemProfileRate int
}

// Profiler manages profiling operations
type Profiler struct {
	config   Config
	cpuFile  *os.File
	traceFile *os.File
	startTime time.Time
	startMem  runtime.MemStats
	originalMemProfileRate int
}

// New creates a new profiler with the given configuration
func New(cfg Config) *Profiler {
	return &Profiler{
		config:    cfg,
		startTime: time.Now(),
	}
}

// Start begins profiling based on configuration
func (p *Profiler) Start() error {
	// Store original memory profile rate
	p.originalMemProfileRate = runtime.MemProfileRate
	
	// Start CPU profiling
	if p.config.CPUProfile != "" {
		var err error
		p.cpuFile, err = os.Create(p.config.CPUProfile)
		if err != nil {
			return fmt.Errorf("could not create CPU profile: %w", err)
		}
		if err := pprof.StartCPUProfile(p.cpuFile); err != nil {
			p.cpuFile.Close()
			return fmt.Errorf("could not start CPU profile: %w", err)
		}
	}

	// Start execution trace
	if p.config.TraceFile != "" {
		var err error
		p.traceFile, err = os.Create(p.config.TraceFile)
		if err != nil {
			p.Stop() // Clean up any started profiles
			return fmt.Errorf("could not create trace file: %w", err)
		}
		if err := trace.Start(p.traceFile); err != nil {
			p.traceFile.Close()
			p.Stop()
			return fmt.Errorf("could not start trace: %w", err)
		}
	}

	// Set memory profiling rate
	if p.config.MemProfile != "" {
		if p.config.MemProfileRate > 0 {
			runtime.MemProfileRate = p.config.MemProfileRate
		} else {
			runtime.MemProfileRate = 4096 // Default sampling rate
		}
	}

	// Enable block profiling
	if p.config.BlockProf != "" {
		runtime.SetBlockProfileRate(1)
	}

	// Enable mutex profiling
	if p.config.MutexProf != "" {
		runtime.SetMutexProfileFraction(1)
	}

	// Capture initial memory stats
	runtime.ReadMemStats(&p.startMem)

	return nil
}

// Stop ends all profiling and writes memory/goroutine profiles
func (p *Profiler) Stop() error {
	var firstErr error

	// Stop CPU profiling
	if p.cpuFile != nil {
		pprof.StopCPUProfile()
		if err := p.cpuFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Stop execution trace
	if p.traceFile != nil {
		trace.Stop()
		if err := p.traceFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Write memory profile
	if p.config.MemProfile != "" {
		f, err := os.Create(p.config.MemProfile)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("could not create memory profile: %w", err)
			}
		} else {
			defer f.Close()
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("could not write memory profile: %w", err)
			}
		}
	}

	// Write goroutine profile
	if p.config.GoroutineProf != "" {
		f, err := os.Create(p.config.GoroutineProf)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("could not create goroutine profile: %w", err)
			}
		} else {
			defer f.Close()
			if err := pprof.Lookup("goroutine").WriteTo(f, 0); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("could not write goroutine profile: %w", err)
			}
		}
	}

	// Write block profile
	if p.config.BlockProf != "" {
		f, err := os.Create(p.config.BlockProf)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("could not create block profile: %w", err)
			}
		} else {
			defer f.Close()
			if err := pprof.Lookup("block").WriteTo(f, 0); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("could not write block profile: %w", err)
			}
		}
		runtime.SetBlockProfileRate(0)
	}

	// Write mutex profile
	if p.config.MutexProf != "" {
		f, err := os.Create(p.config.MutexProf)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("could not create mutex profile: %w", err)
			}
		} else {
			defer f.Close()
			if err := pprof.Lookup("mutex").WriteTo(f, 0); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("could not write mutex profile: %w", err)
			}
		}
		runtime.SetMutexProfileFraction(0)
	}

	// Restore original memory profile rate
	if p.config.MemProfile != "" {
		runtime.MemProfileRate = p.originalMemProfileRate
	}

	return firstErr
}

// PrintStats prints runtime statistics
func (p *Profiler) PrintStats() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	fmt.Printf("\n=== Performance Stats ===\n")
	fmt.Printf("Execution time: %v\n", time.Since(p.startTime))
	fmt.Printf("Memory allocated: %v MB (delta: %+v MB)\n", 
		m.Alloc/1024/1024, 
		(m.Alloc-p.startMem.Alloc)/1024/1024)
	fmt.Printf("Total memory allocated: %v MB\n", m.TotalAlloc/1024/1024)
	fmt.Printf("System memory: %v MB\n", m.Sys/1024/1024)
	fmt.Printf("GC runs: %v\n", m.NumGC-p.startMem.NumGC)
	fmt.Printf("Goroutines: %v\n", runtime.NumGoroutine())
}