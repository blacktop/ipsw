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
	"github.com/spf13/cobra"
)

// ProfilingFlags holds profiling flag values
type ProfilingFlags struct {
	CPUProfile    string
	MemProfile    string
	GoroutineProf string
	BlockProf     string
	MutexProf     string
	TraceFile     string
	MemProfileRate int
}

// AddFlags adds profiling flags to the given command
func AddFlags(cmd *cobra.Command, flags *ProfilingFlags) {
	cmd.Flags().StringVar(&flags.CPUProfile, "cpu-profile", "", "Write CPU profile to file")
	cmd.Flags().StringVar(&flags.MemProfile, "mem-profile", "", "Write memory profile to file")
	cmd.Flags().StringVar(&flags.GoroutineProf, "goroutine-profile", "", "Write goroutine profile to file")
	cmd.Flags().StringVar(&flags.BlockProf, "block-profile", "", "Write block profile to file")
	cmd.Flags().StringVar(&flags.MutexProf, "mutex-profile", "", "Write mutex profile to file")
	cmd.Flags().StringVar(&flags.TraceFile, "trace", "", "Write execution trace to file")
	cmd.Flags().IntVar(&flags.MemProfileRate, "mem-profile-rate", 0, "Memory profiling rate (0 to disable)")
}

// IsEnabled returns true if any profiling is enabled
func (f *ProfilingFlags) IsEnabled() bool {
	return f.CPUProfile != "" || f.MemProfile != "" || f.GoroutineProf != "" ||
		f.BlockProf != "" || f.MutexProf != "" || f.TraceFile != ""
}

// ToConfig converts flags to profiling config
func (f *ProfilingFlags) ToConfig() Config {
	return Config{
		CPUProfile:    f.CPUProfile,
		MemProfile:    f.MemProfile,
		GoroutineProf: f.GoroutineProf,
		BlockProf:     f.BlockProf,
		MutexProf:     f.MutexProf,
		TraceFile:     f.TraceFile,
		MemProfileRate: f.MemProfileRate,
	}
}