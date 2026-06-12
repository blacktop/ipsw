/*
Copyright © 2018-2026 blacktop

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
package cmd

import "testing"

func TestShouldDisableColor(t *testing.T) {
	tests := []struct {
		name             string
		noColor          bool
		forceColor       bool
		stdoutIsTerminal bool
		want             bool
	}{
		{
			name:             "disables color when stdout is not a terminal",
			stdoutIsTerminal: false,
			want:             true,
		},
		{
			name:             "keeps color enabled for terminal stdout",
			stdoutIsTerminal: true,
			want:             false,
		},
		{
			name:             "force color overrides non-terminal stdout",
			forceColor:       true,
			stdoutIsTerminal: false,
			want:             false,
		},
		{
			name:             "no color overrides force color",
			noColor:          true,
			forceColor:       true,
			stdoutIsTerminal: true,
			want:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldDisableColor(tt.noColor, tt.forceColor, tt.stdoutIsTerminal); got != tt.want {
				t.Fatalf("shouldDisableColor(%v, %v, %v) = %v, want %v", tt.noColor, tt.forceColor, tt.stdoutIsTerminal, got, tt.want)
			}
		})
	}
}
