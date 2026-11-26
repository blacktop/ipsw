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

// Command zipgen writes a skill directory as the zip that package skills embeds.
//
// Usage (run by `go generate ./internal/skills`):
//
//	go run ./zipgen <skill-dir> <output.zip>
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/blacktop/ipsw/internal/skills/skillzip"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: zipgen <skill-dir> <output.zip>")
		os.Exit(2)
	}
	var buf bytes.Buffer
	if err := skillzip.Write(&buf, os.DirFS(os.Args[1])); err != nil {
		fmt.Fprintf(os.Stderr, "zipgen: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "zipgen: failed to write %s: %v\n", os.Args[2], err)
		os.Exit(1)
	}
}
