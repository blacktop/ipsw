/*
Copyright © 2026 blacktop

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
package macho

import (
	"errors"
	"fmt"
	"testing"

	gomacho "github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/dyld"
)

func TestCollectImportedMachODependenciesSkipsMissingCacheImages(t *testing.T) {
	t.Parallel()

	imports := []string{
		"/usr/lib/libSystem.B.dylib",
		"/System/Library/PrivateFrameworks/Missing.framework/Missing",
		"/System/Library/PrivateFrameworks/Present.framework/Present",
	}

	var skipped []string
	var resolved []string

	deps, err := collectImportedMachODependencies(
		imports,
		true,
		func(name string) (*gomacho.File, error) {
			resolved = append(resolved, name)
			switch name {
			case "/System/Library/PrivateFrameworks/Missing.framework/Missing":
				return nil, fmt.Errorf("lookup failed: %w", dyld.ErrImageNotFound)
			case "/System/Library/PrivateFrameworks/Present.framework/Present":
				return &gomacho.File{}, nil
			default:
				t.Fatalf("unexpected dependency lookup %q", name)
				return nil, nil
			}
		},
		func(name string, err error) {
			skipped = append(skipped, name)
		},
	)
	if err != nil {
		t.Fatalf("collectImportedMachODependencies returned error: %v", err)
	}

	if len(deps) != 1 {
		t.Fatalf("expected 1 resolved dependency, got %d", len(deps))
	}

	if len(skipped) != 1 || skipped[0] != "/System/Library/PrivateFrameworks/Missing.framework/Missing" {
		t.Fatalf("unexpected skipped dependencies: %#v", skipped)
	}

	if len(resolved) != 2 {
		t.Fatalf("expected only private frameworks to be resolved, got %#v", resolved)
	}
}

func TestCollectImportedMachODependenciesReturnsOtherErrors(t *testing.T) {
	t.Parallel()

	want := errors.New("boom")

	_, err := collectImportedMachODependencies(
		[]string{"/System/Library/PrivateFrameworks/Broken.framework/Broken"},
		true,
		func(name string) (*gomacho.File, error) {
			return nil, want
		},
		nil,
	)
	if !errors.Is(err, want) {
		t.Fatalf("expected error %v, got %v", want, err)
	}
}
