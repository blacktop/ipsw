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
	"strings"

	"github.com/apex/log"
	gomacho "github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/dyld"
)

func loadImportedMachODependencies(
	cache *dyld.File,
	dylibName string,
	imports []string,
	privateFrameworksOnly bool,
) ([]*gomacho.File, error) {
	return collectImportedMachODependencies(
		imports,
		privateFrameworksOnly,
		func(imageName string) (*gomacho.File, error) {
			img, err := cache.Image(imageName)
			if err != nil {
				return nil, err
			}

			return img.GetMacho()
		},
		func(imageName string, err error) {
			log.WithError(err).WithFields(log.Fields{
				"dylib":      dylibName,
				"dependency": imageName,
			}).Warn("Skipping imported dependency missing from cache")
		},
	)
}

func collectImportedMachODependencies(
	imports []string,
	privateFrameworksOnly bool,
	resolve func(string) (*gomacho.File, error),
	onSkip func(string, error),
) ([]*gomacho.File, error) {
	deps := make([]*gomacho.File, 0, len(imports))

	for _, imp := range imports {
		if privateFrameworksOnly && !strings.Contains(imp, "PrivateFrameworks") {
			continue
		}

		m, err := resolve(imp)
		if err != nil {
			if errors.Is(err, dyld.ErrImageNotFound) {
				if onSkip != nil {
					onSkip(imp, err)
				}
				continue
			}

			return nil, err
		}

		deps = append(deps, m)
	}

	return deps, nil
}
