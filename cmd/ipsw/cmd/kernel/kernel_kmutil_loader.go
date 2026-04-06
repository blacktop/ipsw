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
package kernel

import (
	"bytes"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

func openKernelCollection(path string) (*macho.File, error) {
	isMachO, err := magic.IsMachO(path)
	if err != nil {
		return nil, fmt.Errorf("failed to detect kernelcache Mach-O format: %w", err)
	}
	if isMachO {
		log.Info("Parsing KernelManagement kernelcache")
		m, err := macho.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to parse kernelcache MachO: %v", err)
		}
		return m, nil
	}

	isImg4, err := magic.IsImg4(path)
	if err != nil {
		return nil, fmt.Errorf("failed to detect kernelcache IMG4 format: %w", err)
	}
	if !isImg4 {
		return nil, fmt.Errorf("unsupported kernelcache format: expected Mach-O or IMG4")
	}

	log.Info("Decompressing KernelManagement kernelcache")
	data, err := kernelcache.DecompressKernelManagementData(path)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress kernelcache (kernel management data): %v", err)
	}

	m, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse kernelcache (kernel management data): %v", err)
	}

	return m, nil
}
