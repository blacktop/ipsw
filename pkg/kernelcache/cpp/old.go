package cpp

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

/* junk drawer */

// InitFunc holds information about a __mod_init_func entry
type InitFunc struct {
	types.Function
	entryID string
}

// getModInitFuncPointers returns a map of all __mod_init_func pointers for quick lookup
func (c *Cpp) getModInitFuncPointers(m *macho.File, entryID string) (map[uint64]bool, error) {
	var modInitSec *types.Section
	if sec := m.Section("__DATA_CONST", "__mod_init_func"); sec != nil {
		modInitSec = sec
	} else if sec := m.Section("__DATA", "__mod_init_func"); sec != nil {
		modInitSec = sec
	}

	if modInitSec == nil {
		return nil, fmt.Errorf("__mod_init_func section not found")
	}

	data, err := modInitSec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read __mod_init_func: %w", err)
	}

	ptrs := make(map[uint64]bool)
	for i := 0; i < len(data); i += 8 {
		ptrVA := modInitSec.Addr + uint64(i)
		var ptr uint64
		var err error

		// For MH_FILESET, use root to read pointers (fixups are in root kernelcache)
		if c.root.Type == types.MH_FILESET {
			ptr, err = c.root.GetPointerAtAddress(ptrVA)
		} else {
			ptr, err = m.GetPointerAtAddress(ptrVA)
		}

		if err != nil {
			// Fallback to raw read
			ptr = binary.LittleEndian.Uint64(data[i : i+8])
			log.Debugf("Failed to get pointer at %#x, using raw value: %#x", ptrVA, ptr)
		}

		if ptr != 0 {
			ptrs[ptr] = true
			log.Debugf("__mod_init_func[%d] = %#x", i/8, ptr)
		}
	}

	return ptrs, nil
}

func (c *Cpp) getInitFunctions(ctx context.Context, m *macho.File, entryID string) (<-chan InitFunc, error) {
	var modInitSec *types.Section
	if sec := m.Section("__DATA_CONST", "__mod_init_func"); sec != nil {
		modInitSec = sec
	} else if sec := m.Section("__DATA", "__mod_init_func"); sec != nil {
		modInitSec = sec
	}
	if modInitSec == nil {
		return nil, fmt.Errorf("failed to find __mod_init_func section")
	}

	numPtrs := int(modInitSec.Size / 8)
	initsChan := make(chan InitFunc, min(numPtrs, 100))

	log.Debugf("Found __mod_init_func in %s with %d entries at offset %#x", entryID, numPtrs, modInitSec.Offset)

	go func() {
		defer close(initsChan)

		for i := range numPtrs {
			// Check for cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}

			ptrVA := modInitSec.Addr + uint64(i*8)

			var ptr uint64
			var err error
			if c.root.Type == types.MH_FILESET {
				// For MH_FILESET, we need to use the main kernel to read the pointer
				// since the address might be outside the entry's segments
				ptr, err = c.root.GetPointerAtAddress(ptrVA)
			} else {
				ptr, err = m.GetPointerAtAddress(ptrVA)
			}
			if err != nil {
				log.Debugf("Failed to read pointer at VA %#x: %v", ptrVA, err)
				continue
			}
			if ptr == 0 {
				log.Debugf("Skipping null init func pointer at VA %#x", ptrVA)
				continue
			}

			fn, err := m.GetFunctionForVMAddr(ptr)
			if err != nil {
				log.Debugf("No function found for init func pointer %#x at VA %#x: %v", ptr, ptrVA, err)
				continue
			}

			select {
			case <-ctx.Done():
				return
			case initsChan <- InitFunc{
				Function: fn,
				entryID:  entryID,
			}:
			}
		}
	}()

	return initsChan, nil
}

func dedupeClasses(classes []Class) []Class {

	type key struct {
		meta   uint64
		name   string
		bundle string
	}
	result := make([]Class, 0, len(classes))
	indexByKey := make(map[key]int)

	for _, class := range classes {
		k := key{meta: class.MetaPtr, name: class.Name, bundle: class.Bundle}
		if idx, ok := indexByKey[k]; ok {
			existing := &result[idx]
			if existing.VtableAddr == 0 && class.VtableAddr != 0 {
				existing.VtableAddr = class.VtableAddr
			}
			if existing.MetaVtableAddr == 0 && class.MetaVtableAddr != 0 {
				existing.MetaVtableAddr = class.MetaVtableAddr
			}
			if existing.Name == "" && class.Name != "" {
				existing.Name = class.Name
			}
			if existing.NamePtr == 0 && class.NamePtr != 0 {
				existing.NamePtr = class.NamePtr
			}
			if existing.SuperMeta == 0 && class.SuperMeta != 0 {
				existing.SuperMeta = class.SuperMeta
			}
			if existing.Size == 0 && class.Size != 0 {
				existing.Size = class.Size
			}
			if len(class.Methods) > len(existing.Methods) {
				existing.Methods = class.Methods
			}
			if class.SuperClass != nil && existing.SuperClass == nil {
				existing.SuperClass = class.SuperClass
			}
			if existing.Ctor == 0 && class.Ctor != 0 {
				existing.Ctor = class.Ctor
			}
			if existing.DiscoveryPC == 0 && class.DiscoveryPC != 0 {
				existing.DiscoveryPC = class.DiscoveryPC
			}
			if existing.m == nil && class.m != nil {
				existing.m = class.m
			}
			continue
		}

		indexByKey[k] = len(result)
		result = append(result, class)
	}

	return result
}
