package vtable

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

// NewVtableSymbolicator creates a new vtable symbolicator for the given kernelcache
func NewVtableSymbolicator(file *macho.File) *VtableSymbolicator {
	return &VtableSymbolicator{
		file:                 file,
		classes:              make(map[uint64]*ClassMeta),
		classByName:          make(map[string]*ClassMeta),
		constructorTargetSet: make(map[uint64]bool),
		symbolMap:            make(map[uint64]string),
		stringMap:            make(map[string]map[string]uint64), // Critical: initialize stringMap
		// Production hardening features
		unresolvedRB: newRB(256),
		fnTraceCache: make(map[uint64]traceOut),
		counters:     discoveryCounters{}, // Explicitly initialize counters
	}
}

// LoadSymbolMap loads an external symbol map for method naming
func (vs *VtableSymbolicator) LoadSymbolMap(symMap map[uint64]string) {
	vs.symbolMap = symMap
}

// SymbolicateVtables performs the complete vtable symbolication process
func (vs *VtableSymbolicator) SymbolicateVtables() error {
	// Handle fileset kernelcaches - we need to process ALL entries (kernel + kexts)
	if vs.file.Type == types.MH_FILESET {
		log.Debugf("Processing MH_FILESET with %d entries", len(vs.file.FileSets()))

		// Step 1: First, find the OSMetaClass constructor in the kernel entry
		kernel, err := vs.file.GetFileSetFileByName("com.apple.kernel")
		if err != nil {
			return fmt.Errorf("failed to find kernel entry in fileset: %v", err)
		}

		log.Debugf("Finding OSMetaClass constructor in kernel entry...")

		kernelSymbolicator := NewVtableSymbolicator(kernel)
		if err := kernelSymbolicator.findOSMetaClassConstructor(); err != nil {
			return fmt.Errorf("failed to find OSMetaClass constructor in kernel: %v", err)
		}

		// Store the constructor info globally
		vs.constructorAddr = kernelSymbolicator.constructorAddr
		vs.constructorTargetSet = kernelSymbolicator.constructorTargetSet

		log.Debugf("Found OSMetaClass constructor at 0x%x, will use for all fileset entries", vs.constructorAddr)

		// Step 2: Build a global constructor target set by analyzing ALL fileset entries
		log.Debugf("Building global constructor target set for all fileset entries...")
		
		// Scan all fileset entries to build comprehensive target set
		for _, fe := range vs.file.FileSets() {
			entryFile, err := vs.file.GetFileSetFileByName(fe.EntryID)
			if err != nil {
				log.Debugf("Skipping fileset entry %s: %v", fe.EntryID, err)
				continue
			}

			// Add constructor stub symbols if present in this entry
			if entryFile.Symtab != nil {
				for _, sym := range entryFile.Symtab.Syms {
					switch sym.Name {
					case "__ZN11OSMetaClassC2EPKcPKS_j.stub",
						"__ZN11OSMetaClassC1EPKcPKS_j.stub",
						"__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t.stub",
						"__ZN11OSMetaClassC1EPKcPKS_jPP4zoneS1_19zone_create_flags_t.stub":
						vs.constructorTargetSet[sym.Value] = true
						log.Debugf("Added constructor stub symbol %s at %#x from %s", sym.Name, sym.Value, fe.EntryID)
					}
				}
			}

			// Create temporary symbolicator for this entry to find references and stubs
			entrySymbolicator := NewVtableSymbolicator(entryFile)
			entrySymbolicator.constructorAddr = vs.constructorAddr
			entrySymbolicator.constructorTargetSet = vs.constructorTargetSet // Share the global target set

			// Find constructor references specific to this entry
			if refs, err := entrySymbolicator.findConstructorReferences(); err == nil {
				for _, ref := range refs {
					vs.constructorTargetSet[ref] = true
				}
				if len(refs) > 0 {
					log.Debugf("Added %d constructor references from %s", len(refs), fe.EntryID)
				}

				// Find alias stubs specific to this entry
				if stubs, err := entrySymbolicator.findAliasStubs(refs); err == nil {
					for _, stub := range stubs {
						vs.constructorTargetSet[stub] = true
					}
					if len(stubs) > 0 {
						log.Debugf("Added %d alias stubs from %s", len(stubs), fe.EntryID)
					}
				}
			}
		}

		log.Debugf("Built global constructor target set with %d total entries", len(vs.constructorTargetSet))

		// Step 3: Process each fileset entry using the shared constructor info
		for _, fe := range vs.file.FileSets() {
			entryFile, err := vs.file.GetFileSetFileByName(fe.EntryID)
			if err != nil {
				log.Warnf("Failed to parse fileset entry %s: %v", fe.EntryID, err)
				continue // Skip entries that can't be parsed, don't fail the whole process
			}

			log.Debugf("Processing fileset entry: %s", fe.EntryID)

			// Create a new symbolicator for this fileset entry
			entrySymbolicator := NewVtableSymbolicator(entryFile)
			entrySymbolicator.symbolMap = vs.symbolMap

			// Share the global constructor info from the kernel
			entrySymbolicator.constructorAddr = vs.constructorAddr
			entrySymbolicator.constructorTargetSet = vs.constructorTargetSet // Use shared global target set

			log.Debugf("Using shared constructor target set with %d entries for %s", len(vs.constructorTargetSet), fe.EntryID)

			// For the kernel entry, do full symbolication
			if fe.EntryID == "com.apple.kernel" || fe.EntryID == "kernel" {
				if err := entrySymbolicator.SymbolicateVtables(); err != nil {
					log.Warnf("Failed to symbolicate vtables in kernel entry %s: %v", fe.EntryID, err)
					continue
				}
			} else {
				// For kext entries, skip constructor finding and just do class discovery
				if err := entrySymbolicator.discoverClasses(); err != nil {
					log.Debugf("No classes found in fileset entry %s: %v", fe.EntryID, err)
					continue // This is normal for many kexts that don't define C++ classes
				}

				if err := entrySymbolicator.resolveInheritance(); err != nil {
					log.Warnf("Failed to resolve inheritance in fileset entry %s: %v", fe.EntryID, err)
				}

				if err := entrySymbolicator.extractVtables(); err != nil {
					log.Warnf("Failed to extract vtables in fileset entry %s: %v", fe.EntryID, err)
				}

				if err := entrySymbolicator.nameVtableMethods(); err != nil {
					log.Warnf("Failed to name vtable methods in fileset entry %s: %v", fe.EntryID, err)
				}
			}

			// Merge classes found in this entry
			for metaPtr, class := range entrySymbolicator.classes {
				// Set the bundle name to identify which fileset entry this came from
				class.Bundle = fe.EntryID
				vs.classes[metaPtr] = class
				vs.classByName[class.Name] = class
			}

			if len(entrySymbolicator.classes) > 0 {
				log.Debugf("Found %d classes in %s (total: %d)", len(entrySymbolicator.classes), fe.EntryID, len(vs.classes))
			}
		}

		log.Debugf("Total classes discovered across all fileset entries: %d", len(vs.classes))

		return nil
	}

	if err := vs.findOSMetaClassConstructor(); err != nil {
		return fmt.Errorf("failed to find OSMetaClass constructor: %v", err)
	}

	if err := vs.discoverClasses(); err != nil {
		return fmt.Errorf("failed to discover classes: %v", err)
	}

	if err := vs.resolveInheritance(); err != nil {
		return fmt.Errorf("failed to resolve inheritance: %v", err)
	}

	if err := vs.extractVtables(); err != nil {
		return fmt.Errorf("failed to extract vtables: %v", err)
	}

	if err := vs.nameVtableMethods(); err != nil {
		return fmt.Errorf("failed to name vtable methods: %v", err)
	}

	return nil
}

// resolveInheritance builds the class inheritance hierarchy
func (vs *VtableSymbolicator) resolveInheritance() error {
	// Link each class to its parent using the SuperMeta field
	for _, class := range vs.classes {
		if class.SuperMeta != 0 {
			if parent, exists := vs.classes[class.SuperMeta]; exists {
				class.SuperClass = parent
			}
		}
	}

	return nil
}

// nameVtableMethods assigns names to vtable method entries
func (vs *VtableSymbolicator) nameVtableMethods() error {
	// Assign names using inheritance and external symbol maps
	for _, class := range vs.classes {
		vs.nameClassMethods(class)
	}

	return nil
}

// nameClassMethods assigns names to methods in a specific class
func (vs *VtableSymbolicator) nameClassMethods(class *ClassMeta) {
	for i := range class.Methods {
		method := &class.Methods[i]

		// Check external symbol map first
		if name, exists := vs.symbolMap[method.Address]; exists {
			method.Name = name
			continue
		}

		// Check if this address has a symbol in the main kernel
		if vs.file.Symtab != nil {
			for _, sym := range vs.file.Symtab.Syms {
				if sym.Value == method.Address {
					method.Name = sym.Name
					break
				}
			}
		}

		// If still no name, try inheritance
		if method.Name == "" && class.SuperClass != nil {
			if method.Index < len(class.SuperClass.Methods) {
				parentMethod := &class.SuperClass.Methods[method.Index]
				if parentMethod.Address == method.Address {
					// Inherited method
					method.Name = parentMethod.Name
				} else if parentMethod.Name != "" {
					// Overridden method, use parent name as base
					method.Name = fmt.Sprintf("%s::%s", class.Name, fmt.Sprintf("method_%d_%x", method.Index, method.Address))
				}
			}
		}

		// Last resort: generate placeholder name
		if method.Name == "" {
			method.Name = fmt.Sprintf("%s::method_%d_%x", class.Name, method.Index, method.Address)
		}
	}
}

// GetClasses returns all discovered classes
func (vs *VtableSymbolicator) GetClasses() []*ClassMeta {
	classes := make([]*ClassMeta, 0, len(vs.classes))
	for _, class := range vs.classes {
		classes = append(classes, class)
	}

	// Sort by name for consistent output
	sort.Slice(classes, func(i, j int) bool {
		return classes[i].Name < classes[j].Name
	})

	return classes
}

// GetClassByName returns a class by name
func (vs *VtableSymbolicator) GetClassByName(name string) (*ClassMeta, bool) {
	class, exists := vs.classByName[name]
	return class, exists
}

// GetSymbolMap returns a map of all discovered symbols
func (vs *VtableSymbolicator) GetSymbolMap() map[uint64]string {
	symbols := make(map[uint64]string)

	for _, class := range vs.classes {
		for _, method := range class.Methods {
			if method.Name != "" {
				symbols[method.Address] = method.Name
			}
		}
	}

	return symbols
}

// GetClassNames returns all discovered class names
func (vs *VtableSymbolicator) GetClassNames() []string {
	names := make([]string, 0, len(vs.classByName))
	for name := range vs.classByName {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// String returns a string representation of the symbolicator
func (vs *VtableSymbolicator) String() string {
	return fmt.Sprintf("VtableSymbolicator{classes: %d, symbols: %d}",
		len(vs.classes), len(vs.GetSymbolMap()))
}

// Legacy field accessors for backward compatibility

// GetFile returns the underlying macho.File
func (vs *VtableSymbolicator) GetFile() *macho.File {
	return vs.file
}

// GetStringMap returns the string map
func (vs *VtableSymbolicator) GetStringMap() map[string]map[string]uint64 {
	return vs.stringMap
}

// GetClassesByName returns the class by name map
func (vs *VtableSymbolicator) GetClassesByName() map[string]*ClassMeta {
	return vs.classByName
}

// ReadUint64AtAddr reads a uint64 from the given address
func (vs *VtableSymbolicator) ReadUint64AtAddr(addr uint64) (uint64, error) {
	// Validate address is not zero
	if addr == 0 {
		return 0, fmt.Errorf("cannot read from null address")
	}

	// Try to read from file segments
	for _, seg := range vs.file.Segments() {
		if addr >= seg.Addr && addr+8 <= seg.Addr+seg.Filesz {
			data, err := seg.Data()
			if err != nil {
				log.Debugf("Failed to get segment data for %s: %v", seg.Name, err)
				continue
			}
			offset := addr - seg.Addr
			if offset+8 <= uint64(len(data)) {
				return binary.LittleEndian.Uint64(data[offset : offset+8]), nil
			}
			log.Debugf("Offset %d+8 beyond segment %s data length %d", offset, seg.Name, len(data))
		}
	}
	return 0, fmt.Errorf("address %#x not readable in any segment", addr)
}
