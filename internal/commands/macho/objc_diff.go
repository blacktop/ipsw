package macho

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types/objc"
)

// objcModel is the structural snapshot of a dylib's ObjC metadata, keyed by
// name so two versions can be compared regardless of on-disk ordering. Values
// are pointers into the parser's result slices (the structs are large and only
// read).
type objcModel struct {
	classes    map[string]*objc.Class
	protocols  map[string]*objc.Protocol
	categories map[string]*objc.Category
}

func newObjcModel(f *macho.File) (*objcModel, error) {
	m := &objcModel{
		classes:    map[string]*objc.Class{},
		protocols:  map[string]*objc.Protocol{},
		categories: map[string]*objc.Category{},
	}
	classes, err := f.GetObjCClasses()
	if err != nil && !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return nil, fmt.Errorf("failed to get ObjC classes: %w", err)
	}
	for i := range classes {
		m.classes[classes[i].Name] = &classes[i]
	}
	protos, err := f.GetObjCProtocols()
	if err != nil && !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return nil, fmt.Errorf("failed to get ObjC protocols: %w", err)
	}
	for i := range protos {
		m.protocols[protos[i].Name] = &protos[i]
	}
	cats, err := f.GetObjCCategories()
	if err != nil && !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return nil, fmt.Errorf("failed to get ObjC categories: %w", err)
	}
	for i := range cats {
		m.categories[cats[i].Name] = &cats[i]
	}
	return m, nil
}

// Diff compares o (the newer build) against old, returning a ```diff-fenced
// structural diff: added/removed/changed classes, protocols, and categories.
// Identity is by name/selector, so the result is stable no matter what order
// the dylibs emit their ObjC symbols.
func (o *ObjC) Diff(old *ObjC) (string, error) {
	newModel, err := newObjcModel(o.file)
	if err != nil {
		return "", err
	}
	oldModel, err := newObjcModel(old.file)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# ObjC diff: %s\n\n```diff\n", o.conf.Name)
	b.WriteString(diffClasses(oldModel.classes, newModel.classes))
	b.WriteByte('\n')
	b.WriteString(diffProtocols(oldModel.protocols, newModel.protocols))
	b.WriteByte('\n')
	b.WriteString(diffCategories(oldModel.categories, newModel.categories))
	b.WriteString("```\n")
	return b.String(), nil
}

// methodKeys returns selector keys for instance ("-") and class ("+") methods,
// matching ObjC method notation.
func methodKeys(instance, class []objc.Method) map[string]struct{} {
	keys := make(map[string]struct{}, len(instance)+len(class))
	for _, m := range instance {
		keys["-"+m.Name] = struct{}{}
	}
	for _, m := range class {
		keys["+"+m.Name] = struct{}{}
	}
	return keys
}

func protocolKeys(protos []objc.Protocol) map[string]struct{} {
	keys := make(map[string]struct{}, len(protos))
	for _, p := range protos {
		keys["<"+p.Name+">"] = struct{}{}
	}
	return keys
}

func diffClasses(prev, next map[string]*objc.Class) string {
	return diffSection("Classes", prev, next,
		func(c *objc.Class) map[string]struct{} {
			keys := methodKeys(c.InstanceMethods, c.ClassMethods)
			for k := range protocolKeys(c.Protocols) {
				keys[k] = struct{}{}
			}
			return keys
		},
		func(c *objc.Class) string {
			return fmt.Sprintf("%s : %s  (%d methods)", c.Name, c.SuperClass, len(c.InstanceMethods)+len(c.ClassMethods))
		})
}

func diffProtocols(prev, next map[string]*objc.Protocol) string {
	return diffSection("Protocols", prev, next,
		func(p *objc.Protocol) map[string]struct{} {
			keys := methodKeys(p.InstanceMethods, p.ClassMethods)
			for _, m := range p.OptionalInstanceMethods {
				keys["-"+m.Name] = struct{}{}
			}
			for _, m := range p.OptionalClassMethods {
				keys["+"+m.Name] = struct{}{}
			}
			return keys
		},
		func(p *objc.Protocol) string { return p.Name })
}

func diffCategories(prev, next map[string]*objc.Category) string {
	return diffSection("Categories", prev, next,
		func(c *objc.Category) map[string]struct{} {
			return methodKeys(c.InstanceMethods, c.ClassMethods)
		},
		func(c *objc.Category) string { return c.Name })
}
