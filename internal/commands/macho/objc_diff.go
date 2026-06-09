package macho

import (
	"errors"
	"fmt"
	"slices"
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

// addedRemoved returns the keys present only in next ("added") and only in prev
// ("removed"), each sorted.
func addedRemoved(prev, next map[string]struct{}) (added, removed []string) {
	for k := range next {
		if _, ok := prev[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range prev {
		if _, ok := next[k]; !ok {
			removed = append(removed, k)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

// memberDelta renders added ("+ ") and removed ("- ") member lines at column 0
// (so the surrounding ```diff fence colors them), returning "" when there is no
// change.
func memberDelta(added, removed []string) string {
	if len(added) == 0 && len(removed) == 0 {
		return ""
	}
	var b strings.Builder
	for _, a := range added {
		fmt.Fprintf(&b, "+   %s\n", a)
	}
	for _, r := range removed {
		fmt.Fprintf(&b, "-   %s\n", r)
	}
	return b.String()
}

// diffSection renders one named group (Classes/Protocols/Categories) as a diff
// hunk: an "@@ … @@" header, then added ("+ ") and removed ("- ") entities, then
// changed entities (a context line followed by their member deltas). members
// extracts an entity's comparable member keys; addedLine renders the descriptive
// text shown for a newly added entity.
func diffSection[T any](title string, prev, next map[string]*T, members func(*T) map[string]struct{}, addedLine func(*T) string) string {
	type change struct{ name, body string }
	var added, removed []string
	var changed []change

	for name, ne := range next {
		pe, ok := prev[name]
		if !ok {
			added = append(added, name)
			continue
		}
		if body := memberDelta(addedRemoved(members(pe), members(ne))); body != "" {
			changed = append(changed, change{name, body})
		}
	}
	for name := range prev {
		if _, ok := next[name]; !ok {
			removed = append(removed, name)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	slices.SortFunc(changed, func(a, b change) int { return strings.Compare(a.name, b.name) })

	var b strings.Builder
	if len(added)+len(removed)+len(changed) == 0 {
		fmt.Fprintf(&b, "@@ %s: no changes @@\n", title)
		return b.String()
	}
	fmt.Fprintf(&b, "@@ %s: +%d added, -%d removed, ~%d changed @@\n", title, len(added), len(removed), len(changed))
	for _, name := range added {
		fmt.Fprintf(&b, "+ %s\n", addedLine(next[name]))
	}
	for _, name := range removed {
		fmt.Fprintf(&b, "- %s\n", name)
	}
	for _, c := range changed {
		fmt.Fprintf(&b, " %s\n%s", c.name, c.body)
	}
	return b.String()
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
