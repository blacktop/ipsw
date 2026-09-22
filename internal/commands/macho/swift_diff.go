package macho

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/swift"
	stypes "github.com/blacktop/go-macho/types/swift"
	"golang.org/x/sync/errgroup"
)

// swiftSubAddr matches the address-derived placeholder names the Swift dumper
// gives unnamed functions. They move on every rebuild, so they are normalized
// away; the __ptrauth discriminator on the same line still identifies the method.
var swiftSubAddr = regexp.MustCompile(`\bsub_[0-9a-f]+`)

// swiftEntity is one Swift declaration (type, protocol, conformance or
// associated-type extension): a stable identity built from its typed
// descriptor, and every rendered line of its declaration as a member, so two
// builds can be compared regardless of layout or addresses.
type swiftEntity struct {
	key     string
	members map[string]struct{}
}

// swiftModel is the structural snapshot of a dylib's Swift metadata, keyed by
// declaration identity.
type swiftModel struct {
	types        map[string]*swiftEntity
	protocols    map[string]*swiftEntity
	conformances map[string]*swiftEntity
	assocTypes   map[string]*swiftEntity
}

// newSwiftEntity turns the dumper's rendered text for one declaration into
// members: every non-blank line minus closing braces and the "/* fields */"
// section labels, with body-opening braces and function addresses normalized.
// The header line stays a member so a changed superclass or generic signature
// shows as a changed line under a stable key.
func newSwiftEntity(key, rendered string) *swiftEntity {
	e := &swiftEntity{key: key, members: map[string]struct{}{}}
	for line := range strings.SplitSeq(rendered, "\n") {
		line = strings.TrimSpace(swiftSubAddr.ReplaceAllString(line, "sub_"))
		if line == "" || line == "}" {
			continue
		}
		if strings.HasPrefix(line, "/*") && strings.HasSuffix(line, "*/") {
			continue
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, " {}"), " {")
		e.members[line] = struct{}{}
	}
	return e
}

// addSwiftEntity files a declaration under its key, merging members when two
// declarations share one (opaque types have no name of their own).
func addSwiftEntity(into map[string]*swiftEntity, key, rendered string) {
	e := newSwiftEntity(key, rendered)
	if prev, ok := into[key]; ok {
		maps.Copy(prev.members, e.members)
		return
	}
	into[key] = e
}

// swiftTypeKey mirrors how the dumper prints a type's qualified name (up to
// two enclosing contexts) without its generic signature, so the key survives
// signature and superclass changes.
func swiftTypeKey(t stypes.Type) string {
	var parent string
	if t.Parent != nil {
		if t.Parent.Parent != nil && t.Parent.Parent.Name != "" {
			parent += t.Parent.Parent.Name + "."
		}
		if t.Parent.Name != "" {
			parent += t.Parent.Name + "."
		}
	}
	return fmt.Sprintf("%s %s%s", t.Kind, parent, t.Name)
}

func swiftProtocolKey(p stypes.Protocol) string {
	var parent string
	if p.Parent != nil && p.Parent.Name != "" {
		parent = p.Parent.Name + "."
	}
	return "protocol " + parent + p.Name
}

func swiftConformanceKey(c stypes.ConformanceDescriptor) string {
	var parent string
	if c.TypeRef != nil && c.TypeRef.Parent != nil && c.TypeRef.Parent.Name != "" {
		parent = c.TypeRef.Parent.Name + "."
	}
	var name string
	if c.TypeRef != nil {
		name = c.TypeRef.Name
	}
	return "protocol conformance " + parent + name + " : " + c.Protocol
}

func swiftAssociatedTypeKey(a stypes.AssociatedType) string {
	return "extension " + a.ConformingTypeName + ": " + a.ProtocolTypeName
}

// render applies the dump's demangling to text produced by the Swift renderers.
func (s *Swift) render(text string) string {
	if s.conf.Demangle {
		return swift.DemangleSimpleBlob(text)
	}
	return text
}

// diffModel snapshots the Swift metadata of s.file. A missing Swift section is
// an empty group, not an error.
func (s *Swift) diffModel() (*swiftModel, error) {
	restore := s.setAutoDemangle(s.conf.Demangle)
	defer restore()

	m := &swiftModel{
		types:        map[string]*swiftEntity{},
		protocols:    map[string]*swiftEntity{},
		conformances: map[string]*swiftEntity{},
		assocTypes:   map[string]*swiftEntity{},
	}
	if err := s.file.PreCache(); err != nil {
		return nil, fmt.Errorf("failed to precache swift fields/types for %s: %w", s.conf.Name, err)
	}

	typs, err := s.file.GetSwiftTypes()
	if err != nil && !errors.Is(err, macho.ErrSwiftSectionError) {
		return nil, fmt.Errorf("failed to get Swift types: %w", err)
	}
	for _, t := range typs {
		addSwiftEntity(m.types, s.render(swiftTypeKey(t)), s.render(t.String()))
	}
	protos, err := s.file.GetSwiftProtocols()
	if err != nil && !errors.Is(err, macho.ErrSwiftSectionError) {
		return nil, fmt.Errorf("failed to get Swift protocols: %w", err)
	}
	for _, p := range protos {
		addSwiftEntity(m.protocols, s.render(swiftProtocolKey(p)), s.render(p.String()))
	}
	confs, err := s.file.GetSwiftProtocolConformances()
	if err != nil && !errors.Is(err, macho.ErrSwiftSectionError) {
		return nil, fmt.Errorf("failed to get Swift protocol conformances: %w", err)
	}
	for _, c := range confs {
		addSwiftEntity(m.conformances, s.render(swiftConformanceKey(c)), s.render(c.String()))
	}
	assocs, err := s.file.GetSwiftAssociatedTypes()
	if err != nil && !errors.Is(err, macho.ErrSwiftSectionError) {
		return nil, fmt.Errorf("failed to get Swift associated types: %w", err)
	}
	for _, a := range assocs {
		addSwiftEntity(m.assocTypes, s.render(swiftAssociatedTypeKey(a)), s.render(a.String()))
	}
	return m, nil
}

// Diff compares s (the newer build) against old, returning a ```diff-fenced
// structural diff of types, protocols, conformances and associated types.
// Identity comes from the typed descriptors; members are the rendered lines
// with function addresses normalized, so a rebuild with no source change is
// reported as "no changes". The two models are built concurrently: they touch
// separate files and the parsers keep no shared mutable state.
func (s *Swift) Diff(old *Swift) (string, error) {
	var newModel, oldModel *swiftModel
	var g errgroup.Group
	g.Go(func() (err error) {
		newModel, err = s.diffModel()
		return err
	})
	g.Go(func() (err error) {
		oldModel, err = old.diffModel()
		return err
	})
	if err := g.Wait(); err != nil {
		return "", err
	}
	return diffSwiftModels(s.conf.Name, oldModel, newModel), nil
}

func diffSwiftModels(name string, prev, next *swiftModel) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Swift diff: %s\n\n```diff\n", name)
	b.WriteString(diffSwiftEntities("Types", prev.types, next.types))
	b.WriteByte('\n')
	b.WriteString(diffSwiftEntities("Protocols", prev.protocols, next.protocols))
	b.WriteByte('\n')
	b.WriteString(diffSwiftEntities("Conformances", prev.conformances, next.conformances))
	b.WriteByte('\n')
	b.WriteString(diffSwiftEntities("Associated Types", prev.assocTypes, next.assocTypes))
	b.WriteString("```\n")
	return b.String()
}

func diffSwiftEntities(title string, prev, next map[string]*swiftEntity) string {
	return diffSection(title, prev, next,
		func(e *swiftEntity) map[string]struct{} { return e.members },
		func(e *swiftEntity) string { return fmt.Sprintf("%s  (%d members)", e.key, len(e.members)) })
}
