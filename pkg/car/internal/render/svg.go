package render

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html/charset"
)

const maxRenderSVGReferences = 65536

// SVG rendering is deliberately self-contained: no scripts, CSS sheets,
// embedded images, or external resources. Fragment references still support
// common icon constructs such as gradients, masks, and reusable paths.
func validateRenderSVG(data []byte) error {
	const maxNodes = 8192
	if len(data) > 16<<20 {
		return fmt.Errorf("SVG source exceeds 16 MiB")
	}
	type node struct {
		children []int
		refs     []string
	}
	var nodes []node
	var stack []int
	referenceCount := 0
	ids := make(map[string][]int)
	d := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
	d.CharsetReader = charset.NewReaderLabel
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid SVG: %w", err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			if len(stack) == 64 || len(nodes) == maxNodes {
				return fmt.Errorf("SVG exceeds element or nesting limit")
			}
			if token.Name.Space != "" && token.Name.Space != "http://www.w3.org/2000/svg" {
				return fmt.Errorf("unsupported SVG element namespace: %q", token.Name.Space)
			}
			if len(stack) == 0 && (len(nodes) != 0 || token.Name.Local != "svg") {
				return fmt.Errorf("SVG must contain one svg root")
			}
			switch token.Name.Local {
			case "svg", "g", "defs", "title", "desc", "path", "rect", "circle", "ellipse",
				"line", "polyline", "polygon", "use", "clipPath", "mask", "linearGradient",
				"radialGradient", "stop", "pattern", "symbol", "text", "tspan", "textPath":
			default:
				return fmt.Errorf("unsupported SVG rendering element: %q", token.Name.Local)
			}
			index := len(nodes)
			nodes = append(nodes, node{})
			if len(stack) != 0 {
				parent := stack[len(stack)-1]
				nodes[parent].children = append(nodes[parent].children, index)
			}
			stack = append(stack, index)
			for _, attr := range token.Attr {
				if attr.Name.Space == "xmlns" || attr.Name.Local == "xmlns" {
					continue
				}
				name := strings.ToLower(attr.Name.Local)
				if strings.HasPrefix(name, "on") || name == "base" {
					return fmt.Errorf("unsupported SVG rendering attribute: %q", attr.Name.Local)
				}
				if name == "id" {
					ids[attr.Value] = append(ids[attr.Value], index)
					continue
				}
				refs, err := renderSVGReferences(name, attr.Value)
				if err != nil {
					return err
				}
				if len(refs) > maxRenderSVGReferences-referenceCount {
					return fmt.Errorf("SVG reference count exceeds limit")
				}
				referenceCount += len(refs)
				nodes[index].refs = append(nodes[index].refs, refs...)
			}
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.Directive:
			return fmt.Errorf("SVG declarations are unsupported for rendering")
		case xml.ProcInst:
			if token.Target != "xml" {
				return fmt.Errorf("SVG processing instructions are unsupported for rendering")
			}
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(token)) != 0 {
				return fmt.Errorf("text outside SVG root")
			}
		}
	}
	if len(nodes) == 0 || len(stack) != 0 {
		return fmt.Errorf("missing or incomplete SVG root")
	}
	edges := len(nodes) - 1
	for i := range nodes {
		for _, ref := range nodes[i].refs {
			targets, ok := ids[ref]
			if !ok {
				return fmt.Errorf("SVG fragment target is missing: %.128q", ref)
			}
			// Some compiled sources repeat unused IDs. Referenced duplicates are
			// ambiguous and could multiply into a quadratic dependency graph.
			if len(targets) != 1 {
				return fmt.Errorf("ambiguous SVG fragment target: %.128q", ref)
			}
			if edges == maxRenderSVGReferences {
				return fmt.Errorf("SVG reference graph exceeds limit")
			}
			edges++
			nodes[i].children = append(nodes[i].children, targets[0])
		}
	}
	// Count expanded references, not only source elements: a small DAG of uses
	// can otherwise multiply into an unbounded amount of native drawing work.
	counts := make([]int, len(nodes))
	active := make([]bool, len(nodes))
	var visit func(int, int) (int, error)
	visit = func(index, depth int) (int, error) {
		if depth > 128 || active[index] {
			return 0, fmt.Errorf("cyclic or excessive SVG references")
		}
		if counts[index] != 0 {
			return counts[index], nil
		}
		active[index] = true
		count := 1
		for _, child := range nodes[index].children {
			n, err := visit(child, depth+1)
			if err != nil {
				return 0, err
			}
			count += n
			if count > 65536 {
				return 0, fmt.Errorf("SVG reference expansion exceeds limit")
			}
		}
		active[index] = false
		counts[index] = count
		return count, nil
	}
	_, err := visit(0, 0)
	return err
}

func renderSVGReferences(name, value string) ([]string, error) {
	fragment := func(value string) (string, error) {
		value = strings.TrimSpace(value)
		if len(value) < 2 || value[0] != '#' || strings.ContainsAny(value, " \t\n\r") {
			return "", fmt.Errorf("SVG rendering supports only local fragment references")
		}
		return value[1:], nil
	}
	if strings.ContainsAny(value, "\\@") || strings.Contains(value, "/*") {
		return nil, fmt.Errorf("SVG rendering does not support CSS escapes or imports")
	}
	if name == "href" {
		ref, err := fragment(value)
		return []string{ref}, err
	}
	var refs []string
	// CSS function names are ASCII-insensitive. Keep byte offsets unchanged
	// for Unicode IDs and text elsewhere in the attribute.
	lower := []byte(value)
	for i, c := range lower {
		if c >= 'A' && c <= 'Z' {
			lower[i] = c + ('a' - 'A')
		}
	}
	for {
		start := bytes.Index(lower, []byte("url("))
		if start < 0 {
			break
		}
		if len(refs) == maxRenderSVGReferences {
			return nil, fmt.Errorf("SVG reference count exceeds limit")
		}
		value = value[start+3:]
		lower = lower[start+3:]
		end := strings.IndexByte(value, ')')
		if end < 0 {
			return nil, fmt.Errorf("invalid SVG resource reference")
		}
		target := strings.TrimSpace(value[1:end])
		if len(target) >= 2 && (target[0] == '\'' || target[0] == '"') && target[len(target)-1] == target[0] {
			target = target[1 : len(target)-1]
		}
		ref, err := fragment(target)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
		value = value[end+1:]
		lower = lower[end+1:]
	}
	return refs, nil
}
