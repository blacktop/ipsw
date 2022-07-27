package sandbox

import (
	"errors"
	"fmt"
	"strings"
)

// CREDIT: https://github.com/wolever/nfa2regex

// nfaNodeName and nfaEdgeValue are type aliases for node name values and edge values.
type nfaNodeName = string
type nfaEdgeValue = string

// NFA defines a non-deterministic finite state automata specifically for use with the nfa2regex package.
type NFA struct {
	Nodes map[nfaNodeName](*NFANode)
	Edges [](*NFAEdge)
}

// NFAEdge defines the edge between two nodes in the NFA.
type NFAEdge struct {
	SrcNode *NFANode
	DstNode *NFANode
	Value   string
}

// NFANode defines a node in the NFA.
type NFANode struct {
	Name       nfaNodeName
	IsInitial  bool
	IsTerminal bool
}

// NewNFA creates a new NFA.
func NewNFA() *NFA {
	return &NFA{
		Nodes: map[nfaNodeName]*NFANode{},
		Edges: []*NFAEdge{},
	}
}

// Adds an edge between nodes ``srcName`` and ``dstName`` with ``value`` to the NFA.
func (nfa *NFA) AddEdge(srcName nfaNodeName, dstName nfaNodeName, value nfaEdgeValue) {
	srcNode := nfa.GetOrCreateNode(srcName)
	dstNode := nfa.GetOrCreateNode(dstName)
	nfa.Edges = append(nfa.Edges, &NFAEdge{
		SrcNode: srcNode,
		DstNode: dstNode,
		Value:   value,
	})
}

// Replaces a node in the NFA without mutating any of the underlying data structures.
func (nfa *NFA) ReplaceNode(name nfaNodeName, newNode *NFANode) {
	newEdges := make([](*NFAEdge), 0, len(nfa.Edges))
	oldNode := nfa.Nodes[name]
	nfa.Nodes[name] = newNode
	for _, edge := range nfa.Edges {
		if edge.SrcNode == oldNode {
			edge = &NFAEdge{
				SrcNode: newNode,
				DstNode: edge.DstNode,
				Value:   edge.Value,
			}
		}
		if edge.DstNode == oldNode {
			edge = &NFAEdge{
				SrcNode: edge.SrcNode,
				DstNode: newNode,
				Value:   edge.Value,
			}
		}
		newEdges = append(newEdges, edge)
	}
	nfa.Edges = newEdges
}

// RemoveNode removes a node and all associated edges from the NFA.
func (nfa *NFA) RemoveNode(nodeName nfaNodeName) {
	node := nfa.Nodes[nodeName]
	delete(nfa.Nodes, nodeName)
	newEdges := make([](*NFAEdge), 0, len(nfa.Edges))
	for _, edge := range nfa.Edges {
		if edge.SrcNode == node || edge.DstNode == node {
			continue
		}
		newEdges = append(newEdges, edge)
	}
	nfa.Edges = newEdges
}

// EdgesIn returns a list of edges into ``nodeName`` (ie, where edge.DstNode == nodeName).
func (nfa *NFA) EdgesIn(nodeName nfaNodeName) [](*NFAEdge) {
	node := nfa.Nodes[nodeName]
	res := [](*NFAEdge){}
	for _, edge := range nfa.Edges {
		if edge.DstNode == node {
			res = append(res, edge)
		}
	}
	return res
}

// EdgesOut a list of edges out from ``nodeName`` (ie, where edge.SrcNode == nodeName)
func (nfa *NFA) EdgesOut(nodeName nfaNodeName) [](*NFAEdge) {
	node := nfa.Nodes[nodeName]
	res := [](*NFAEdge){}
	for _, edge := range nfa.Edges {
		if edge.SrcNode == node {
			res = append(res, edge)
		}
	}
	return res
}

// GetOrCreateNode gets node ``name``, or creates if it does not exist.
func (nfa *NFA) GetOrCreateNode(name nfaNodeName) *NFANode {
	node := nfa.Nodes[name]
	if node == nil {
		node = &NFANode{
			Name:       name,
			IsInitial:  false,
			IsTerminal: false,
		}
		nfa.Nodes[name] = node
	}
	return node
}

// ShallowCopy creates a shallow copy of the NFA.
func (nfa *NFA) ShallowCopy() *NFA {
	res := &NFA{
		Nodes: map[nfaNodeName]*NFANode{},
		Edges: make([]*NFAEdge, len(nfa.Edges)),
	}
	for key, val := range nfa.Nodes {
		res.Nodes[key] = val
	}
	copy(res.Edges, nfa.Edges)
	return res
}

// Match determins whether `nfa`` accepts `input`
func (nfa *NFA) Match(input string) bool {
	activeNodes := [](*NFANode){}
	for _, node := range nfa.Nodes {
		if node.IsInitial {
			activeNodes = append(activeNodes, node)
		}
	}

	for _, chRune := range input {
		ch := string(chRune)
		newActiveNodes := [](*NFANode){}
		for _, activeNode := range activeNodes {
			for _, outEdge := range nfa.EdgesOut(activeNode.Name) {
				if outEdge.Value == ch {
					newActiveNodes = append(newActiveNodes, outEdge.DstNode)
				}
			}
		}

		activeNodes = newActiveNodes
	}

	for _, node := range activeNodes {
		if node.IsTerminal {
			return true
		}
	}

	return false
}

func (nfa *NFA) ToRegex() (string, error) {

	if nfa == nil {
		return "", errors.New("NFA must be non-nil")
	}

	nfa = nfa.ShallowCopy()

	// 1. Create single initial and terminal nodes with empty transitions to
	initialNode := nfa.GetOrCreateNode("__initial__")
	terminalNode := nfa.GetOrCreateNode("__terminal__")
	nfaHasInitial := false
	nfaHasTerminal := false
	for _, node := range nfa.Nodes {
		if node.IsInitial {
			nfaHasInitial = true
			nfa.AddEdge(initialNode.Name, node.Name, "")
			nfa.ReplaceNode(node.Name, &NFANode{
				Name:       node.Name,
				IsInitial:  false,
				IsTerminal: false,
			})
		}
		if node.IsTerminal {
			nfaHasTerminal = true
			nfa.AddEdge(node.Name, terminalNode.Name, "")
			nfa.ReplaceNode(node.Name, &NFANode{
				Name:       node.Name,
				IsInitial:  false,
				IsTerminal: false,
			})
		}
	}
	initialNode.IsInitial = true
	terminalNode.IsTerminal = true

	if !nfaHasInitial {
		return "", errors.New("NFA has no initial node(s)")
	}

	if !nfaHasTerminal {
		return "", errors.New("NFA has no terminal node(s)")
	}

	// 2. Iteritively remove nodes which aren't the initial or terminal node
	for len(nfa.Nodes) > 2 {
		for _, node := range nfa.Nodes {
			if node == initialNode || node == terminalNode {
				continue
			}

			// Collect any loops (ie, where the node references its self) so they
			// can be converted to kleen star in the middle of new edges
			kleenStarValues := []string{}
			inEdges := nfa.EdgesIn(node.Name)
			for _, inEdge := range inEdges {
				if inEdge.SrcNode == inEdge.DstNode {
					kleenStarValues = append(kleenStarValues, inEdge.Value)
				}
			}

			kleenStarMiddle := addKleenStar(orJoin(kleenStarValues), len(kleenStarValues) > 1)
			for _, inEdge := range inEdges {
				if inEdge.SrcNode == inEdge.DstNode {
					continue
				}
				for _, outEdge := range nfa.EdgesOut(node.Name) {
					if outEdge.SrcNode == outEdge.DstNode {
						continue
					}

					nfa.AddEdge(
						inEdge.SrcNode.Name,
						outEdge.DstNode.Name,
						inEdge.Value+kleenStarMiddle+outEdge.Value,
					)
				}
			}

			nfa.RemoveNode(node.Name)

		}
	}

	// 3. Produce the regular expression
	hasInitialTerminalEdge := false
	res := make([]string, 0, len(nfa.Edges))
	for _, edge := range nfa.Edges {
		if edge.SrcNode.IsInitial && edge.DstNode.IsTerminal {
			hasInitialTerminalEdge = true
		}
		res = append(res, edge.Value)
	}
	if !hasInitialTerminalEdge {
		return "", errors.New("NFA has no path between initial and terminal node(s)")
	}

	return orJoin(res), nil
}

// ToDot generates a graphviz dot file from a NFA.
func ToDot(nfa *NFA) string {
	res := make([]string, 0, len(nfa.Edges)+5)

	res = append(res, "\trankdir = LR;")

	for _, edge := range nfa.Edges {
		label := edge.Value
		if len(label) == 0 {
			label = "''"
		}
		res = append(res, fmt.Sprintf(
			"\t%q -> %q [label=%q];",
			edge.SrcNode.Name,
			edge.DstNode.Name,
			label,
		))
	}

	for _, node := range nfa.Nodes {
		if node.IsInitial {
			res = append(res, fmt.Sprintf("\t%q [shape=point];", node.Name+"__initial"))
			res = append(res, fmt.Sprintf("\t%q -> %q;", node.Name+"__initial", node.Name))
		}
		if node.IsTerminal {
			res = append(res, fmt.Sprintf("\t%q [peripheries=2];", node.Name))
		}
	}

	return "digraph g {\n" + strings.Join(res, "\n") + "\n}\n"
}

// addKleenStar a kleen star to ``s``:
//   addKleenStar("") -> ""
//   addKleenStar("a") -> "a*"
//   addKleenStar("abc") -> "(abc)*"
//   addKleenStar("(abc|123)", true) -> "(abc|123)*"
func addKleenStar(s string, noWrap ...bool) string {
	switch len(s) {
	case 0:
		return ""
	case 1:
		return s + "*"
	default:
		if len(noWrap) > 0 && noWrap[0] {
			return s + "*"
		}
		return fmt.Sprintf("(%s)*", s)
	}
}

// orJoin joins a series of strings together in an "or" statement, ignoring
// empty strings:
//   orJoin({"a"}) -> "a"
//   orJoin({"a", "b"}) -> "(a|b)"
//   orJoin({"", "a", "b"}) -> "(a|b)"
func orJoin(inputStrs []string) string {
	strs := make([]string, 0, len(inputStrs))
	for _, s := range inputStrs {
		if len(s) > 0 {
			strs = append(strs, s)
		}
	}

	switch len(strs) {
	case 0:
		return ""
	case 1:
		return strs[0]
	default:
		return "(" + strings.Join(strs, "|") + ")"
	}
}
