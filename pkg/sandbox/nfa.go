package sandbox

import (
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
)

// CREDIT: based on https://github.com/wolever/nfa2regex TODO: turn this into a fork (maybe PR)

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

// Adds an edge between nodes “srcName“ and “dstName“ with “value“ to the NFA.
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

// EdgesIn returns a list of edges into “nodeName“ (ie, where edge.DstNode == nodeName).
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

// EdgesOut a list of edges out from “nodeName“ (ie, where edge.SrcNode == nodeName)
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

func (nfa *NFA) GetEdges(src, dst *NFANode) []*NFAEdge {
	var edges []*NFAEdge
	for _, outEdge := range nfa.EdgesOut(src.Name) {
		if outEdge.DstNode == dst {
			edges = append(edges, outEdge)
		}
	}
	return edges
}

// remove edge from nfa
func (nfa *NFA) RemoveEdge(edge *NFAEdge) {
	newEdges := make([](*NFAEdge), 0, len(nfa.Edges))
	for _, e := range nfa.Edges {
		if e != edge {
			newEdges = append(newEdges, e)
		}
	}
	nfa.Edges = newEdges
}

// GetOrCreateNode gets node “name“, or creates if it does not exist.
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

// Match determins whether nfa accepts input
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

// SortedNodeNames returns a sorted list of node names in the NFA (in decending order of node name).
func (nfa *NFA) SortedNodeNames(reverse bool) []string {
	var names []string
	for name := range nfa.Nodes {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		numA, _ := strconv.Atoi(names[i])
		numB, _ := strconv.Atoi(names[j])
		if reverse {
			return numA > numB
		}
		return numA < numB

	})
	return names
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

	// nfa.OpenURL()

	// 2. remove states with one transition in and out
	for _, node := range nfa.Nodes {
		if node == initialNode || node == terminalNode {
			continue
		}
		// combine adjacent edges with onyl one transition
		if len(nfa.EdgesIn(node.Name)) == 1 && len(nfa.EdgesOut(node.Name)) == 1 {
			inEdge := nfa.EdgesIn(node.Name)[0]
			outEdge := nfa.EdgesOut(node.Name)[0]
			nfa.AddEdge(inEdge.SrcNode.Name, outEdge.DstNode.Name, (inEdge.Value + outEdge.Value))
			nfa.RemoveNode(node.Name)
			// remove states with one transition out to non-terminal "" node
		} else if len(nfa.EdgesIn(node.Name)) == 1 && len(nfa.EdgesOut(node.Name)) == 0 && !node.IsTerminal {
			inEdge := nfa.EdgesIn(node.Name)[0]
			if inEdge.Value == "" {
				nfa.RemoveNode(node.Name)
			}
		}
	}

	// nfa.OpenURL()

	// 3. remove loops
	for _, node := range nfa.Nodes {
		if node == initialNode || node == terminalNode {
			continue
		}
		inNodes := nfa.EdgesIn(node.Name)
		outNodes := nfa.EdgesOut(node.Name)
		if len(inNodes) >= 2 && len(outNodes) == 1 {
			outEdge := outNodes[0]
			if len(nfa.EdgesOut(outEdge.DstNode.Name)) == 2 { // ([0-9])*[0-9] reduction
				for _, inEdge := range inNodes {
					if outEdge.DstNode.Name == inEdge.SrcNode.Name {
						outEdge.Value += "+"
						nfa.RemoveEdge(inEdge)
						break
					}
				}
			}
		} else { // kleen star
			for _, inEdge := range inNodes {
				if inEdge.SrcNode == inEdge.DstNode {
					kleenStar := addKleenStar(inEdge.Value)
					for _, inEdge := range inNodes {
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
								inEdge.Value+kleenStar+outEdge.Value,
							)
						}
					}
					nfa.RemoveNode(node.Name)
				}
			}
		}
	}

	// 3.5. remove states with one transition in and out (AGAIN)
	for _, node := range nfa.Nodes {
		if node == initialNode || node == terminalNode {
			continue
		}
		// combine adjacent edges with onyl one transition
		if len(nfa.EdgesIn(node.Name)) == 1 && len(nfa.EdgesOut(node.Name)) == 1 {
			inEdge := nfa.EdgesIn(node.Name)[0]
			outEdge := nfa.EdgesOut(node.Name)[0]
			nfa.AddEdge(inEdge.SrcNode.Name, outEdge.DstNode.Name, (inEdge.Value + outEdge.Value))
			nfa.RemoveNode(node.Name)
			// remove states with one transition out to non-terminal "" node
		} else if len(nfa.EdgesIn(node.Name)) == 1 && len(nfa.EdgesOut(node.Name)) == 0 && !node.IsTerminal {
			inEdge := nfa.EdgesIn(node.Name)[0]
			if inEdge.Value == "" {
				nfa.RemoveNode(node.Name)
			}
		}
	}

	// nfa.OpenURL()

	walks := []string{}
	nfa.DFS(initialNode, terminalNode, func(path []*NFANode) {
		walk := nfa.GetPathFromNodes(path)
		walks = append(walks, strings.Join(walk, ""))
	})

	walks = utils.Unique(walks)

	var unifiedRegex string
	if len(walks) > 1 {
		unifiedRegex = walks[0]
		for _, edge := range walks[1:] {
			unifiedRegex = unifyStrings(unifiedRegex, edge)
		}
	} else {
		return walks[0], nil
	}

	return unifiedRegex, nil
}

func (nfa *NFA) GetPathFromNodes(nodes []*NFANode) []string {
	var nextNode *NFANode
	res := []string{}

	for idx, node := range nodes {
		var value string

		nextNode = nodes[idx+1]
		outEdges := nfa.GetEdges(node, nextNode)

		switch len(outEdges) {
		case 0:
			value = ""
		case 1:
			value = outEdges[0].Value
		case 2:
			if outEdges[0].Value != "" && outEdges[1].Value != "" {
				value = fmt.Sprintf("(%s|%s)", outEdges[0].Value, outEdges[1].Value)
			} else if outEdges[0].Value == "" || outEdges[1].Value == "" {
				if outEdges[0].DstNode == outEdges[1].DstNode {
					value = fmt.Sprintf("(%s)?", outEdges[0].Value+outEdges[1].Value)
				}
			} else {
				value = outEdges[0].Value + outEdges[1].Value
			}
		default:
			log.Fatalf("unexpected out edge count %d", len(outEdges))
		}

		res = append(res, value)
		if nextNode.IsTerminal {
			break
		}
	}

	return res
}

func (nfa *NFA) DFS(src *NFANode, dst *NFANode, visitCb func([]*NFANode)) {
	var paths []*NFANode
	visited := map[*NFANode]bool{}
	nfa.dfs(src, dst, visited, paths, visitCb)
}

func (nfa *NFA) dfs(src *NFANode, dst *NFANode, visited map[*NFANode]bool, path []*NFANode, visitCb func([]*NFANode)) {

	visited[src] = true
	path = append(path, src)

	if src == dst {
		visitCb(path)
	}

	for _, edge := range nfa.EdgesOut(src.Name) {
		if !visited[edge.DstNode] {
			nfa.dfs(edge.DstNode, dst, visited, path, visitCb)
		}
	}

	path = path[:len(path)-1] // nolint:staticcheck
	visited[src] = false
}

func unifyStrings(p1, p2 string) string {
	s1 := p1
	s2 := p2
	// get longest common prefix
	var lcps string
	for idx := 0; idx < len(s1) && idx < len(s2); idx++ {
		if s1[idx] == s2[idx] {
			lcps += string(s1[idx])
		} else {
			break
		}
	}
	if len(lcps) > 0 {
		s1 = s1[len(lcps):]
		s2 = s2[len(lcps):]
	}
	// get longest common suffix
	var lcss string
	for idx := len(s1) - 1; idx >= 0; idx-- {
		if strings.HasSuffix(s2, s1[idx:]) {
			lcss = string(s1[idx]) + lcss
		} else {
			break
		}
	}
	if len(lcss) > 0 {
		s1 = s1[:(len(s1) - len(lcss))]
		s2 = s2[:(len(s2) - len(lcss))]
	}

	if len(s1) == 0 && len(s2) == 0 {
		return lcps + lcss
	} else if len(s1) > 0 && len(s2) > 0 {
		return lcps + "(" + s1 + "|" + s2 + ")" + lcss
	}

	if len(s2) == 0 {
		s2 = s1
	}

	if strings.HasSuffix(s2, "+") {
		s2 = s2[:len(s2)-1] + "*"
	} else {
		if len(s2) > 1 {
			s2 = "(" + s2 + ")?"
		} else {
			s2 = s2 + "?"
		}
	}

	return lcps + s2 + lcss
}

// ToDot generates a graphviz dot file from a NFA.
func (nfa *NFA) ToDot() string {
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

func (nfa *NFA) OpenURL() error {
	var err error

	url := "https://edotor.net/?engine=dot#" + url.PathEscape(nfa.ToDot())

	log.Debug("Graph:")
	utils.Indent(log.Debug, 2)(url)

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return err
}

func (nfa *NFA) GetState(initialNode, terminalNode *NFANode) error {
	if err := nfa.OpenURL(); err != nil {
		return err
	}

	log.Debug("DFS WALKS:")
	walks := []string{}
	nfa.DFS(initialNode, terminalNode, func(path []*NFANode) {
		walk := nfa.GetPathFromNodes(path)
		utils.Indent(log.Debug, 2)(strings.Join(walk, ""))
		walks = append(walks, strings.Join(walk, ""))
	})

	walks = utils.Unique(walks)

	log.Debugf("LongestCommonSubstring: %s", string(LongestCommonSubstring(walks)))

	if len(walks) > 1 {
		current := walks[0]
		for _, edge := range walks[1:] {
			current = unifyStrings(current, edge)
		}
		log.Debugf("current: %s\n", current)
	}

	return nil
}

// addKleenStar a kleen star to “s“:
//
//	addKleenStar("") -> ""
//	addKleenStar("a") -> "a*"
//	addKleenStar("abc") -> "(abc)*"
//	addKleenStar("(abc|123)", true) -> "(abc|123)*"
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
//
//	orJoin({"a"}) -> "a"
//	orJoin({"a", "b"}) -> "(a|b)"
//	orJoin({"", "a", "b"}) -> "(a|b)"
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
