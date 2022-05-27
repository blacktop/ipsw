package sandbox

// nfaNodeName and nfaEdgeValue are type aliases for node name values and edge
// values.
type nfaNodeName = string
type nfaEdgeValue = string

// NFA defines a non-deterministic finite state automata specifically for use
// with the nfa2regex package.
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

// Replaces a node in the NFA without mutating any of the underlying data
// structures.
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

// EdgesIn returns a list of edges into ``nodeName`` (ie, where edge.DstNode ==
// nodeName).
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

// NewNFA creates a new NFA.
func NewNFA() *NFA {
	return &NFA{
		Nodes: map[nfaNodeName]*NFANode{},
		Edges: []*NFAEdge{},
	}
}
