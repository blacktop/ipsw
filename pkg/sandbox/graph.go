package sandbox

type OpGraph struct {
	List     []OperationNode
	Decision string
	Type     []string
	Not      bool

	nodesToProcess []*Operation
	processedNodes map[OperationNode]*Operation
}

func NewOpGraph() *OpGraph {
	return &OpGraph{}
}

func (og *OpGraph) BuildGraph(node, defaultNode *Operation) error {

	og.nodesToProcess = []*Operation{nil, node}

	for len(og.nodesToProcess) > 0 {
		parent_node, current_node := og.nodesToProcess[0], og.nodesToProcess[1]
		if defaultNode.Node.IsTerminal() {
			switch {
			case current_node.IsNonTerminalDeny(): // In case of non-terminal match and deny as unmatch, add match to path.
				og.AddToPath(current_node, parent_node)
			case current_node.IsNonTerminalAllow(): // In case of non-terminal match and allow as unmatch, do a not (reverse), end match path and add unmatch to parent path.
				og.MarkNot(current_node, parent_node)
				og.EndPath(current_node, parent_node)
				og.AddToParentPath(current_node, parent_node)
			case current_node.IsNonTerminalNonTerminal(): // In case of non-terminals, add match to path and unmatch to parent path.
				og.AddToPath(current_node, parent_node)
				og.AddToParentPath(current_node, parent_node)
			case current_node.IsAllowNonTerminal(): // In case of allow as match and non-terminal unmatch, end path and add unmatch to parent path.
				og.EndPath(current_node, parent_node)
				og.AddToParentPath(current_node, parent_node)
			case current_node.IsDenyNonTerminal(): // In case of deny as match and non-terminal unmatch, do a not (reverse), and add match to path.
				og.MarkNot(current_node, parent_node)
				og.AddToPath(current_node, parent_node)
			case current_node.IsDenyAllow(): // In case of deny as match and allow as unmatch, do a not (reverse), and end match path (completely).
				og.MarkNot(current_node, parent_node)
				og.EndPath(current_node, parent_node)
			case current_node.IsAllowDeny(): // In case of allow as match and deny as unmatch, end match path (completely).
				og.EndPath(current_node, parent_node)
			}
		} else {
			switch {
			case current_node.IsNonTerminalDeny(): // In case of non-terminal match and deny as unmatch, do a not (reverse), end match path and add unmatch to parent path.
				og.MarkNot(current_node, parent_node)
				og.EndPath(current_node, parent_node)
				og.AddToParentPath(current_node, parent_node)
			case current_node.IsNonTerminalAllow(): // In case of non-terminal match and allow as unmatch, add match to path.
				og.AddToPath(current_node, parent_node)
			case current_node.IsNonTerminalNonTerminal(): // In case of non-terminals, add match to path and unmatch to parent path.
				og.AddToPath(current_node, parent_node)
				og.AddToParentPath(current_node, parent_node)
			case current_node.IsAllowNonTerminal(): // In case of allow as match and non-terminal unmatch, do a not (reverse), and add match to path.
				og.MarkNot(current_node, parent_node)
				og.AddToPath(current_node, parent_node)
			case current_node.IsDenyNonTerminal(): // In case of deny as match and non-terminal unmatch, end path and add unmatch to parent path.
				og.EndPath(current_node, parent_node)
				og.AddToParentPath(current_node, parent_node)
			case current_node.IsDenyAllow(): // In case of deny as match and allow as unmatch, end match path (completely).
				og.EndPath(current_node, parent_node)
			case current_node.IsAllowDeny(): // In case of allow as match and deny as unmatch, do a not (reverse), and end match path (completely).
				og.MarkNot(current_node, parent_node)
				og.EndPath(current_node, parent_node)
			}
		}
	}

	og.processedNodes[node.Node] = node

	// TODO: clean_edges_in_operation_node_graph
	// TODO: clean_nodes_in_operation_node_graph

	return nil
}

func (og *OpGraph) MarkNot(node, parent *Operation) error {
	return nil
}

func (og *OpGraph) EndPath(node, parent *Operation) error {
	return nil
}

func (og *OpGraph) AddToPath(node, parent *Operation) error {
	return nil
}

func (og *OpGraph) AddToParentPath(node, parent *Operation) error {
	return nil
}
