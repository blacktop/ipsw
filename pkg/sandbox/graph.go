package sandbox

import "fmt"

func (sb *Sandbox) CreateOperationGraph(node, defaultNode *Operation) error {

	var nodesToProcess Stack[*Operation]

	nodesToProcess.Push(nil)
	nodesToProcess.Push(node)

	for !nodesToProcess.IsEmpty() {
		parent_node, ok := nodesToProcess.Pop()
		if !ok {
			return fmt.Errorf("failed to pop parent_node from stack")
		}
		current_node, _ := nodesToProcess.Pop()
		if !ok {
			return fmt.Errorf("failed to pop current_node from stack")
		}

		current_node.Type = Normal
		if parent_node == nil {
			current_node.Type = Start
		} else {
			if err := sb.ParseOperation(parent_node); err != nil {
				return fmt.Errorf("failed to parse operation node %#x: %v", current_node.Node, err)
			}
		}

		if err := sb.ParseOperation(current_node); err != nil {
			return fmt.Errorf("failed to parse operation node %#x: %v", current_node.Node, err)
		}

		if !current_node.Terminal {
			if !defaultNode.Allow { // deny
				switch {
				case current_node.IsNonTerminalDeny(): // In case of non-terminal match and deny as unmatch, add match to path.
					if !current_node.Match.parsed {
						current_node.List = append(current_node.List, current_node.Match)
						nodesToProcess.Push(current_node, current_node.Match)
					}
				case current_node.IsNonTerminalAllow(): // In case of non-terminal match and allow as unmatch, do a not (reverse), end match path and add unmatch to parent path.
					current_node.not = true
					current_node.Type = Final
					if !current_node.Unmatch.parsed {
						if parent_node != nil {
							parent_node.List = append(parent_node.List, current_node.Unmatch)
						}
						nodesToProcess.Push(parent_node, current_node.Unmatch)
					}
				case current_node.IsNonTerminalNonTerminal(): // In case of non-terminals, add match to path and unmatch to parent path.
					if !current_node.Match.parsed {
						current_node.List = append(current_node.List, current_node.Match)
						nodesToProcess.Push(current_node, current_node.Match)
					}
					if !current_node.Unmatch.parsed {
						if parent_node != nil {
							parent_node.List = append(parent_node.List, current_node.Unmatch)
						}
						nodesToProcess.Push(parent_node, current_node.Unmatch)
					}
				case current_node.IsAllowNonTerminal(): // In case of allow as match and non-terminal unmatch, end path and add unmatch to parent path.
					current_node.Type = Final
					if !current_node.Unmatch.parsed {
						if parent_node != nil {
							parent_node.List = append(parent_node.List, current_node.Unmatch)
						}
						nodesToProcess.Push(parent_node, current_node.Unmatch)
					}
				case current_node.IsDenyNonTerminal(): // In case of deny as match and non-terminal unmatch, do a not (reverse), and add match to path.
					current_node.not = true
					if !current_node.Match.parsed {
						current_node.List = append(current_node.List, current_node.Match)
						nodesToProcess.Push(current_node, current_node.Match)
					}
				case current_node.IsDenyAllow(): // In case of deny as match and allow as unmatch, do a not (reverse), and end match path (completely).
					current_node.not = true
					current_node.Type = Final
				case current_node.IsAllowDeny(): // In case of allow as match and deny as unmatch, end match path (completely).
					current_node.Type = Final
				}
			} else { // allow
				switch {
				case current_node.IsNonTerminalDeny(): // In case of non-terminal match and deny as unmatch, do a not (reverse), end match path and add unmatch to parent path.
					current_node.not = true
					current_node.Type = Final
					if !current_node.Unmatch.parsed {
						if parent_node != nil {
							parent_node.List = append(parent_node.List, current_node.Unmatch)
						}
						nodesToProcess.Push(parent_node, current_node.Unmatch)
					}
				case current_node.IsNonTerminalAllow(): // In case of non-terminal match and allow as unmatch, add match to path.
					if !current_node.Match.parsed {
						current_node.List = append(current_node.List, current_node.Match)
						nodesToProcess.Push(current_node, current_node.Match)
					}
				case current_node.IsNonTerminalNonTerminal(): // In case of non-terminals, add match to path and unmatch to parent path.
					if !current_node.Match.parsed {
						current_node.List = append(current_node.List, current_node.Match)
						nodesToProcess.Push(current_node, current_node.Match)
					}
					if !current_node.Unmatch.parsed {
						if parent_node != nil {
							parent_node.List = append(parent_node.List, current_node.Unmatch)
						}
						nodesToProcess.Push(parent_node, current_node.Unmatch)
					}
				case current_node.IsAllowNonTerminal(): // In case of allow as match and non-terminal unmatch, do a not (reverse), and add match to path.
					current_node.not = true
					if !current_node.Match.parsed {
						current_node.List = append(current_node.List, current_node.Match)
						nodesToProcess.Push(current_node, current_node.Match)
					}
				case current_node.IsDenyNonTerminal(): // In case of deny as match and non-terminal unmatch, end path and add unmatch to parent path.
					current_node.Type = Final
					if !current_node.Unmatch.parsed {
						if parent_node != nil {
							parent_node.List = append(parent_node.List, current_node.Unmatch)
						}
						nodesToProcess.Push(parent_node, current_node.Unmatch)
					}
				case current_node.IsDenyAllow(): // In case of deny as match and allow as unmatch, end match path (completely).
					current_node.Type = Final
				case current_node.IsAllowDeny(): // In case of allow as match and deny as unmatch, do a not (reverse), and end match path (completely).
					current_node.not = true
					current_node.Type = Final
				}
			}
		}
	}

	// TODO: clean_edges_in_operation_node_graph
	// TODO: clean_nodes_in_operation_node_graph

	return nil
}

func MarkNot(node *Operation) {
	node.not = true
	// *node.Match, *node.Unmatch = *node.Unmatch, *node.Match // TODO: probably shouldn't flip this incase other profiles use it
	// node.MatchOffset, node.UnmatchOffset = node.UnmatchOffset, node.MatchOffset
}
