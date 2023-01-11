package sandbox

import (
	"fmt"
	"strings"
)

type opType uint8

const (
	Normal opType = iota
	Start
	Final
)

type vertex struct {
	node     *Operation
	Decision string
	Type     opType
	Not      bool
}

type edge struct {
	Src *vertex
	Dst *vertex
}

type OpGraph struct {
	vertices  map[*Operation]*vertex
	edges     []*edge
	toProcess Stack[*Operation]
	sb        *Sandbox
}

func NewOpGraph(sb *Sandbox) *OpGraph {
	return &OpGraph{
		vertices: make(map[*Operation]*vertex),
		edges:    make([]*edge, 0),
		sb:       sb,
	}
}

func (g *OpGraph) AddEdge(src *Operation, dst *Operation) {
	if _, ok := g.vertices[src]; !ok {
		g.vertices[src] = &vertex{
			node: src,
			Type: Normal,
		}
	}
	if _, ok := g.vertices[dst]; !ok {
		g.vertices[dst] = &vertex{
			node: dst,
			Type: Normal,
		}
	}
	g.edges = append(g.edges, &edge{
		Src: g.vertices[src],
		Dst: g.vertices[dst],
	})
}

// add vertex to graph
func (g *OpGraph) AddVertex(o *Operation, typ opType) {
	if _, ok := g.vertices[o]; !ok {
		g.vertices[o] = &vertex{
			node: o,
			Type: typ,
		}
	}
}

// remove vertex and all edges from graph
func (g *OpGraph) RemoveVertex(o *Operation) {
	for i, e := range g.edges {
		if e.Src == g.vertices[o] || e.Dst == g.vertices[o] {
			g.edges = append(g.edges[:i], g.edges[i+1:]...)
		}
	}
	delete(g.vertices, o)
}

// remove edge from graph
func (g *OpGraph) RemoveEdge(src *Operation, dst *Operation) {
	for i, e := range g.edges {
		if e.Src == g.vertices[src] && e.Dst == g.vertices[dst] {
			g.edges = append(g.edges[:i], g.edges[i+1:]...)
			return
		}
	}
}

func (g *OpGraph) Walk(start *Operation, f func(*Operation)) {
	visited := make(map[*Operation]bool)
	g.walk(start, visited, f)
}

func (g *OpGraph) walk(start *Operation, visited map[*Operation]bool, f func(*Operation)) {
	if visited[start] {
		return
	}
	visited[start] = true
	f(start)
	for _, e := range g.edges {
		if e.Src == g.vertices[start] {
			g.walk(e.Dst.node, visited, f)
		}
	}
}

// DFS to find all paths
func (g *OpGraph) DFS(start *Operation) [][]*Operation {
	visited := make(map[*Operation]bool)
	paths := make([][]*Operation, 0)
	g.dfs(start, visited, &paths, make([]*Operation, 0))
	return paths
}

func (g *OpGraph) dfs(start *Operation, visited map[*Operation]bool, paths *[][]*Operation, path []*Operation) {
	if visited[start] {
		return
	}
	visited[start] = true
	path = append(path, start)
	if g.vertices[start].Type == Final {
		*paths = append(*paths, path)
		return
	}
	for _, e := range g.edges {
		if e.Src == g.vertices[start] {
			g.dfs(e.Dst.node, visited, paths, path)
		}
	}
}

// // DFS to find all paths
// func (g *OpGraph) DFS(start, end *Operation) [][]*Operation {
// 	visited := make(map[*Operation]bool)
// 	paths := make([][]*Operation, 0)
// 	g.dfs(start, end, visited, &paths, make([]*Operation, 0))
// 	return paths
// }

// func (g *OpGraph) dfs(start, end *Operation, visited map[*Operation]bool, paths *[][]*Operation, path []*Operation) {
// 	if visited[start] {
// 		return
// 	}
// 	visited[start] = true
// 	path = append(path, start)
// 	if start == end {
// 		*paths = append(*paths, path)
// 		return
// 	}
// 	for _, e := range g.edges {
// 		if e.Src == g.vertices[start] {
// 			g.dfs(e.Dst.node, end, visited, paths, path)
// 		}
// 	}
// }

func (sb *Sandbox) CreateOperationGraph(node, defaultNode *Operation) (*OpGraph, error) {

	if node.Node.IsTerminal() {
		return nil, fmt.Errorf("cannot create graph from terminal node")
	} else if defaultNode.Node.IsNonTerminal() {
		return nil, fmt.Errorf("cannot create graph from non-terminal default node")
	} else if node.parsed {
		return nil, fmt.Errorf("cannot create graph from already parsed node")
	}

	g := &OpGraph{
		vertices: make(map[*Operation]*vertex),
		edges:    make([]*edge, 0),
		sb:       sb,
	}

	g.toProcess.Push(nil)  // parent
	g.toProcess.Push(node) // current

	for !g.toProcess.IsEmpty() {
		current_node, ok := g.toProcess.Pop()
		if !ok {
			return nil, fmt.Errorf("failed to pop current_node from stack")
		}
		parent_node, ok := g.toProcess.Pop()
		if !ok {
			return nil, fmt.Errorf("failed to pop parent_node from stack")
		}

		current_node.Type = Normal
		if parent_node == nil {
			g.AddVertex(current_node, Start)
		} else {
			g.AddVertex(current_node, Normal)
		}

		if !current_node.Node.IsTerminal() {
			if TerminalNode(defaultNode.Node).IsDeny() {
				switch {
				case current_node.IsNonTerminalDeny(): // In case of non-terminal match and deny as unmatch, add match to path.
					g.AddToPath(current_node)
				case current_node.IsNonTerminalAllow(): // In case of non-terminal match and allow as unmatch, do a not (reverse), end match path and add unmatch to parent path.
					g.MarkNot(current_node)
					g.EndPath(current_node)
					g.AddToParentPath(current_node, parent_node)
				case current_node.IsNonTerminalNonTerminal(): // In case of non-terminals, add match to path and unmatch to parent path.
					g.AddToPath(current_node)
					g.AddToParentPath(current_node, parent_node)
				case current_node.IsAllowNonTerminal(): // In case of allow as match and non-terminal unmatch, end path and add unmatch to parent path.
					g.EndPath(current_node)
					g.AddToParentPath(current_node, parent_node)
				case current_node.IsDenyNonTerminal(): // In case of deny as match and non-terminal unmatch, do a not (reverse), and add match to path.
					g.MarkNot(current_node)
					g.AddToPath(current_node)
				case current_node.IsDenyAllow(): // In case of deny as match and allow as unmatch, do a not (reverse), and end match path (completely).
					g.MarkNot(current_node)
					g.EndPath(current_node)
				case current_node.IsAllowDeny(): // In case of allow as match and deny as unmatch, end match path (completely).
					g.EndPath(current_node)
				}
			} else { // allow
				switch {
				case current_node.IsNonTerminalDeny(): // In case of non-terminal match and deny as unmatch, do a not (reverse), end match path and add unmatch to parent path.
					g.MarkNot(current_node)
					g.EndPath(current_node)
					g.AddToParentPath(current_node, parent_node)
				case current_node.IsNonTerminalAllow(): // In case of non-terminal match and allow as unmatch, add match to path.
					g.AddToPath(current_node)
				case current_node.IsNonTerminalNonTerminal(): // In case of non-terminals, add match to path and unmatch to parent path.
					g.AddToPath(current_node)
					g.AddToParentPath(current_node, parent_node)
				case current_node.IsAllowNonTerminal(): // In case of allow as match and non-terminal unmatch, do a not (reverse), and add match to path.
					g.MarkNot(current_node)
					g.AddToPath(current_node)
				case current_node.IsDenyNonTerminal(): // In case of deny as match and non-terminal unmatch, end path and add unmatch to parent path.
					g.EndPath(current_node)
					g.AddToParentPath(current_node, parent_node)
				case current_node.IsDenyAllow(): // In case of deny as match and allow as unmatch, end match path (completely).
					g.EndPath(current_node)
				case current_node.IsAllowDeny(): // In case of allow as match and deny as unmatch, do a not (reverse), and end match path (completely).
					g.MarkNot(current_node)
					g.EndPath(current_node)
				}
			}
		}
	}

	if err := sb.ParseOperation(node); err != nil {
		return nil, fmt.Errorf("failed to parse operation node %s: %v", node.Node, err)
	}

	// TODO: clean_edges_in_operation_node_graph
	// TODO: clean_nodes_in_operation_node_graph

	return g, nil
}

func (g *OpGraph) Size() int {
	if g == nil {
		return 0
	}
	return len(g.vertices)
}

func (g *OpGraph) String(start *Operation) string {
	return g.StringFrom(g.vertices[start])
}

func (g *OpGraph) StringFrom(v *vertex) string {
	if v == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(v.node.String("", 0))
	for _, e := range g.edges {
		if e.Src == v {
			sb.WriteString(g.StringFrom(e.Dst))
		}
	}
	return sb.String()
}

// print graph
// func (g *OpGraph) Print() {
// 	fmt.Println("Graph:")
// 	for _, v := range g.vertices {
// 		fmt.Printf("%s: %s", v.node.String("", 0), v.node.Node)
// 		if v.node.Node.IsTerminal() {
// 			fmt.Printf(" (terminal)")
// 		}
// 		fmt.Println()
// 		for _, e := range g.edges {
// 			if e.Src == v {
// 				fmt.Printf("  %s -> %s", e.Src.node.String("", 0), e.Dst.node.String("", 0))
// 				if e.Src.node.Node.IsTerminal() {
// 					fmt.Printf(" (terminal)")
// 				}

// 				if e.Src.Decision == "deny" {
// 					fmt.Printf(" (deny)")
// 				}

// 				if e.Src.Decision == "allow" {
// 					fmt.Printf(" (allow)")
// 				}

// 				fmt.Println()
// 			}

// 			fmt.Println()
// 		}
// 	}
// }

// func (g *Graph) Depth() int {
// 	if o == nil {
// 		return 0
// 	}
// 	if o.Match == nil && o.Unmatch == nil {
// 		return 1
// 	}
// 	lHeight := o.Match.Depth()
// 	rHeight := o.Unmatch.Depth()
// 	if lHeight >= rHeight {
// 		return lHeight + 1
// 	} else {
// 		return rHeight + 1
// 	}
// }

func (g *OpGraph) AddToPath(o *Operation) {
	if !g.sb.OpNodes[o.MatchOffset].parsed {
		g.AddEdge(o, g.sb.OpNodes[o.MatchOffset])
		g.toProcess.Push(o, g.sb.OpNodes[o.MatchOffset])
	}
}
func (g *OpGraph) AddToParentPath(o, parent *Operation) {
	if !g.sb.OpNodes[o.UnmatchOffset].parsed {
		g.AddEdge(parent, g.sb.OpNodes[o.UnmatchOffset])
		g.toProcess.Push(parent, g.sb.OpNodes[o.UnmatchOffset])
	}
}

func (g *OpGraph) EndPath(o *Operation) {
	g.vertices[o].Decision = TerminalNode(o.Match).Decision()
	g.vertices[o].Type = Final
}

func (g *OpGraph) MarkNot(o *Operation) {
	g.vertices[o].Type = Final
	// *node.Match, *node.Unmatch = *node.Unmatch, *node.Match // TODO: probably shouldn't flip this incase other profiles use it
	// node.MatchOffset, node.UnmatchOffset = node.UnmatchOffset, node.MatchOffset
}
