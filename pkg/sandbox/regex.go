package sandbox

//go:generate stringer -type=reType -output regex_string.go

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"strconv"

	n "github.com/wolever/nfa2regex"
	"github.com/yourbasic/graph"
)

type reType int

const (
	Character reType = iota
	JumpForward
	JumpBackward
	Class
	ClassExclude
	End
	Terminator
)

type reNode struct {
	// Postion int
	Next    int
	Type    reType
	Value   any
	isStart bool
	isEnd   bool
	accum   string
}

func (n reNode) String(nn *reNode) string {
	switch n.Type {
	case Character:
		fallthrough
	case Class:
		fallthrough
	case ClassExclude:
		return fmt.Sprintf("%s", n.Value)
	case JumpForward:
		if nn == nil {
			return fmt.Sprintf("[jumpforward=%d>", n.Value.(uint16))
		} else {
			return fmt.Sprintf("[jumpforward=%d{%s}>", n.Value.(uint16), nn.String(nil))
		}
	case JumpBackward:
		if nn == nil {
			return fmt.Sprintf("<jumpback=%d]", n.Value.(uint16))
		} else {
			return fmt.Sprintf("<jumpback=%d{%s}]", n.Value.(uint16), nn.String(nil))
		}
	case End:
		return "[end]"
	default:
		return fmt.Sprintf("[ERROR] unsupported regex byte type: %x", n.Type)
	}
}

type reList map[int]reNode

func (rl reList) Root() *reNode {
	for _, r := range rl {
		if r.isStart {
			return &r
		}
	}
	return nil
}

func (rl reList) String() string {
	var out string
	i := 0
	for {
		switch rl[i].Type {
		case Character:
			fallthrough
		case Class:
			fallthrough
		case ClassExclude:
			fallthrough
		case End:
			out += rl[i].String(nil)
		case JumpForward:
			fwd := rl[i].Value.(uint16)
			nn := rl[int(fwd)]
			out += rl[i].String(&nn)
		case JumpBackward:
			bck := rl[i].Value.(uint16)
			nn := rl[int(bck)]
			out += rl[i].String(&nn)
		}
		i = rl[i].Next
		if rl[i].isEnd {
			break
		}
	}
	return out
}

type Regex struct {
	Version uint32
	Length  uint16
	Data    []byte
}

func NewRegex(data []byte) (*Regex, error) {
	re := &Regex{}

	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.BigEndian, &re.Version); err != nil {
		return nil, fmt.Errorf("failed to read regex version: %v", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &re.Length); err != nil {
		return nil, fmt.Errorf("failed to read regex data length: %v", err)
	}

	re.Data = data[6:]

	return re, nil
}

func (re *Regex) String() string {
	return fmt.Sprintf("version: %d, length: %d", re.Version, re.Length)
}

func (re *Regex) Parse() (reList, error) {
	if re.Version != 3 {
		return nil, fmt.Errorf("unsupported regex version: %d", re.Version)
	}

	rlist := make(reList)

	for i := 0; i < len(re.Data); i++ {
		var rl reNode

		if i == 0 {
			rl.isStart = true
		}

		switch {
		case re.Data[i] == 0x02:
			// parse character
			rl.Next = i + 2
			rl.Type = Character
			rl.Value = string(re.Data[i+1])
			if string(re.Data[i+1]) == "." {
				rl.Value = "[.]"
			}
			rlist[i] = rl
			i++
		case re.Data[i] == 0x19:
			// parse begining of line
			rl.Next = i + 1
			rl.Type = Character
			rl.Value = "^"
			rlist[i] = rl
		case re.Data[i] == 0x29:
			// parse end of line
			rl.Next = i + 1
			rl.Type = Character
			rl.Value = "$"
			rlist[i] = rl
		case re.Data[i] == 0x09:
			// parse any character
			rl.Next = i + 1
			rl.Type = Character
			rl.Value = "."
			rlist[i] = rl
		case re.Data[i] == 0x2f:
			// parse jump forward
			rl.Next = i + 3
			rl.Type = JumpForward
			rl.Value = uint16(re.Data[i+1]) + uint16(re.Data[i+2])<<8
			rlist[i] = rl
			i += 2
		case (re.Data[i] & 0xf) == 0xa:
			// parse jump backward
			rl.Next = i + 3
			rl.Type = JumpBackward
			rl.Value = uint16(re.Data[i+1]) + uint16(re.Data[i+2])<<8
			rlist[i] = rl
			i += 2
		case (re.Data[i] & 0xf) == 0xb:
			// parse character class
			n := int(re.Data[i] >> 4)
			i++
			var values []byte
			val := "["
			for j := 0; j < n; j++ {
				values = append(values, re.Data[i+(2*j)])
				values = append(values, re.Data[i+(2*j)+1])
			}
			first := values[0]
			last := values[len(values)-1]
			if first > last {
				rl.Type = ClassExclude
				val += "^"
				for j := len(values) - 1; j > 0; j-- {
					values[j] = values[j-1]
				}
				values[0] = last
				for j := 0; j < len(values); j++ {
					if (j % 2) == 0 {
						values[j] = values[j] + 1
					} else {
						values[j] = values[j] - 1
					}
				}
			} else {
				rl.Type = Class
			}
			for j := 0; j < len(values); j += 2 {
				if values[j] < values[j+1] {
					val += string(values[j]) + "-" + string(values[j+1])
				} else {
					val += string(values[j])
				}
			}
			val += "]"
			rl.Next = i + (2 * n)
			rl.Value = val
			rlist[i-1] = rl
			i += (2 * n) - 1
		case (re.Data[i] & 0xf) == 0x5:
			// parse end
			rl.Next = i + 2
			rl.Type = End
			rl.Value = 0
			rlist[i] = rl
			i++
		default:
			return nil, fmt.Errorf("unsupported regex byte type: %x", re.Data[i])
		}
	}

	// add end node
	rlist[len(re.Data)] = reNode{
		Type:  Terminator,
		isEnd: true,
	}

	return rlist, nil
}

func (re *Regex) Graph() (*graph.Mutable, error) {
	var endNode int

	rlist, err := re.Parse()
	if err != nil {
		return nil, err
	}

	g := graph.New(int(re.Length + 1))

	i := 0
	for {
		switch rlist[i].Type {
		case Character:
			fallthrough
		case Class:
			fallthrough
		case ClassExclude:
			fallthrough
		case End:
			g.Add(i, rlist[i].Next)
		case JumpForward:
			fallthrough
		case JumpBackward:
			g.Add(i, rlist[i].Next)
			g.Add(i, int(rlist[i].Value.(uint16)))
		default:
			return nil, fmt.Errorf("unsupported regex byte type: %x", rlist[i].Type)
		}

		i = rlist[i].Next

		if rlist[i].isEnd {
			endNode = i
			break
		}
	}

	// fmt.Println(g)

	// needsPlus := func(v int, s string, cycles [][]int) bool {
	// 	if len(s) == 0 {
	// 		return false
	// 	} else if s[len(s)-1] == '^' {
	// 		return false
	// 	} else if s[len(s)-1] == '$' {
	// 		return false
	// 	} else if len(cycles) == 0 {
	// 		return false
	// 	}
	// 	for _, cc := range cycles {
	// 		if cc[0] == v {
	// 			return true
	// 		}
	// 	}
	// 	return false
	// }

	// p, d := graph.ShortestPath(g, 0, endNode)
	// fmt.Printf("ShortestPath:\n\tp: %v, d: %v\n", p, d)
	// for _, x := range p {
	// 	fmt.Printf("%d) (%s)\t%v\n", x, rlist[x].Type, rlist[x].Value)
	// }

	// var cycles [][]int
	// if !graph.Acyclic(g) {
	// 	for _, cs := range graph.StrongComponents(g) {
	// 		if len(cs) > 1 {
	// 			sort.Ints(cs)
	// 			cycles = append(cycles, cs)
	// 		}
	// 	}
	// }

	var out string
	var res []string

	for v := 0; v < g.Order(); v++ {
		// Visiting edge (v, w) of cost c.
		g.Visit(v, func(w int, c int64) (skip bool) {
			fmt.Printf("%03d -> %03d => (%s)\t%v\n", v, w, rlist[v].Type, rlist[v].Value)
			if rlist[v].Type == Character {
				out += rlist[v].Value.(string)
			} else if rlist[v].Type == Class || rlist[v].Type == ClassExclude {
				out += rlist[v].Value.(string)
				out += "+"
			} else if rlist[v].Type == JumpBackward || rlist[v].Type == JumpForward {
				if len(out) > 0 {
					rl := rlist[v]
					rl.accum = out
					res = append(res, out)
					out = ""
					rlist[v] = rl
				}
			}
			if rlist[w].Type == End {
				if len(out) > 0 {
					rl := rlist[v]
					rl.accum = out
					res = append(res, out)
					out = ""
					rlist[v] = rl
				}
				// res = append(res, out)
				// if reflect.TypeOf(rlist[v].Value).Kind() == reflect.String {
				// 	out = strings.TrimSuffix(out, rlist[v].Value.(string))
				// }
			}
			if w == endNode {
				fmt.Printf("%03d -> 🛑  => (%s)\t%v\n", w, rlist[w].Type, rlist[w].Value)
			}
			return
		})
	}

	for _, r := range res {
		fmt.Printf("\t%s\n", r)
	}

	dist := make([]int, g.Order())
	graph.BFS(graph.Sort(g), 0, func(v, w int, _ int64) {
		fmt.Printf("%03d -> %03d => (%s)\t%v\n", v, w, rlist[v].Type, rlist[v].Value)
		dist[w] = dist[v] + 1
	})
	fmt.Println("dist:", dist)

	return g, nil
}

func (re *Regex) NFA() (*n.NFA, error) {
	rlist, err := re.Parse()
	if err != nil {
		return nil, err
	}

	nfa := n.NewNFA()

	i := 0
	for {
		switch rlist[i].Type {
		case Character:
			fallthrough
		case Class:
			fallthrough
		case ClassExclude:
			nfa.AddEdge(strconv.Itoa(i), strconv.Itoa(rlist[i].Next), rlist[i].Value.(string))
		case End:
			// nfa.AddEdge(strconv.Itoa(i), strconv.Itoa(rlist[i].Next), "")
			nfa.Nodes[strconv.Itoa(i)].IsTerminal = true
		case JumpForward:
			fallthrough
		case JumpBackward:
			nfa.AddEdge(strconv.Itoa(i), strconv.Itoa(rlist[i].Next), "")
			nfa.AddEdge(strconv.Itoa(i), strconv.Itoa(int(rlist[i].Value.(uint16))), "")
		default:
			return nil, fmt.Errorf("unsupported regex byte type: %x", rlist[i].Type)
		}

		i = rlist[i].Next

		if rlist[i].isEnd {
			// nfa.Nodes[strconv.Itoa(i)].IsTerminal = true
			break
		}
	}

	nfa.Nodes[strconv.Itoa(0)].IsInitial = true

	// rstr, err := n.ToRegexWithConfig(nfa, n.ToRegexConfig{
	// 	StepCallback: func(nfa *n.NFA, stepName string) error {
	// 		fmt.Printf("%s\n", stepName)
	// 		return nil
	// 	},
	// })
	// if err != nil {
	// 	return nil, err
	// }
	// fmt.Println("NFA:", rstr)
	// ioutil.WriteFile("regex", []byte(rstr), 0644)

	fmt.Println("Graph:")
	fmt.Println("https://dreampuf.github.io/GraphvizOnline/#" + url.PathEscape(n.ToDot(nfa)))

	f, err := os.Create("nfa.svg")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := n.ToSVG(nfa, f); err != nil {
		return nil, err
	}

	return nfa, nil
}

// func (re *Regex) Graph() (*Graph, error) {
// 	rlist, err := re.Parse()
// 	if err != nil {
// 		return nil, err
// 	}

// 	g := NewDirectedGraph()

// 	i := 0
// 	for {
// 		switch rlist[i].Type {
// 		case Character:
// 			fallthrough
// 		case Class:
// 			fallthrough
// 		case ClassExclude:
// 			fallthrough
// 		case End:
// 			g.AddVertex(i)
// 			g.AddVertex(rlist[i].Next)
// 			g.AddEdge(i, rlist[i].Next)
// 			i = rlist[i].Next
// 		case JumpForward:
// 			fallthrough
// 		case JumpBackward:
// 			g.AddVertex(i)
// 			g.AddVertex(rlist[i].Next)
// 			g.AddEdge(i, rlist[i].Next)
// 			g.AddVertex(int(rlist[i].Value.(uint16)))
// 			g.AddEdge(i, int(rlist[i].Value.(uint16)))
// 			i = int(rlist[i].Value.(uint16))
// 		default:
// 			return nil, fmt.Errorf("unsupported regex byte type: %x", rlist[i].Type)
// 		}

// 		if rlist[i].isEnd {
// 			break
// 		}
// 	}

// 	// var out []string
// 	g.DFS(g.Vertices[0], func(i int) {
// 		fmt.Printf("%d) %s\n", i, rlist[i].String(nil))
// 		if rlist[i].Type == End {
// 			fmt.Println(rlist[i].String(nil))
// 		}
// 		// if rlist[i].Type == Character || rlist[i].Type == Class || rlist[i].Type == ClassExclude {
// 		// 	out = append(out, rlist[i].Value.(string))
// 		// }
// 	})

// 	return g, nil
// }
