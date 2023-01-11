package sandbox

//go:generate stringer -type=reType -output regex_string.go

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
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
	Value   any
	Next    int
	Type    reType
	isStart bool
	isEnd   bool
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
	Data    []byte
	Version uint32
	Length  uint16
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

func (re *Regex) Dump(name string) error {
	var buff bytes.Buffer

	if err := binary.Write(&buff, binary.BigEndian, uint32(re.Version)); err != nil {
		return fmt.Errorf("failed to write regex version: %v", err)
	}
	if err := binary.Write(&buff, binary.LittleEndian, uint16(re.Length)); err != nil {
		return fmt.Errorf("failed to write regex data length: %v", err)
	}
	if _, err := buff.Write(re.Data); err != nil {
		return fmt.Errorf("failed to write regex data: %v", err)
	}

	return os.WriteFile(name, buff.Bytes(), 0644)
}

func (re *Regex) Parse() (reList, error) {
	if re.Version != 3 {
		return nil, fmt.Errorf("unsupported regex version: %d", re.Version)
	}

	rlist := make(reList)

	var rl reNode
	for i := 0; i < len(re.Data); i++ {
		rl = reNode{}

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
			rl.Value = uint16(re.Data[i+1]) + (uint16(re.Data[i+2]) << 8)
			rlist[i] = rl
			i += 2
		case (re.Data[i] & 0xf) == 0xa:
			// parse jump backward
			rl.Next = i + 3
			rl.Type = JumpBackward
			rl.Value = uint16(re.Data[i+1]) + (uint16(re.Data[i+2]) << 8)
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

func (re *Regex) NFA() (*NFA, error) {
	rlist, err := re.Parse()
	if err != nil {
		return nil, err
	}

	nfa := NewNFA()

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
			nfa.Nodes[strconv.Itoa(i)].IsTerminal = true
		case JumpForward:
			nfa.AddEdge(strconv.Itoa(i), strconv.Itoa(rlist[i].Next), "")
			nfa.AddEdge(strconv.Itoa(i), strconv.Itoa(int(rlist[i].Value.(uint16))), "")
		case JumpBackward:
			nfa.AddEdge(strconv.Itoa(i), strconv.Itoa(int(rlist[i].Value.(uint16))), "")
		default:
			return nil, fmt.Errorf("unsupported regex byte type: %x", rlist[i].Type)
		}

		i = rlist[i].Next

		if rlist[i].isEnd {
			break
		}
	}

	nfa.Nodes[strconv.Itoa(0)].IsInitial = true

	return nfa, nil
}
