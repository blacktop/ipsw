package sandbox

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type reType int

const (
	Character reType = iota
	JumpForward
	JumpBackward
	Class
	ClassExclude
	End
)

type reNode struct {
	Postion int
	Next    int
	Type    reType
	Value   any
}

type reList []reNode

func (rl reList) String() string {
	var out string
	for _, r := range rl {
		if r.Type == Character || r.Type == Class || r.Type == ClassExclude {
			out += fmt.Sprintf("%s", r.Value)
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
	var rlist reList

	if re.Version != 3 {
		return nil, fmt.Errorf("unsupported regex version: %d", re.Version)
	}

	for i := 0; i < len(re.Data); i++ {
		var rl reNode
		switch {
		case re.Data[i] == 0x02:
			// parse character
			rl.Postion = i
			rl.Next = i + 2
			rl.Type = Character
			rl.Value = string(re.Data[i+1])
			if string(re.Data[i+1]) == "." {
				rl.Value = "[.]"
			}
			i++
		case re.Data[i] == 0x19:
			// parse begining of line
			rl.Postion = i
			rl.Next = i + 1
			rl.Type = Character
			rl.Value = "^"
		case re.Data[i] == 0x29:
			// parse end of line
			rl.Postion = i
			rl.Next = i + 1
			rl.Type = Character
			rl.Value = "$"
		case re.Data[i] == 0x09:
			// parse any character
			rl.Postion = i
			rl.Next = i + 1
			rl.Type = Character
			rl.Value = "."
		case re.Data[i] == 0x2f:
			// parse jump forward
			rl.Postion = i
			rl.Next = i + 3
			rl.Type = JumpForward
			rl.Value = uint16(re.Data[i+1]) + uint16(re.Data[i+2])<<8
			i += 2
		case (re.Data[i] & 0xf) == 0xa:
			// parse jump backward
			rl.Postion = i
			rl.Next = i + 3
			rl.Type = JumpBackward
			rl.Value = uint16(re.Data[i+1]) + uint16(re.Data[i+2])<<8
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
			rl.Postion = i - 1
			rl.Next = i + (2 * n)
			rl.Value = val
			i += (2 * n) - 1
		case (re.Data[i] & 0xf) == 0x5:
			// parse end
			rl.Postion = i
			rl.Next = i + 2
			rl.Type = End
			rl.Value = 0
			i++
		default:
			return nil, fmt.Errorf("unsupported regex byte type: %x", re.Data[i])
		}

		rlist = append(rlist, rl)
	}

	return rlist, nil
}
