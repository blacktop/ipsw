package sandbox

import (
	"fmt"

	"github.com/blacktop/go-macho/types"
)

const (
	OPERATION_NODE_TYPE_NON_TERMINAL = 0
	OPERATION_NODE_TYPE_TERMINAL     = 1
)

type OperationNode uint64

func (o OperationNode) Type() uint8 {
	return byte(types.ExtractBits(uint64(o), 0, 8))
}
func (o OperationNode) IsTerminal() bool {
	return o.Type() == OPERATION_NODE_TYPE_TERMINAL
}
func (o OperationNode) IsNonTerminal() bool {
	return o.Type() == OPERATION_NODE_TYPE_NON_TERMINAL
}
func (o OperationNode) String() string {
	if o.IsTerminal() {
		return TerminalNode(o).String()
	} else {
		return NonTerminalNode(o).String()
	}
}

const (
	TERMINAL_NODE_TYPE_ALLOW = 0
	TERMINAL_NODE_TYPE_DENY  = 1
)

// TerminalNode a terminal node, when reached, either denies or allows the rule.
type TerminalNode uint64

func (n TerminalNode) Type() uint8 {
	return uint8(types.ExtractBits(uint64(n), 8, 1))
}
func (n TerminalNode) Flags() uint8 {
	return uint8(types.ExtractBits(uint64(n), 9, 7))
}
func (n TerminalNode) Extra() uint64 {
	return types.ExtractBits(uint64(n), 16, 48)
}
func (n TerminalNode) IsAllow() bool {
	return n.Type() == TERMINAL_NODE_TYPE_ALLOW
}
func (n TerminalNode) IsDeny() bool {
	return n.Type() == TERMINAL_NODE_TYPE_DENY
}
func (n TerminalNode) TypeString() string {
	if n.IsAllow() {
		return "allow"
	}
	return "deny"
}
func (n TerminalNode) String() string {
	return fmt.Sprintf("terminal (%s flag: %d, extra: %#x)", n.TypeString(), n.Flags(), n.Extra())
}

type NonTerminalNode uint64

func (n NonTerminalNode) FilterID() uint8 {
	return uint8(types.ExtractBits(uint64(n), 8, 8))
}
func (n NonTerminalNode) ArgumentID() uint16 {
	return uint16(types.ExtractBits(uint64(n), 16, 8) + (types.ExtractBits(uint64(n), 24, 8) << 8))
}
func (n NonTerminalNode) MatchOffset() uint16 {
	return uint16(types.ExtractBits(uint64(n), 32, 8) + (types.ExtractBits(uint64(n), 40, 8) << 8))
}
func (n NonTerminalNode) UnmatchOffset() uint16 {
	return uint16(types.ExtractBits(uint64(n), 48, 8) + (types.ExtractBits(uint64(n), 56, 8) << 8))
}
func (n NonTerminalNode) String() string {
	return fmt.Sprintf("non-terminal (filter_id: %d, argument_id: %d, match_offset: %#x, unmatch_offset: %#x)", n.FilterID(), n.ArgumentID(), n.MatchOffset(), n.UnmatchOffset())
}

type Operation struct {
	Name     string
	Filter   *FilterInfo
	Argument any
	Match    *Operation
	Unmatch  *Operation

	node   OperationNode
	parsed bool
}

func ParseOperation(sb *Sandbox, op OperationNode) (*Operation, error) {
	if op.IsTerminal() {
		return &Operation{
			node:   op,
			parsed: true,
		}, nil
	} else {
		node := NonTerminalNode(op)
		filter, err := sb.db.GetFilter(node.FilterID())
		if err != nil {
			return nil, fmt.Errorf("failed to get filter for ID %d: %v", node.FilterID(), err)
		}
		arg, err := filter.GetArgument(sb, node.ArgumentID())
		if err != nil {
			return nil, fmt.Errorf("failed to get argument for ID %d: %v", node.ArgumentID(), err)
		}
		match, err := ParseOperation(sb, sb.OpNodes[node.MatchOffset()])
		if err != nil {
			return nil, fmt.Errorf("failed to parse match operation node %s: %v", sb.OpNodes[node.MatchOffset()], err)
		}
		unmatch, err := ParseOperation(sb, sb.OpNodes[node.UnmatchOffset()])
		if err != nil {
			return nil, fmt.Errorf("failed to parse unmatch operation node %s: %v", sb.OpNodes[node.UnmatchOffset()], err)
		}
		return &Operation{
			Filter:   filter,
			Argument: arg,
			Match:    match,
			Unmatch:  unmatch,
			node:     op,
			parsed:   true,
		}, nil
	}
}

func (o *Operation) String(name string) string {
	var out string
	if o.node.IsTerminal() {
		out = fmt.Sprintf("(%s %s)", TerminalNode(o.node).TypeString(), name)
	} else {
		out = fmt.Sprintf("(%s %s %s)", o.Filter.Name, o.Argument, name)
		if o.Match.node.IsTerminal() {
			out += fmt.Sprintf("\t%s", o.Match.String(name))
		} else {
			out += fmt.Sprintf("\t%s", o.Unmatch.String(name))
		}
	}
	return out
}
