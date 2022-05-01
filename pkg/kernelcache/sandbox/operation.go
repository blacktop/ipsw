package sandbox

import (
	"fmt"

	"github.com/blacktop/go-macho/types"
)

const (
	OPERATION_NODE_TYPE_NON_TERMINAL = 0x00
	OPERATION_NODE_TYPE_TERMINAL     = 0x01
)

type OperationNode uint64

func (o OperationNode) Type() byte {
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
	TERMINAL_NODE_TYPE_ALLOW = 0x00
	TERMINAL_NODE_TYPE_DENY  = 0x01
)

// TerminalNode a terminal node, when reached, either denies or allows the rule.
type TerminalNode uint64

func (n TerminalNode) Type() byte {
	return byte(types.ExtractBits(uint64(n), 0, 1))
}
func (n TerminalNode) Flags() byte {
	return byte(types.ExtractBits(uint64(n), 1, 7))
}
func (n TerminalNode) Extra() uint64 {
	return types.ExtractBits(uint64(n), 8, 54)
}
func (n TerminalNode) IsAllow() bool {
	return n.Type() == TERMINAL_NODE_TYPE_ALLOW
}
func (n TerminalNode) IsDeny() bool {
	return n.Type() == TERMINAL_NODE_TYPE_DENY
}
func (n TerminalNode) String() string {
	typ := "allow"
	if n.IsDeny() {
		typ = "deny "
	}
	return fmt.Sprintf("terminal (%s flag: %d, extra: %#x)", typ, n.Flags(), n.Extra())
}

type NonTerminalNode uint64

func (n NonTerminalNode) FilterID() byte {
	return byte(types.ExtractBits(uint64(n), 8, 8))
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
