package sandbox

import (
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
)

const (
	OPERATION_NODE_TYPE_NON_TERMINAL = 0
	OPERATION_NODE_TYPE_TERMINAL     = 1
)

type OperationNode uint64 // instruction

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
	switch o.Type() {
	case OPERATION_NODE_TYPE_NON_TERMINAL:
		return NonTerminalNode(o).String()
	case OPERATION_NODE_TYPE_TERMINAL:
		return TerminalNode(o).String()
	default:
		return fmt.Sprintf("unknown operation node type: %d", o.Type())
	}
}

const (
	TERMINAL_NODE_TYPE_ALLOW = 0
	TERMINAL_NODE_TYPE_DENY  = 1
	ACTION_INLINE_FLAG       = 0x8000
	ALT_TYPE_FLAG            = 0x8000 /* some op nodes filter ids have this bit set (I think this means
	 * a different kind of argument variant) for example there used to be a filter name "syscall-mask" in sandblaster,
	 * but they didn't know how to parse it. I've seen the filter "syscall-number" have this high bit set in it's ID
	 * so I think that means it's the "syscall-mask" variant? There also used to be a LOT of regex versions of filters
	 * xattr-regex etc etc so it might mean a regex variant as well */
	INSTR_TYPE_NONE     = 0
	INSTR_TYPE_JUMP     = 1 << 0 // 1
	INSTR_TYPE_ACTION   = 1 << 1 // 2
	INSTR_TYPE_UNKNOWN  = 1 << 2 // 4
	INSTR_TYPE_UNKNOWN2 = 1 << 4 // 16
)

// TerminalNode a terminal node, when reached, either denies or allows the rule.
type TerminalNode uint64

func (n TerminalNode) Action() uint8 {
	return uint8(types.ExtractBits(uint64(n), 8, 1))
}
func (n TerminalNode) Type() uint8 {
	return uint8(types.ExtractBits(uint64(n), 9, 7))
}
func (n TerminalNode) Flags() uint16 {
	return uint16(types.ExtractBits(uint64(n), 16, 16))
}
func (n TerminalNode) ActionInline() bool {
	/* NOTE: from emit_instruction(_QWORD *a1, __int64 instruction, _WORD *a3) in libsandbox.1.dylib (macOS 12.3.1)
	 *     if ( (flags & 0x8000) != 0 )
	 *         j____assert_rtn_2("sb_instr_get_action_flags", "instruction.c", 475, "(flags & ACTION_INLINE_FLAG) == 0");   */
	return (n.Flags() & ACTION_INLINE_FLAG) != 0
}
func (n TerminalNode) ActionModifiers() uint32 {
	return uint32(types.ExtractBits(uint64(n), 24, 8))
}
func (n TerminalNode) ModParts() (uint16, uint16) {
	return uint16(types.ExtractBits(uint64(n), 48, 16)), uint16(types.ExtractBits(uint64(n), 32, 16))
}
func (n TerminalNode) IsAllow() bool {
	return n.Action() == TERMINAL_NODE_TYPE_ALLOW
}
func (n TerminalNode) IsDeny() bool {
	return n.Action() == TERMINAL_NODE_TYPE_DENY
}
func (n TerminalNode) Decision() string {
	if n.IsAllow() {
		return "allow"
	}
	return "deny "
}
func (n TerminalNode) String() string {
	var mod string
	if n.ActionInline() {
		car, cdr := n.ModParts()
		mod = fmt.Sprintf("action-inline(%d, %#x), ", car, cdr)
	} else {
		car, cdr := n.ModParts()
		if cdr > 0 {
			mod = fmt.Sprintf("modifiers(%d, %d), ", car, cdr)
		}
	}
	return fmt.Sprintf("terminal (%s type: %d, flag: %#x, %sraw: %#016x)",
		n.Decision(),
		n.Type(),
		n.Flags(),
		mod,
		uint64(n))
}

type NonTerminalNode uint64 // condition

func (n NonTerminalNode) FilterID() uint8 {
	return uint8(types.ExtractBits(uint64(n)&^uint64(ALT_TYPE_FLAG), 8, 8))
}
func (n NonTerminalNode) AltArgument() bool {
	return (uint64(n) & ALT_TYPE_FLAG) != 0
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
	arg := "arg"
	if n.AltArgument() {
		arg = "alt-arg"
	}
	return fmt.Sprintf("non-terminal (filter_id: %2d, %7s: %#04x, match_off: %#x, unmatch_off: %#x)",
		n.FilterID(),
		arg,
		n.ArgumentID(),
		n.MatchOffset(),
		n.UnmatchOffset())
}

// FIXME: turn this into an acyclic graph
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
	if opr, ok := sb.ops[op]; ok {
		return opr, nil
	}

	log.Debugf("parsing op node: %s", op.String())

	switch op.Type() {
	case OPERATION_NODE_TYPE_NON_TERMINAL:
		node := NonTerminalNode(op)
		filter, err := sb.db.GetFilter(node.FilterID())
		if err != nil {
			return nil, fmt.Errorf("failed to get filter for ID %d: %v", node.FilterID(), err)
		}
		arg, err := filter.GetArgument(sb, node.ArgumentID(), node.AltArgument())
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
		// cache the parsed node
		sb.ops[op] = &Operation{
			Filter:   filter,
			Argument: arg,
			Match:    match,
			Unmatch:  unmatch,
			node:     op,
			parsed:   true,
		}
		return sb.ops[op], nil
	case OPERATION_NODE_TYPE_TERMINAL:
		// cache the parsed node
		sb.ops[op] = &Operation{
			node:   op,
			parsed: true,
		}
		return sb.ops[op], nil
	default:
		return nil, fmt.Errorf("unknown operation node type: %d", op.Type())
	}
}

func (o *Operation) String(name string) string {
	var out string
	if o.node.IsTerminal() {
		node := TerminalNode(o.node)
		if node.ActionInline() {
			out = fmt.Sprintf("(%s, %s) %s 👀", node.Decision(), name, node)
		} else {
			_, cdr := node.ModParts()
			if cdr > 0 {
				out = fmt.Sprintf("(%s, %s) %s 👀", node.Decision(), name, node)
			} else {
				out = fmt.Sprintf("(%s %s)", node.Decision(), name)
			}
		}
	} else {
		out = fmt.Sprintf("(%s %s %s)", o.Filter.Name, o.Argument, name)
		out += fmt.Sprintf("\n\t  MATCH: %s", o.Match.String(name))
		out += fmt.Sprintf("\n\tUNMATCH: %s", o.Unmatch.String(name))
	}
	return out
}
