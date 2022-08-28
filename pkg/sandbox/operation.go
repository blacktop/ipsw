package sandbox

import (
	"fmt"
	"strings"

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
	ACTION_INLINE_FLAG       = 0x80
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

type InlineModifier struct {
	ID          uint8
	PolicyOpIdx uint8
	Argument    uint16
}

type Modifier struct {
	Count   uint8
	Unknown uint8
	Offset  uint16
}

// TerminalNode a terminal node, when reached, either denies or allows the rule.
type TerminalNode uint64

func (n TerminalNode) Action() uint16 {
	return uint16(types.ExtractBits(uint64(n), 8, 16))
}
func (n TerminalNode) ModifierFlags() uint16 {
	return uint16(types.ExtractBits(uint64(n), 24, 8))
}
func (n TerminalNode) ActionInline() bool {
	/* NOTE: from emit_instruction(_QWORD *a1, __int64 instruction, _WORD *a3) in libsandbox.1.dylib (macOS 12.3.1)
	 *     if ( (flags & 0x8000) != 0 )
	 *         j____assert_rtn_2("sb_instr_get_action_flags", "instruction.c", 475, "(flags & ACTION_INLINE_FLAG) == 0");   */
	return (n.ModifierFlags() & ACTION_INLINE_FLAG) != 0
}
func (n TerminalNode) InlineModifier() InlineModifier {
	return InlineModifier{
		ID:          uint8(types.ExtractBits(uint64(n), 32, 8)),
		PolicyOpIdx: uint8(types.ExtractBits(uint64(n), 40, 8)),
		Argument:    uint16(types.ExtractBits(uint64(n), 48, 16)),
	}
}
func (n TerminalNode) Modifier() Modifier {
	return Modifier{
		Count:   uint8(types.ExtractBits(uint64(n), 32, 8)),
		Unknown: uint8(types.ExtractBits(uint64(n), 40, 8)),
		Offset:  uint16(types.ExtractBits(uint64(n), 48, 16)),
	}
}
func (n TerminalNode) IsAllow() bool {
	return (n.Action() & 0x1) == TERMINAL_NODE_TYPE_ALLOW
}
func (n TerminalNode) IsDeny() bool {
	return (n.Action() & 0x1) == TERMINAL_NODE_TYPE_DENY
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
		mod = fmt.Sprintf("inline_mod(%v), ", n.InlineModifier())
	} else {
		if n.Modifier().Count > 0 {
			mod = fmt.Sprintf("modifiers(%v), ", n.Modifier())
		}
	}
	return fmt.Sprintf("terminal (%s action: %d, flags: %#x, %sraw: %#016x)",
		n.Decision(),
		n.Action(),
		n.ModifierFlags(),
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
	return fmt.Sprintf("non-terminal (filter_id: %2d, %7s: %#04x, match_off: %#x, unmatch_off: %#x, raw: %#x)",
		n.FilterID(),
		arg,
		n.ArgumentID(),
		n.MatchOffset(),
		n.UnmatchOffset(),
		uint64(n))
}

func (sb *Sandbox) ParseOperation(op *Operation) (err error) {
	if op.parsed {
		return nil
	}

	log.Debugf("parsing op node: %s", op.Node.String())

	switch op.Node.Type() {
	case OPERATION_NODE_TYPE_NON_TERMINAL:
		node := NonTerminalNode(op.Node)
		op.Match = &Operation{
			Node:          sb.OpNodes[op.MatchOffset].Node,
			MatchOffset:   NonTerminalNode(sb.OpNodes[op.MatchOffset].Node).MatchOffset(),
			UnmatchOffset: NonTerminalNode(sb.OpNodes[op.UnmatchOffset].Node).UnmatchOffset(),
		}
		op.Unmatch = &Operation{
			Node:          sb.OpNodes[op.UnmatchOffset].Node,
			MatchOffset:   NonTerminalNode(sb.OpNodes[op.MatchOffset].Node).MatchOffset(),
			UnmatchOffset: NonTerminalNode(sb.OpNodes[op.UnmatchOffset].Node).UnmatchOffset(),
		}
		op.Filter, err = sb.db.GetFilter(node.FilterID())
		if err != nil {
			return fmt.Errorf("failed to get filter for ID %d: %v", node.FilterID(), err)
		}
		op.Argument, err = op.Filter.GetArgument(sb, node.ArgumentID(), node.AltArgument())
		if err != nil {
			// return fmt.Errorf("failed to get argument for ID %d: %v", node.ArgumentID(), err)
			log.Errorf("failed to get filter %s argument for ID %d: %v", op.Filter.Name, node.ArgumentID(), err)
		}
		switch v := op.Argument.(type) {
		default:
			fmt.Printf("unexpected type %T", v)
		case []string:
			if len(v) == 1 {
				op.Argument = fmt.Sprintf("\"%s\"", v[0])
			}
			if len(v) > 1 {
				op.Argument = dedup(op.Argument.([]string))
				if len(op.Argument.([]string)) == 1 {
					op.Argument = fmt.Sprintf("\"%s\"", op.Argument.([]string)[0])
				}
			}
		case string:
			op.Argument = fmt.Sprintf("\"%s\"", op.Argument)
			if len(op.Argument.(string)) > 500 {
				op.Argument = op.Argument.(string)[:200]
			}
		}
		op.parsed = true
	case OPERATION_NODE_TYPE_TERMINAL:
		node := TerminalNode(op.Node)
		op.Terminal = true
		op.Allow = node.IsAllow()
		// var mods []ModifierInfo
		// if node.ActionInline() {
		// 	mod, err := sb.db.GetModifier(node.InlineModifier().ID)
		// 	if err != nil {
		// 		return err
		// 	}
		// 	fmt.Printf("(apply-%s\n", mod.Name)
		// 	oper, err := sb.db.GetOperation(node.InlineModifier().PolicyOpIdx)
		// 	if err != nil {
		// 		return err
		// 	}
		// 	oo, err := sb.ParseOperation(sb.OpNodes[sb.Policies[node.InlineModifier().Argument]])
		// 	if err != nil {
		// 		return err
		// 	}
		// 	fmt.Println(oo.String(0))
		// 	if oo.Match > 0 {
		// 		match, err := sb.ParseOperation(oo.Name, oo.Match)
		// 		if err != nil {
		// 			log.Errorf("failed to parse match operation node %s: %v", oo.Match, err)
		// 		}
		// 		fmt.Println("MATCH:", match.String(1))
		// 	}
		// 	if oo.Unmatch > 0 {
		// 		unmatch, err := sb.ParseOperation(oo.Name, oo.Unmatch)
		// 		if err != nil {
		// 			log.Errorf("failed to parse unmatch operation node %s: %v", oo.Unmatch, err)
		// 		}
		// 		fmt.Println("UNMATCH:", unmatch.String(1))
		// 	}
		// } else if node.Modifier().Count > 0 {
		// 	mod := node.Modifier()
		// 	if mod.Count > 0 {
		// 		fmt.Println(mod)
		// 	}
		// } else {
		// 	var err error
		op.Modiers, err = sb.db.GetModifiersFromAction(node.Action())
		if err != nil {
			return err
		}
		// }
		op.parsed = true
	default:
		return fmt.Errorf("unknown operation node type: %d", op.Node.Type())
	}
	return nil
}

func dedup(args []string) []string {
	// sort.Slice(args, func(i, j int) bool {
	// 	return len(args[i]) < len(args[j])
	// })
	var ret []string
	seen := make(map[string]bool)
	for _, arg := range args {
		if !seen[arg] && !seen[arg+"/"] {
			ret = append(ret, arg)
			seen[arg] = true
		}
	}
	return ret
}

type opType uint8

const (
	Normal opType = iota
	Start
	Final
)

// FIXME: turn this into an acyclic graph
type Operation struct {
	Argument      any
	Filter        *FilterInfo
	Modiers       []ModifierInfo
	Node          OperationNode
	Match         *Operation
	Unmatch       *Operation
	UnmatchOffset uint16
	MatchOffset   uint16
	Terminal      bool
	Allow         bool
	not           bool
	Type          opType
	parsed        bool
	List          []*Operation
}

func (o *Operation) Depth() int {
	if o == nil {
		return 0
	}
	if o.Match == nil && o.Unmatch == nil {
		return 1
	}
	lHeight := o.Match.Depth()
	rHeight := o.Unmatch.Depth()
	if lHeight >= rHeight {
		return lHeight + 1
	} else {
		return rHeight + 1
	}
}

func (o *Operation) IsNonTerminalDeny() bool {
	if !o.Match.Terminal && o.Unmatch.Terminal {
		return !o.Unmatch.Allow
	}
	return false
}
func (o *Operation) IsNonTerminalAllow() bool {
	if !o.Match.Terminal && o.Unmatch.Terminal {
		return o.Unmatch.Allow
	}
	return false
}
func (o *Operation) IsNonTerminalNonTerminal() bool {
	return !o.Match.Terminal && !o.Unmatch.Terminal
}
func (o *Operation) IsAllowNonTerminal() bool {
	if o.Match.Terminal && !o.Unmatch.Terminal {
		return o.Match.Allow
	}
	return false
}
func (o *Operation) IsDenyNonTerminal() bool {
	if o.Match.Terminal && !o.Unmatch.Terminal {
		return !o.Match.Allow
	}
	return false
}
func (o *Operation) IsDenyAllow() bool {
	if o.Match.Terminal && o.Unmatch.Terminal {
		return !o.Match.Allow && o.Unmatch.Allow
	}
	return false
}
func (o *Operation) IsAllowDeny() bool {
	if o.Match.Terminal && o.Unmatch.Terminal {
		return o.Match.Allow && !o.Unmatch.Allow
	}
	return false
}

func (o *Operation) String(name string, indent int) string {
	var out string
	if o == nil {
		return ""
	}
	if o.Node.IsTerminal() {
		node := TerminalNode(o.Node)
		out = fmt.Sprintf("(%s %s ", node.Decision(), name)
		if len(o.Modiers) > 0 {
			for _, mod := range o.Modiers {
				out += fmt.Sprintf("(with %s) 👀 ", mod.Name)
			}
		} else if node.ActionInline() {
			out = fmt.Sprintf("(%s, %s) %s 👀", node.Decision(), name, node)
		} else {
			mod := node.Modifier()
			if mod.Count > 0 {
				out = fmt.Sprintf("(%s, %s) %s 👀", node.Decision(), name, node)
			}
		}
	} else {
		if o.Filter != nil {
			out = fmt.Sprintf("(%s %s %s)", name, o.Filter.Name, o.Argument)
		} else {
			out = fmt.Sprintf("(%s %s)", name, o.Argument)
		}
		// out += fmt.Sprintf("\n\t%s  MATCH: %s", strings.Repeat("  ", indent), o.Match.String())
		// out += fmt.Sprintf("\n\t%sUNMATCH: %s", strings.Repeat("  ", indent), o.Unmatch.String())
		out += fmt.Sprintf("\n\t%s  MATCH: %s", strings.Repeat("  ", indent), o.Match.String(name, indent+1))
		out += fmt.Sprintf("\n\t%sUNMATCH: %s", strings.Repeat("  ", indent), o.Unmatch.String(name, indent+1))
	}
	return out
}

func (o *Operation) Graph() string {
	return ""
}
