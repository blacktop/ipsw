package kdk

import (
	"encoding/binary"
	"sort"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

// foreignCodeContext decides whether a function in another fileset entry can
// return. KEXTs in a collection branch directly to kernel functions such as
// __stack_chk_fail or panic. Assuming that those return lets the register
// tracking of recoverOff12References fall through into the next basic block,
// where the tracked register means something else; the invented OFF12
// adjustments then corrupt ordinary field accesses (`str x20, [x28]` became
// `[x28, #0x2a0]` in apfs) as soon as kmutil lays the collection out anew.
type foreignCodeContext struct {
	functions []types.Function // sorted by start address
	code      []codeRange      // instruction sections of all entries
	memo      map[uint64]bool
}

type codeRange struct {
	addr uint64
	data []byte
}

func newForeignCodeContext(kc *macho.File, entries map[string]*macho.File) *foreignCodeContext {
	ctx := &foreignCodeContext{memo: make(map[uint64]bool)}
	for _, fse := range kc.FileSets() {
		mfse, ok := entries[fse.EntryID]
		if !ok {
			continue
		}
		ctx.functions = append(ctx.functions, mfse.GetFunctions()...)
		for _, sec := range codeSections(mfse) {
			if data, err := sec.Data(); err == nil {
				ctx.code = append(ctx.code, codeRange{addr: sec.Addr, data: data})
			}
		}
	}
	sort.Slice(ctx.functions, func(i, j int) bool { return ctx.functions[i].StartAddr < ctx.functions[j].StartAddr })
	return ctx
}

func (ctx *foreignCodeContext) instruction(addr uint64) (uint32, bool) {
	for _, c := range ctx.code {
		if addr >= c.addr && addr+4 <= c.addr+uint64(len(c.data)) {
			return binary.LittleEndian.Uint32(c.data[addr-c.addr:]), true
		}
	}
	return 0, false
}

func (ctx *foreignCodeContext) function(addr uint64) (types.Function, bool) {
	i := sort.Search(len(ctx.functions), func(i int) bool { return ctx.functions[i].StartAddr > addr }) - 1
	if i < 0 || !addressInFunction(addr, ctx.functions[i]) {
		return types.Function{}, false
	}
	return ctx.functions[i], true
}

// mayReturn reports whether a RET (or a tail call into a returning function)
// is reachable within the function starting at start. Flow that leaves the
// function's bounds by falling through follows a call that does not return.
// Anything that cannot be analysed is assumed to return.
func (ctx *foreignCodeContext) mayReturn(start uint64, depth int) bool {
	if ctx == nil {
		return true
	}
	if r, ok := ctx.memo[start]; ok {
		return r
	}
	fn, ok := ctx.function(start)
	if !ok || fn.StartAddr != start || depth > 8 {
		return true
	}
	ctx.memo[start] = true // recursion: assume it returns
	result := false
	seen := make(map[uint64]bool)
	work := []uint64{start}
	for len(work) > 0 && !result {
		pc := work[len(work)-1]
		work = work[:len(work)-1]
		for !result {
			if pc < fn.StartAddr || pc >= fn.EndAddr || seen[pc] {
				break
			}
			seen[pc] = true
			insn, ok := ctx.instruction(pc)
			if !ok {
				result = true
				break
			}
			switch {
			case insn&0xFFFFFC1F == 0xD65F0000 || insn == 0xD65F0BFF || insn == 0xD65F0FFF:
				result = true // RET, RETAA, RETAB
			case insn&0xFFE0001F == 0xD4200000:
				// BRK ends the path.
			case insn&0xFFFFFC1F == 0xD61F0000 || isAuthenticatedJump(insn):
				result = true // indirect jump or tail call: unknown
			case insn&0xFC000000 == 0x94000000: // BL
				if target, ok := branchTarget(insn, pc); ok && !ctx.mayReturn(target, depth+1) {
					break
				}
				pc += 4
				continue
			case insn&0xFC000000 == 0x14000000: // B
				target, _ := branchTarget(insn, pc)
				if target < fn.StartAddr || target >= fn.EndAddr {
					result = ctx.mayReturn(target, depth+1) // tail call
					break
				}
				pc = target
				continue
			default:
				if target, ok := branchTarget(insn, pc); ok { // conditional branch
					work = append(work, target)
				}
				pc += 4
				continue
			}
			break
		}
	}
	ctx.memo[start] = result
	return result
}
