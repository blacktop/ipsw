//go:build unicorn

package emu

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/blacktop/arm64-cgo/disassemble"
)

func colorOperands(operands string) string {
	if len(operands) > 0 {
		immMatch := regexp.MustCompile(`#?-?0x[0-9a-z]+`)
		operands = immMatch.ReplaceAllStringFunc(operands, func(s string) string {
			return colorImm(s)
		})
		regMatch := regexp.MustCompile(`\W([wxvbhsdqzp][0-9]{1,2}|(c|s)psr(_c)?|pc|sl|sb|fp|ip|sp|lr|fpsid|fpscr|fpexc)`)
		operands = regMatch.ReplaceAllStringFunc(operands, func(s string) string {
			return string(s[0]) + colorRegs(s[1:])
		})
	}
	return operands
}

func printDecodeFailure(startAddr uint64, instrValue uint32, err error) {
	fmt.Printf("%s:  %s\t%s\t%#-18x ; (%s)\n",
		colorAddr("%#08x", uint64(startAddr)),
		colorOp("%-7s", ".long"),
		colorOpCodes(disassemble.GetOpCodeByteString(instrValue)),
		instrValue,
		err.Error())
}

func diss(startAddr uint64, data []byte) {
	var instrValue uint32
	var decoder disassemble.Decoder

	r := bytes.NewReader(data)

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		var instruction disassemble.Inst
		if err := decoder.DecomposeInto(startAddr, instrValue, &instruction); err != nil {
			printDecodeFailure(startAddr, instrValue, err)
			startAddr += uint64(binary.Size(uint32(0)))
			continue
		}

		disass, err := instruction.Disassemble()
		if err != nil {
			printDecodeFailure(startAddr, instrValue, err)
			startAddr += uint64(binary.Size(uint32(0)))
			continue
		}

		opStr := strings.TrimSpace(strings.TrimPrefix(disass, instruction.Operation.String()))

		fmt.Printf("%s:  %s   %s %s\n",
			colorAddr("%#08x", uint64(startAddr)),
			colorOpCodes(disassemble.GetOpCodeByteString(instrValue)),
			colorOp("%-7s", instruction.Operation),
			colorOperands(" "+opStr),
		)

		startAddr += uint64(binary.Size(uint32(0)))
	}
}
