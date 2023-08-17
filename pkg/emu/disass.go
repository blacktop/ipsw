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

func diss(startAddr uint64, data []byte) (instruction *disassemble.Instruction) {
	var instrValue uint32
	var results [1024]byte

	r := bytes.NewReader(data)

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		instruction, err = disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			fmt.Printf("%s:  %s\t%s\t%#-18x ; (%s)\n",
				colorAddr("%#08x", uint64(startAddr)),
				colorOp("%-7s", ".long"),
				colorOpCodes(disassemble.GetOpCodeByteString(instrValue)),
				instrValue,
				err.Error())
		}

		opStr := strings.TrimSpace(strings.TrimPrefix(instruction.String(), instruction.Operation.String()))

		fmt.Printf("%s:  %s   %s %s\n",
			colorAddr("%#08x", uint64(startAddr)),
			colorOpCodes(disassemble.GetOpCodeByteString(instrValue)),
			colorOp("%-7s", instruction.Operation),
			colorOperands(" "+opStr),
		)

		startAddr += uint64(binary.Size(uint32(0)))
	}

	return
}
