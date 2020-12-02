/*
Copyright © 2020 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alecthomas/chroma"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/quick"
	"github.com/alecthomas/chroma/styles"
	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldDisassCmd)

	// dyldDisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	// dyldDisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	dyldDisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	dyldDisassCmd.Flags().BoolVarP(&demangleFlag, "demangle", "d", false, "Demandle symbol names")
	// dyldDisassCmd.Flags().StringP("sym-file", "s", "", "Companion symbol map file")
	dyldDisassCmd.Flags().StringP("image", "i", "", "dylib image to search")

	symaddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")

	styles.Register(chroma.MustNewStyle("nord", chroma.StyleEntries{
		chroma.TextWhitespace:        "#d8dee9",
		chroma.Comment:               "italic #616e87",
		chroma.CommentPreproc:        "#5e81ac",
		chroma.Keyword:               "bold #81a1c1",
		chroma.KeywordPseudo:         "nobold #81a1c1",
		chroma.KeywordType:           "nobold #81a1c1",
		chroma.Operator:              "#81a1c1",
		chroma.OperatorWord:          "bold #81a1c1",
		chroma.Name:                  "#d8dee9",
		chroma.NameBuiltin:           "#81a1c1",
		chroma.NameFunction:          "#88c0d0",
		chroma.NameClass:             "#8fbcbb",
		chroma.NameNamespace:         "#8fbcbb",
		chroma.NameException:         "#bf616a",
		chroma.NameVariable:          "#d8dee9",
		chroma.NameConstant:          "#8fbcbb",
		chroma.NameLabel:             "#8fbcbb",
		chroma.NameEntity:            "#d08770",
		chroma.NameAttribute:         "#8fbcbb",
		chroma.NameTag:               "#81a1c1",
		chroma.NameDecorator:         "#d08770",
		chroma.Punctuation:           "#eceff4",
		chroma.LiteralString:         "#a3be8c",
		chroma.LiteralStringDoc:      "#616e87",
		chroma.LiteralStringInterpol: "#a3be8c",
		chroma.LiteralStringEscape:   "#ebcb8b",
		chroma.LiteralStringRegex:    "#ebcb8b",
		chroma.LiteralStringSymbol:   "#a3be8c",
		chroma.LiteralStringOther:    "#a3be8c",
		chroma.LiteralNumber:         "#b48ead",
		chroma.GenericHeading:        "bold #88c0d0",
		chroma.GenericSubheading:     "bold #88c0d0",
		chroma.GenericDeleted:        "#bf616a",
		chroma.GenericInserted:       "#a3be8c",
		chroma.GenericError:          "#bf616a",
		chroma.GenericEmph:           "italic",
		chroma.GenericStrong:         "bold",
		chroma.GenericPrompt:         "bold #4c566a",
		chroma.GenericOutput:         "#d8dee9",
		chroma.GenericTraceback:      "#bf616a",
		chroma.Error:                 "#bf616a",
		chroma.Background:            " bg:#2e3440",
	}))

	lexers.Register(chroma.MustNewLexer(
		&chroma.Config{
			Name:      "ARM",
			Aliases:   []string{"arm"},
			Filenames: []string{"*.S"},
			MimeTypes: []string{},
		},
		chroma.Rules{
			"root": {
				chroma.Include("whitespace"),
				{`(?:[a-zA-Z$_][\w$.@-]*|\.[\w$.@-]+):`, chroma.NameLabel, nil},
				{`(?:0[xX][a-zA-Z0-9]+|\d+):`, chroma.NameLabel, nil},
				{`\.(?:[a-zA-Z$_][\w$.@-]*|\.[\w$.@-]+)`, chroma.NameAttribute, chroma.Push("directive-args")},
				{`(?:[a-zA-Z$_][\w$.@-]*|\.[\w$.@-]+)`, chroma.NameFunction, chroma.Push("instruction-args")},
				{`[\r\n]+`, chroma.Text, nil},
			},
			"directive-args": {
				{`(?:[a-zA-Z$_][\w$.@-]*|\.[\w$.@-]+)`, chroma.NameConstant, nil},
				{`"(\\"|[^"])*"`, chroma.LiteralString, nil},
				{`(?:0[xX][a-zA-Z0-9]+|\d+)`, chroma.LiteralNumberInteger, nil},
				{`[\r\n]+`, chroma.Text, chroma.Pop(1)},
				chroma.Include("punctuation"),
				chroma.Include("whitespace"),
			},
			"instruction-args": {
				{`(?:[a-zA-Z$_][\w$.@-]*|\.[\w$.@-]+)`, chroma.NameConstant, nil},
				{`(?:0[xX][a-zA-Z0-9]+|\d+)`, chroma.LiteralNumberInteger, nil},
				{`r[rR]\d+`, chroma.NameVariable, nil},
				{`'(.|\\')'?`, chroma.LiteralStringChar, nil},
				{`[\r\n]+`, chroma.Text, chroma.Pop(1)},
				chroma.Include("punctuation"),
				chroma.Include("whitespace"),
			},
			"whitespace": {
				{`[ \t]`, chroma.Text, nil},
				{`//[\w\W]*?(?=\n)`, chroma.CommentSingle, nil},
				{`/[*][\w\W]*?[*]/`, chroma.CommentMultiline, nil},
				{`[;@].*?(?=\n)`, chroma.CommentSingle, nil},
			},
			"punctuation": {
				{`[-*,.()\[\]!:{}^=#\+\\]+`, chroma.Punctuation, nil},
			},
			"eol": {
				{`[\r\n]+`, chroma.Text, nil},
			},
		},
	))
}

// disassCmd represents the disass command
var dyldDisassCmd = &cobra.Command{
	Use:   "disass",
	Short: "🚧 [WIP] Disassemble dyld_shared_cache symbol in an image",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		var data []byte
		var starts []uint64

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		instructions, _ := cmd.Flags().GetUint64("count")

		// symbolName, _ := cmd.Flags().GetString("symbol")
		// doDemangle, _ := cmd.Flags().GetBool("demangle")

		dscPath := filepath.Clean(args[0])

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		// Load all symbols
		if _, err := os.Stat(dscPath + ".a2s"); os.IsNotExist(err) {
			log.Info("Generating dyld_shared_cache companion symbol map file...")

			utils.Indent(log.Warn, 2)("parsing public symbols...")
			err = f.GetAllExportedSymbols(false)
			if err != nil {
				return err
			}

			utils.Indent(log.Warn, 2)("parsing private symbols...")
			err = f.ParseLocalSyms()
			if err != nil {
				return err
			}

			// save lookup map to disk to speed up subsequent requests
			err = f.SaveAddrToSymMap(dscPath + ".a2s")
			if err != nil {
				return err
			}

		} else {
			log.Info("Found dyld_shared_cache companion symbol map file...")
			a2sFile, err := os.Open(dscPath + ".a2s")
			if err != nil {
				return fmt.Errorf("failed to open companion file %s; %v", dscPath+".a2s", err)
			}

			gzr, err := gzip.NewReader(a2sFile)
			if err != nil {
				return fmt.Errorf("failed to create gzip reader: %v", err)
			}

			// Decoding the serialized data
			err = gob.NewDecoder(gzr).Decode(&f.AddressToSymbol)
			if err != nil {
				return fmt.Errorf("failed to decode addr2sym map; %v", err)
			}
			gzr.Close()
			a2sFile.Close()
		}

		if len(args) > 1 {
			log.Info("Locating symbol: " + args[1])
			symAddr, image, err := f.GetSymbolAddress(args[1], imageName)
			if err != nil {
				return err
			}

			off, _ := f.GetOffset(symAddr)

			if image == nil {
				image, err = f.GetImageContainingTextAddr(symAddr)
				if err != nil {
					return err
				}
			}

			log.WithFields(log.Fields{"dylib": image.Name}).Info("Found symbol")

			m, err := image.GetPartialMacho()
			if err != nil {
				return err
			}

			// fmt.Println(m.FileTOC.String())

			if fs := m.FunctionStarts(); fs != nil {
				data, err := f.ReadBytes(int64(fs.Offset), uint64(fs.Size))
				if err != nil {
					return err
				}
				starts = m.FunctionStartAddrs(data...)
			}

			if instructions > 0 {
				data, err = f.ReadBytes(int64(off), instructions*4)
				if err != nil {
					return err
				}
			} else {
				data, err = f.ReadBytes(int64(off), uint64(f.FunctionSize(starts, symAddr)))
				if err != nil {
					return err
				}
			}

			if m.HasObjC() {
				log.Info("Parsing ObjC runtime structures...")
				err = f.CFStringsForImage(image.Name)
				if err != nil {
					return errors.Wrapf(err, "failed to parse objc cfstrings")
				}
				err = f.MethodsForImage(image.Name)
				if err != nil {
					return errors.Wrapf(err, "failed to parse objc methods")
				}
				err = f.SelectorsForImage(image.Name)
				// _, err = f.AllSelectors(false)
				if err != nil {
					return errors.Wrapf(err, "failed to parse objc selectors")
				}
				err = f.ClassesForImage(image.Name)
				if err != nil {
					return errors.Wrapf(err, "failed to parse objc classes")
				}
			}

			log.Info("Parsing MachO symbol stubs...")
			err = f.ParseSymbolStubs(m)
			if err != nil {
				return errors.Wrapf(err, "failed to parse symbol stubs")
			}

			log.Info("Parsing MachO global offset table...")
			err = f.ParseGOT(m)
			if err != nil {
				return errors.Wrapf(err, "failed to parse GOT")
			}

			var funcASM string
			var prevInstruction arm64.Instruction

			for i := range arm64.Disassemble(bytes.NewReader(data), arm64.Options{StartAddress: int64(symAddr)}) {

				if i.Error != nil {
					fmt.Println(i.StrRepr)
					continue
				}

				opStr := i.Instruction.OpStr()

				// check for start of a new function
				if yes, fname := f.IsFunctionStart(starts, i.Instruction.Address(), demangleFlag); yes {
					if len(fname) > 0 {
						funcASM += fmt.Sprintf("\n%s:\n", fname)
						// fmt.Printf("\n%s:\n", fname)
					} else {
						// fmt.Printf("\nfunc_%x:\n", i.Instruction.Address())
						funcASM += fmt.Sprintf("\nfunc_%x:\n", i.Instruction.Address())
					}
				}

				// lookup adrp/ldr or add address as a cstring or symbol name
				operation := i.Instruction.Operation().String()
				if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
					operands := i.Instruction.Operands()
					if operands != nil && prevInstruction.Operands() != nil {
						adrpRegister := prevInstruction.Operands()[0].Reg[0]
						adrpImm := prevInstruction.Operands()[1].Immediate
						if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
							adrpImm += operands[1].Immediate
						} else if operation == "add" && adrpRegister == operands[1].Reg[0] {
							adrpImm += operands[2].Immediate
						}
						// markup disassemble with label comment
						symName := f.FindSymbol(adrpImm, demangleFlag)
						if len(symName) > 0 {
							opStr += fmt.Sprintf(" ; %s", symName)
						} else {
							cstr, err := f.IsCString(m, adrpImm)
							if err == nil {
								if len(cstr) > 200 {
									opStr += fmt.Sprintf(" ; %#v...", cstr[:200])
								} else {
									opStr += fmt.Sprintf(" ; %#v", cstr)
								}
							}
						}
					}

				} else if i.Instruction.Group() == arm64.GROUP_BRANCH_EXCEPTION_SYSTEM { // check if branch location is a function
					operands := i.Instruction.Operands()
					if operands != nil && operands[0].OpClass == arm64.LABEL {
						symName := f.FindSymbol(operands[0].Immediate, demangleFlag)
						if len(symName) > 0 {
							opStr = fmt.Sprintf("\t%s", symName)
						}
					}
				} else if i.Instruction.Group() == arm64.GROUP_DATA_PROCESSING_IMM || i.Instruction.Group() == arm64.GROUP_LOAD_STORE {
					operation := i.Instruction.Operation()
					if operation == arm64.ARM64_LDR || operation == arm64.ARM64_ADR {
						operands := i.Instruction.Operands()
						if operands[1].OpClass == arm64.LABEL {
							symName := f.FindSymbol(operands[1].Immediate, demangleFlag)
							if len(symName) > 0 {
								opStr += fmt.Sprintf(" ; %s", symName)
							}
						}
					}
				}

				// fmt.Printf("%#08x:  %s\t%s%s%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), pad(10-len(i.Instruction.Operation().String())), opStr)
				funcASM += fmt.Sprintf("%#08x:  %s\t%s%s%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), pad(10-len(i.Instruction.Operation().String())), opStr)
				prevInstruction = *i.Instruction
			}

			err = quick.Highlight(os.Stdout, funcASM, "asm", "terminal256", "nord")
			// err = quick.Highlight(os.Stdout, funcASM, "s", "html", "paraiso-dark")
			if err != nil {
				return err
			}

			return nil
		}

		return fmt.Errorf("you must supply a cache and a symbol to disassemble")
	},
}
