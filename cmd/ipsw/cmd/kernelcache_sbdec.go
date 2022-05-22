//go:build cgo

/*
Copyright © 2018-2022 blacktop

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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/sandbox"
	"github.com/spf13/cobra"
)

func init() {
	kernelcacheCmd.AddCommand(sbdecCmd)
	sbdecCmd.Flags().BoolP("diff", "f", false, "Diff two kernel's sandbox profiles")
	sbdecCmd.Flags().BoolP("dump", "d", false, "Dump sandbox profile data")
	sbdecCmd.Flags().BoolP("profile", "p", false, "Decompile sandbox profile")
	sbdecCmd.Flags().StringP("input", "i", "", "Input sandbox profile binary file")
	sbdecCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// sbdecCmd represents the kernel sbdec command
var sbdecCmd = &cobra.Command{
	Use:           "sbdec",
	Short:         "🚧 [WIP] Decompile Sandbox Profile",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		diff, _ := cmd.Flags().GetBool("diff")
		dump, _ := cmd.Flags().GetBool("dump")
		decProfile, _ := cmd.Flags().GetBool("profile")
		input, _ := cmd.Flags().GetString("input")

		kcPath := filepath.Clean(args[0])

		if _, err := os.Stat(kcPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(kcPath)
		if err != nil {
			return err
		}
		defer m.Close()

		sb, err := sandbox.NewSandbox(&sandbox.Config{Kernel: m, ProfileBinPath: input})
		if err != nil {
			return err
		}

		if dump {
			if dat, err := sb.GetPlatformProfileData(); err != nil {
				return fmt.Errorf("failed to get sandbox platform profile data: %v", err)
			} else {
				sbppath := filepath.Join(filepath.Dir(kcPath), "sandbox_profile.bin")
				log.Infof("Creating %s...", sbppath)
				if err := ioutil.WriteFile(sbppath, dat, 0755); err != nil {
					return fmt.Errorf("failed to write sandbox platform profile data: %v", err)
				}
			}
			if dat, err := sb.GetCollectionData(); err != nil {
				return fmt.Errorf("failed to get sandbox collection data: %v", err)
			} else {
				sbcpath := filepath.Join(filepath.Dir(kcPath), "sandbox_collection.bin")
				log.Infof("Creating %s...", sbcpath)
				if err := ioutil.WriteFile(sbcpath, dat, 0755); err != nil {
					return fmt.Errorf("failed to write sandbox collection data: %v", err)
				}
			}
		}

		if len(input) > 0 {
			if err := sb.ParseSandboxProfile(); err != nil {
				return fmt.Errorf("failed parsing sandbox profile: %s", err)
			}

			if len(sb.Regexes) > 0 {
				re, err := sb.Regexes[0].NFA()
				if err != nil {
					return err
				}
				fmt.Println(re)
			}

			defaultOp := sandbox.TerminalNode(sb.OpNodes[sb.Profiles[0].Operands[0]])

			for idx, op := range sb.Profiles[0].Operands {
				if sb.Operations[idx] != "default" && sb.OpNodes[op].IsTerminal() {
					if sandbox.TerminalNode(sb.OpNodes[op]).Type() == defaultOp.Type() {
						continue
					}
				}
				o, err := sandbox.ParseOperation(sb, sb.OpNodes[op])
				if err != nil {
					// return fmt.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
					log.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
					continue
				}
				fmt.Println(o.String(sb.Operations[idx]))
			}

			return nil
		}

		if decProfile {
			if err := sb.ParseSandboxProfile(); err != nil {
				return fmt.Errorf("failed parsing sandbox profile: %s", err)
			}

			defaultOp := sandbox.TerminalNode(sb.OpNodes[sb.Profiles[0].Operands[0]])

			for idx, op := range sb.Profiles[0].Operands {
				if sb.Operations[idx] != "default" && sb.OpNodes[op].IsTerminal() {
					if sandbox.TerminalNode(sb.OpNodes[op]).Type() == defaultOp.Type() {
						continue
					}
				}
				o, err := sandbox.ParseOperation(sb, sb.OpNodes[op])
				if err != nil {
					// return fmt.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
					log.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
					continue
				}
				fmt.Println(o.String(sb.Operations[idx]))
			}

			return nil
		} else {
			if err := sb.ParseSandboxCollection(); err != nil {
				return fmt.Errorf("failed parsing sandbox collection: %s", err)
			}
		}

		if diff {
			if len(args) < 3 {
				return fmt.Errorf("please provide two kernelcache files to diff AND a profile name to compare")
			}

			kcPath2 := filepath.Clean(args[1])

			if _, err := os.Stat(kcPath2); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", args[1])
			}

			// m2, err := macho.Open(kcPath2)
			// if err != nil {
			// 	return err
			// }
			// defer m.Close()

			// sb2, err := sandbox.NewSandbox(m2)
			// if err != nil {
			// 	return err
			// }

			panic("diffing is not implemented yet")
		} else {
			if len(args) > 1 { // decompile single profile

				// for _, op := range sb.OpNodes {
				// 	if op.IsTerminal() {
				// 		fmt.Println(op)
				// 	}
				// }

				prof, err := sb.GetProfile(args[1])
				if err != nil {
					return err
				}
				fmt.Println(prof)

				defaultOp := sandbox.TerminalNode(sb.OpNodes[prof.Operands[0]])

				for idx, op := range prof.Operands {
					if sb.Operations[idx] != "default" && sb.OpNodes[op].IsTerminal() {
						if sandbox.TerminalNode(sb.OpNodes[op]).Type() == defaultOp.Type() {
							continue
						}
					}
					o, err := sandbox.ParseOperation(sb, sb.OpNodes[op])
					// _, err := sandbox.ParseOperation(sb, sb.OpNodes[op])
					if err != nil {
						// return fmt.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
						log.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
						continue
					}
					fmt.Println(o.String(sb.Operations[idx]))
				}

				// rl, err := sb.Regexes[0].Parse()
				// if err != nil {
				// 	return err
				// }

				// if _, err := sb.Regexes[3].NFA(); err != nil {
				// 	return err
				// }

				// sb.Regexes[3].Graph()
				// sb.Regexes[80].Graph()

				// for _, re := range sb.Regexes {
				// 	fmt.Println(re)
				// 	if _, err := re.Graph(); err != nil {
				// 		return err
				// 	}
				// }

				// regexFolder := filepath.Join(filepath.Dir(kcPath), "regex")
				// os.MkdirAll(regexFolder, 0755)
				// for idx, re := range sb.Regexes {
				// 	regexPath := filepath.Join(regexFolder, fmt.Sprintf("regex_%d", idx))
				// 	err = ioutil.WriteFile(regexPath, re.Data, 0755)
				// 	if err != nil {
				// 		return err
				// 	}
				// }

			} else { // decompile all profiles
				for _, prof := range sb.Profiles {
					fmt.Println(prof.Name)
					defaultOp := sandbox.TerminalNode(sb.OpNodes[0])

					for idx, op := range prof.Operands {
						if sb.Operations[idx] != "default" && sb.OpNodes[op].IsTerminal() {
							if sandbox.TerminalNode(sb.OpNodes[op]).Type() == defaultOp.Type() {
								continue
							}
						}
						o, err := sandbox.ParseOperation(sb, sb.OpNodes[op])
						if err != nil {
							// return fmt.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
							log.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
							continue
						}
						fmt.Println(o.String(sb.Operations[idx]))
					}
				}
			}
		}

		return nil
	},
}
