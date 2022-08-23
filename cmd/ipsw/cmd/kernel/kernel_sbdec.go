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
package kernel

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/sandbox"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(sbdecCmd)
	sbdecCmd.Flags().BoolP("diff", "f", false, "Diff two kernel's sandbox profiles")
	sbdecCmd.Flags().BoolP("dump", "d", false, "Dump sandbox profile data")
	sbdecCmd.Flags().BoolP("profile", "p", false, "Decompile sandbox profile")
	sbdecCmd.Flags().BoolP("protobox", "b", false, "Decompile sandbox protobox collection")
	sbdecCmd.Flags().BoolP("list-profiles", "l", false, "List sandbox collection profiles")
	sbdecCmd.Flags().StringP("input", "i", "", "Input sandbox profile binary file")

	viper.BindPFlag("kernel.sbdec.diff", sbdecCmd.Flags().Lookup("diff"))
	viper.BindPFlag("kernel.sbdec.dump", sbdecCmd.Flags().Lookup("dump"))
	viper.BindPFlag("kernel.sbdec.profile", sbdecCmd.Flags().Lookup("profile"))
	viper.BindPFlag("kernel.sbdec.protobox", sbdecCmd.Flags().Lookup("protobox"))
	viper.BindPFlag("kernel.sbdec.list-profiles", sbdecCmd.Flags().Lookup("list-profiles"))
	viper.BindPFlag("kernel.sbdec.input", sbdecCmd.Flags().Lookup("input"))

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

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		kcPath := filepath.Clean(args[0])

		m, err := macho.Open(kcPath)
		if err != nil {
			return fmt.Errorf("failed to open %s: %v", kcPath, err)
		}
		defer m.Close()

		conf := &sandbox.Config{
			Kernel:         m,
			ProfileBinPath: viper.GetString("kernel.sbdec.input"), // supply your own sandbox profile data blob
		}

		if m.FileTOC.FileHeader.Type == types.FileSet {
			fixups := make(map[uint64]uint64)
			if m.HasFixups() {
				dcf, err := m.DyldChainedFixups()
				if err != nil {
					return err
				}
				for _, start := range dcf.Starts {
					if start.PageStarts != nil {
						for _, fixup := range start.Fixups {
							switch f := fixup.(type) {
							case fixupchains.Rebase:
								fixups[f.Raw()] = uint64(f.Offset()) + m.GetBaseAddress()
							}
						}
					}
				}
			}
			conf.Kernel = m
			conf.Fixups = fixups
		}

		sb, err := sandbox.NewSandbox(conf)
		if err != nil {
			return err
		}

		if viper.GetBool("kernel.sbdec.dump") { // DUMP OUT PROFILE DATA BLOBS
			if dat, err := sb.GetCollectionData(); err != nil {
				return fmt.Errorf("failed to get sandbox collection data: %v", err)
			} else {
				sbcpath := filepath.Join(filepath.Dir(kcPath), "sandbox_collection.bin")
				log.Infof("Creating %s...", sbcpath)
				if err := os.WriteFile(sbcpath, dat, 0755); err != nil {
					return fmt.Errorf("failed to write sandbox collection data: %v", err)
				}
			}
			if dat, err := sb.GetProtoboxCollectionData(); err != nil {
				return fmt.Errorf("failed to get sandbox protobox collection data: %v", err)
			} else {
				sbcpath := filepath.Join(filepath.Dir(kcPath), "sandbox_protobox.bin")
				log.Infof("Creating %s...", sbcpath)
				if err := os.WriteFile(sbcpath, dat, 0755); err != nil {
					return fmt.Errorf("failed to write sandbox protobox collection data: %v", err)
				}
			}
			if dat, err := sb.GetPlatformProfileData(); err != nil {
				return fmt.Errorf("failed to get sandbox platform profile data: %v", err)
			} else {
				sbppath := filepath.Join(filepath.Dir(kcPath), "sandbox_profile.bin")
				log.Infof("Creating %s...", sbppath)
				if err := os.WriteFile(sbppath, dat, 0755); err != nil {
					return fmt.Errorf("failed to write sandbox platform profile data: %v", err)
				}
			}
			return nil
		}

		if viper.GetBool("kernel.sbdec.profile") { // PARSE DEFAULT SANDBOX PROFILE
			if err := sb.ParseSandboxProfile(); err != nil {
				return fmt.Errorf("failed parsing sandbox profile: %s", err)
			}

			for idx, op := range sb.OpNodes {
				if err := sb.ParseOperation(&op); err != nil {
					// return fmt.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
					log.Errorf("failed to parse operation for node %s: %v", op, err)
					continue
				}
				fmt.Println(op.String(fmt.Sprintf("op_node_%d", idx), 0))
			}

			defaultOp := sandbox.TerminalNode(sb.OpNodes[0].Node)

			for idx, op := range sb.Profiles[0].Operands {
				if sb.Operations[idx] != "default" && sb.OpNodes[op].Node.IsTerminal() {
					if sandbox.TerminalNode(sb.OpNodes[op].Node).Decision() == defaultOp.Decision() {
						continue
					}
				}
				if err := sb.ParseOperation(&sb.OpNodes[op]); err != nil {
					// return fmt.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
					log.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
					continue
				}
				fmt.Println(sb.OpNodes[op].String(sb.Operations[idx], 0))
				if sb.OpNodes[op].Match > 0 {
					if err := sb.ParseOperation(&sb.OpNodes[sb.OpNodes[op].MatchOffset]); err != nil {
						log.Errorf("failed to parse match operation node %s: %v", sb.OpNodes[op].Match, err)
					}
					fmt.Println("MATCH:", sb.OpNodes[sb.OpNodes[op].MatchOffset].String(sb.Operations[idx], 1))
				}
				if sb.OpNodes[op].Unmatch > 0 {
					if err := sb.ParseOperation(&sb.OpNodes[sb.OpNodes[op].UnmatchOffset]); err != nil {
						log.Errorf("failed to parse unmatch operation node %s: %v", sb.OpNodes[op].Unmatch, err)
					}
					fmt.Println("UNMATCH:", sb.OpNodes[sb.OpNodes[op].UnmatchOffset].String(sb.Operations[idx], 1))
				}
			}
			return nil
		} else if viper.GetBool("kernel.sbdec.protobox") { // PARSE PROTOBOX COLLECTION
			if _, err := sb.GetProtoboxCollectionData(); err != nil {
				return fmt.Errorf("failed to get sandbox protoboxcollection data: %v", err)
			}
			if err := sb.ParseProtoboxCollection(); err != nil {
				return fmt.Errorf("failed parsing sandbox protobox collection: %s", err)
			}
		} else { // PARSE BUILTIN COLLECTION
			if _, err := sb.GetCollectionData(); err != nil {
				return fmt.Errorf("failed to get sandbox collection data: %v", err)
			}
			if err := sb.ParseSandboxCollection(); err != nil {
				return fmt.Errorf("failed parsing sandbox collection: %s", err)
			}

			// for idx, ent := range sb.Entitlements {
			// 	o, err := sb.ParseOperation(fmt.Sprintf("ent_%d", idx), sb.OpNodes[ent])
			// 	if err != nil {
			// 		return err
			// 	}
			// 	fmt.Println(o.String(0))
			// 	if o.Match > 0 {
			// 		match, err := sb.ParseOperation(o.Name, o.Match)
			// 		if err != nil {
			// 			log.Errorf("failed to parse match operation node %s: %v", o.Match, err)
			// 		}
			// 		fmt.Println("MATCH:", match.String(1))
			// 	}
			// 	if o.Unmatch > 0 {
			// 		unmatch, err := sb.ParseOperation(o.Name, o.Unmatch)
			// 		if err != nil {
			// 			log.Errorf("failed to parse unmatch operation node %s: %v", o.Unmatch, err)
			// 		}
			// 		fmt.Println("UNMATCH:", unmatch.String(1))
			// 	}
			// }
		}

		// for idx, pol := range sb.Policies {
		// 	o, err := sb.ParseOperation(fmt.Sprintf("policy_%d", idx), sb.OpNodes[pol])
		// 	if err != nil {
		// 		return err
		// 	}
		// 	fmt.Println(o.String(0))
		// 	if o.Match > 0 {
		// 		match, err := sb.ParseOperation(o.Name, o.Match)
		// 		if err != nil {
		// 			log.Errorf("failed to parse match operation node %s: %v", o.Match, err)
		// 		}
		// 		fmt.Println("MATCH:", match.String(1))
		// 	}
		// 	if o.Unmatch > 0 {
		// 		unmatch, err := sb.ParseOperation(o.Name, o.Unmatch)
		// 		if err != nil {
		// 			log.Errorf("failed to parse unmatch operation node %s: %v", o.Unmatch, err)
		// 		}
		// 		fmt.Println("UNMATCH:", unmatch.String(1))
		// 	}
		// }

		// for idx, unk := range sb.Unknown {
		// 	o, err := sb.ParsePolicy(unk)
		// 	if err != nil {
		// 		log.Error(err.Error())
		// 		continue
		// 	}
		// 	fmt.Printf("\n\nUnknown (%d)\n", idx)
		// 	fmt.Println(o.String(0))
		// 	if o.Match > 0 {
		// 		match, err := sb.ParseOperation(o.Name, o.Match)
		// 		if err != nil {
		// 			log.Errorf("failed to parse match operation node %s: %v", o.Match, err)
		// 		}
		// 		fmt.Println("MATCH:", match.String(1))
		// 	}
		// 	if o.Unmatch > 0 {
		// 		unmatch, err := sb.ParseOperation(o.Name, o.Unmatch)
		// 		if err != nil {
		// 			log.Errorf("failed to parse unmatch operation node %s: %v", o.Unmatch, err)
		// 		}
		// 		fmt.Println("UNMATCH:", unmatch.String(1))
		// 	}
		// }

		if viper.GetBool("kernel.sbdec.list-profiles") {
			fmt.Println("PROFILES")
			fmt.Println("========")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, prof := range sb.Profiles {
				fmt.Fprintf(w, "%s\tflags=%#x\tpolicy=%d\n", prof.Name, prof.Flags, prof.PolicyIndex)
			}
			w.Flush()
			return nil
		}

		if viper.GetBool("kernel.sbdec.diff") {
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
			if len(args) > 1 { // DECOMPILE SINGLE PROFILE

				// for _, prof := range sb.Profiles {
				// 	fmt.Println(prof.Name)
				// }

				// for _, op := range sb.OpNodes {
				// 	if op.IsNonTerminal() {
				// 		fmt.Println(op)
				// 	}
				// }

				prof, err := sb.GetProfile(args[1])
				if err != nil {
					return err
				}
				fmt.Println(prof)

				defaultOp := sandbox.TerminalNode(sb.OpNodes[prof.Operands[0]].Node)

				for idx, op := range prof.Operands {
					if sb.Operations[idx] != "default" && sb.OpNodes[op].Node.IsTerminal() {
						if sandbox.TerminalNode(sb.OpNodes[op].Node).Decision() == defaultOp.Decision() {
							continue
						}
					}
					if err := sb.ParseOperation(&sb.OpNodes[op]); err != nil {
						// return fmt.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
						log.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
						continue
					}
					fmt.Println(sb.OpNodes[op].String(sb.Operations[idx], 0))
					if sb.OpNodes[op].Match > 0 {
						if err := sb.ParseOperation(&sb.OpNodes[sb.OpNodes[op].MatchOffset]); err != nil {
							log.Errorf("failed to parse match operation node %s: %v", sb.OpNodes[op].Match, err)
						}
						fmt.Println("MATCH:", sb.OpNodes[sb.OpNodes[op].MatchOffset].String(sb.Operations[idx], 1))
					}
					if sb.OpNodes[op].Unmatch > 0 {
						if err := sb.ParseOperation(&sb.OpNodes[sb.OpNodes[op].UnmatchOffset]); err != nil {
							log.Errorf("failed to parse unmatch operation node %s: %v", sb.OpNodes[op].Unmatch, err)
						}
						fmt.Println("UNMATCH:", sb.OpNodes[sb.OpNodes[op].UnmatchOffset].String(sb.Operations[idx], 1))
					}
				}

				// rindex := 2 // ^gdt-[A-Za-z0-9]+-(c|s)$
				// rindex := 6 // ^/private/var/(((mobile|euser[0-9]+)|[-0-9A-F]+)|Users/[^/]+)/Media/([^/]+/)?iTunes_Control/iTunes$
				// rindex := 7
				// rindex := 229
				// if err := sb.Regexes[rindex].Dump("/tmp/regex"); err != nil {
				// 	return fmt.Errorf("failed to dump regex: %v", err)
				// }
				// nfa, err := sb.Regexes[rindex].NFA()
				// if err != nil {
				// 	return err
				// }
				// fmt.Printf("%v\n", sb.Regexes[rindex].Data)
				// rx, err := nfa.ToRegex()
				// if err != nil {
				// 	return err
				// }
				// fmt.Println(rx)

				// for idx, re := range sb.Regexes {
				// 	nfa, err := re.NFA()
				// 	if err != nil {
				// 		return err
				// 	}
				// 	rx, err := nfa.ToRegex()
				// 	if err != nil {
				// 		return err
				// 	}
				// 	if len(rx) > 0 {
				// 		// fmt.Printf("regex %d)\n%s\n", idx, rx)
				// 	} else {
				// 		log.Errorf("failed to parse regex %d", idx)
				// 	}
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
				// 	err = os.WriteFile(regexPath, re.Data, 0755)
				// 	if err != nil {
				// 		return err
				// 	}
				// }

			} else { // DECOMPILE ALL PROFILES
				var max int
				for _, prof := range sb.Profiles {
					fmt.Println(prof)
					// if prof.Name == "BTServer" {
					// 	fmt.Println("SKIPPING>>>>>>>>")
					// 	continue
					// }
					// fmt.Println("DUMP SIMPLE GRAPHS")
					// defaultOp2 := sandbox.TerminalNode(sb.OpNodes[prof.Operands[0]])
					// for idx, op := range prof.Operands {
					// 	if sb.Operations[idx] != "default" && sb.OpNodes[op].IsTerminal() {
					// 		if sandbox.TerminalNode(sb.OpNodes[op]).Decision() == defaultOp2.Decision() {
					// 			continue
					// 		}
					// 	}
					// 	og, err := sb.CreateOperationGraph(sb.Operations[idx], sb.OpNodes[op])
					// 	if err != nil {
					// 		return err
					// 	}
					// 	depth := og.Depth()
					// 	if depth <= 10 {
					// 		fmt.Printf("DEPTH: %d %s\n", depth, og.String(0))
					// 	} else {
					// 		fmt.Printf("DEPTH: %d (%s\n", depth, og.Name)
					// 		fmt.Println("<SNIP>")
					// 	}
					// 	if depth > max {
					// 		fmt.Printf("NEW max %d found in %s for %s\n", depth, prof.Name, og.Name)
					// 		max = depth
					// 	}
					// 	og = nil
					// }
					// continue
					defaultOp := sandbox.TerminalNode(sb.OpNodes[0].Node)

					for idx, op := range prof.Operands {
						if sb.Operations[idx] != "default" && sb.OpNodes[op].Node.IsTerminal() {
							if sandbox.TerminalNode(sb.OpNodes[op].Node).Decision() == defaultOp.Decision() {
								continue
							}
						}
						if err := sb.ParseOperation(&sb.OpNodes[op]); err != nil {
							// return fmt.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
							log.Errorf("failed to parse operation %s for node %s: %s", sb.Operations[idx], sb.OpNodes[op], err)
							continue
						}
						fmt.Println(sb.OpNodes[op].String(sb.Operations[idx], 0))
					}
				}
				fmt.Println("MAX: ", max)
			}
		}

		return nil
	},
}
