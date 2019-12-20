/*
Copyright © 2019 blacktop

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
	"os"
	"reflect"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/macho"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(machoCmd)
}

func examiner(t reflect.Type, depth int) {
	fmt.Println(strings.Repeat("\t", depth), "Type is", t.Name(), "and kind is", t.Kind())
	switch t.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Ptr, reflect.Slice:
		fmt.Println(strings.Repeat("\t", depth+1), "Contained type:")
		examiner(t.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fmt.Println(strings.Repeat("\t", depth+1), "Field", i+1, "name is", f.Name, "type is", f.Type.Name(), "and kind is", f.Type.Kind())
			if f.Tag != "" {
				fmt.Println(strings.Repeat("\t", depth+2), "Tag is", f.Tag)
				fmt.Println(strings.Repeat("\t", depth+2), "tag1 is", f.Tag.Get("tag1"), "tag2 is", f.Tag.Get("tag2"))
			}
		}
	}
}

// machoCmd represents the macho command
var machoCmd = &cobra.Command{
	Use:   "macho <macho_file>",
	Short: "Parse a MachO file",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		if _, err := os.Stat(args[0]); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(args[0])
		if err != nil {
			return err
		}

		fmt.Println("Type:", m.Type.String())
		fmt.Println("CPU:", m.Cpu.String())
		fmt.Println("Flags:", m.FileHeader.Flags.String())
		for _, sym := range m.Symtab.Syms {
			fmt.Printf("0x%016X %s\n", sym.Value, sym.Name)
		}
		fmt.Println("LOADS:", m.FileHeader.Ncmd)
		fmt.Println("=====")
		for idx, l := range m.Loads {
			rf := reflect.TypeOf(l)
			if rf != nil {
				if rf.Elem().Kind() != reflect.Struct {
					log.Error("did not get expected type of struct")
					examiner(rf, 0)
				}
				load := rf.Elem()
				fmt.Println(idx+1, ")", load.Name())
				switch load.Name() {
				case "Dylib":
					examiner(load, 1)
				case "DylibID":
					examiner(load, 1)
				case "WeakDylib":
					// examiner(load, 1)
					// lVal := reflect.ValueOf(load)
					for i := 0; i < load.NumField(); i++ {
						f := load.Field(i)
						if strings.EqualFold(f.Name, "Name") {
							// fVal := reflect.ValueOf(&f)
							fmt.Printf("%+v", load)
						}
					}
					// val := reflect.ValueOf(load).Elem()

					// for i := 0; i < val.NumField(); i++ {
					// 	valueField := val.Field(i)
					// 	typeField := val.Type().Field(i)
					// 	tag := typeField.Tag

					// 	fmt.Printf("Field Name: %s,\t Field Value: %v,\t Tag Value: %s\n", typeField.Name, valueField.Interface(), tag.Get("tag_name"))
					// }
					// var dd macho.Dyl
					// d := reflect.TypeOf(macho.DylibID)
					// dd := load.(macho.DylibID)
				}
				// if strings.Contains(rf.Elem().Name(), "Dylib") {
				// 	for i := 0; i < rf.Elem().NumField(); i++ {
				// 		f := rf.Elem().Field(i)
				// 		fmt.Println(f.Name)
				// 	}
				// }
			}
		}

		return nil
	},
}
