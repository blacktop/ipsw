/*
Copyright © 2018-2024 blacktop

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
package macho

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
)

/*
 * ROADMAP:
 * - [x] add install_name_tool features
 * - [x] add vtool features
 * - [ ] add ability to add arbitrary LCs
 */

func confirm(path string, overwrite bool) bool {
	if overwrite {
		return true
	}
	yes := false
	prompt := &survey.Confirm{
		Message: fmt.Sprintf("You are about to overwrite %s. Continue?", path),
		Default: true,
	}
	survey.AskOne(prompt, &yes)
	return yes
}

func init() {
	MachoCmd.AddCommand(machoPatchCmd)
}

// machoPatchCmd represents the macho patch command
var machoPatchCmd = &cobra.Command{
	Use:     "patch",
	Aliases: []string{"p"},
	Short:   "Patch MachO Load Commands",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
