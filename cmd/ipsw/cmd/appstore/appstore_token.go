/*
Copyright © 2024 blacktop

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
package appstore

import (
	"fmt"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ASTokenCmd represents the appstore token command
var ASTokenCmd = &cobra.Command{
	Use:           "token",
	Short:         "Generate JWT for AppStore Connect API",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")
		// flags
		lifetime := viper.GetDuration("appstore.token.lifetime")
		// parent flags
		viper.BindPFlag("appstore.p8", cmd.Flags().Lookup("p8"))
		viper.BindPFlag("appstore.iss", cmd.Flags().Lookup("iss"))
		viper.BindPFlag("appstore.kid", cmd.Flags().Lookup("kid"))
		// Validate flags
		if viper.GetString("appstore.p8") == "" || viper.GetString("appstore.iss") == "" || viper.GetString("appstore.kid") == "" {
			return fmt.Errorf("you must provide --p8, --iss and --kid")
		}
		if lifetime > 20*time.Minute {
			return fmt.Errorf("lifetime cannot be more than 20m")
		}

		as := appstore.NewAppStore(
			viper.GetString("appstore.p8"),
			viper.GetString("appstore.iss"),
			viper.GetString("appstore.kid"),
			"",
		)

		jwt, err := as.GenerateToken(lifetime)
		if err != nil {
			return fmt.Errorf("failed to generate token: %v", err)
		}

		fmt.Println(jwt)

		return nil
	},
}

func init() {
	AppstoreCmd.AddCommand(ASTokenCmd)
	ASTokenCmd.Flags().DurationP("lifetime", "l", 5*time.Minute, "Lifetime of JWT (max: 20m)")
	ASTokenCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		AppstoreCmd.PersistentFlags().MarkHidden("jwt")
		c.Parent().HelpFunc()(c, s)
	})
	viper.BindPFlag("appstore.token.lifetime", ASTokenCmd.Flags().Lookup("lifetime"))
}
