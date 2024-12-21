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
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

func init() {
	ASReviewCmd.AddCommand(ASReviewListCmd)

	ASReviewListCmd.Flags().String("id", "", "App ID")
	viper.BindPFlag("appstore.review.ls.id", ASReviewListCmd.Flags().Lookup("id"))
}

// ASReviewListCmd represents the appstore review ls command
var ASReviewListCmd = &cobra.Command{
	Use:           "ls",
	Short:         "List reviews",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// parent flags
		viper.BindPFlag("appstore.p8", cmd.Flags().Lookup("p8"))
		viper.BindPFlag("appstore.iss", cmd.Flags().Lookup("iss"))
		viper.BindPFlag("appstore.kid", cmd.Flags().Lookup("kid"))
		viper.BindPFlag("appstore.jwt", cmd.Flags().Lookup("jwt"))
		// flags
		id := viper.GetString("appstore.review.ls.id")
		// Validate flags
		if (viper.GetString("appstore.p8") == "" || viper.GetString("appstore.iss") == "" || viper.GetString("appstore.kid") == "") && viper.GetString("appstore.jwt") == "" {
			return fmt.Errorf("you must provide (--p8, --iss and --kid) OR --jwt")
		}
		if id == "" {
			return fmt.Errorf("you must provide --id")
		}

		as := appstore.NewAppStore(
			viper.GetString("appstore.p8"),
			viper.GetString("appstore.iss"),
			viper.GetString("appstore.kid"),
			viper.GetString("appstore.jwt"),
		)

		reviewsResponse, err := as.GetReviews(id)
		if err != nil {
			return err
		}

		// create a map of CustomerReviewResponses by id
		responsesById := make(map[string]appstore.CustomerReviewResponse)
		for _, response := range reviewsResponse.Responses {
			responsesById[response.ID] = response
		}

		// sort reviews by Created descending
		reviews := reviewsResponse.Reviews
		sort.Slice(reviews, func(i, j int) bool {
			return reviews[j].Attributes.Created.Before(reviews[i].Attributes.Created)
		})

		// display reviews in a format useful for customer service
		fmt.Printf("Reviews\n")
		fmt.Printf("%d reviews\n", len(reviews))
		fmt.Printf("%d responses\n", len(responsesById))
		for idx, review := range reviews {
			date := review.Attributes.Created.Format("Jan _2 2006")
			stars := strings.Repeat("★", review.Attributes.Rating)
			hrule := strings.Repeat("-", 16)
			fmt.Printf("\n%s\n[%3d]\n%s [%-5s] by %s\n", hrule, idx, date, stars, review.Attributes.Reviewer)
			fmt.Printf("%s\n\n", review.Attributes.Title)

			responseData := review.Relationships.Response.Data
			if responseData != nil {
				fmt.Printf("    (responded)\n")
				// fmt.Printf("    response: %v\n", responseId)
			} else {
				fmt.Printf("    %s\n", review.Attributes.Body)
			}
		}
		ratingsUrl := fmt.Sprintf("https://appstoreconnect.apple.com/apps/%s/distribution/activity/ios/ratingsResponses", id)
		fmt.Printf("\nTo respond, visit %s", ratingsUrl)

		return nil
	},
}
