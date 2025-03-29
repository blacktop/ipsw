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
	"os"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

func init() {
	AppstoreCmd.AddCommand(ASReviewListCmd)

	ASReviewListCmd.Flags().String("id", "", "App ID")
	ASReviewListCmd.Flags().String("after", "", "Only show responses on or after date, e.g. \"2024-12-22\"")
	ASReviewListCmd.Flags().String("since", "", "Only show responses within duration, e.g. \"36h\"")
	viper.BindPFlag("appstore.review-list.id", ASReviewListCmd.Flags().Lookup("id"))
	viper.BindPFlag("appstore.review-list.after", ASReviewListCmd.Flags().Lookup("after"))
	viper.BindPFlag("appstore.review-list.since", ASReviewListCmd.Flags().Lookup("since"))
}

// ASReviewListCmd represents the appstore review command
var ASReviewListCmd = &cobra.Command{
	Use:           "review-list",
	Aliases:       []string{"r"},
	Short:         "List app store reviews",
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
		id := viper.GetString("appstore.review-list.id")
		after := viper.GetString("appstore.review-list.after")
		since := viper.GetString("appstore.review-list.since")
		// Validate flags
		if (viper.GetString("appstore.p8") == "" || viper.GetString("appstore.iss") == "" || viper.GetString("appstore.kid") == "") && viper.GetString("appstore.jwt") == "" {
			return fmt.Errorf("you must provide (--p8, --iss and --kid) OR --jwt")
		}
		if id == "" {
			return fmt.Errorf("you must provide --id")
		}
		if after != "" && since != "" {
			return fmt.Errorf("you cannot specify both `--after` and `--since`")
		}
		afterDate, err := time.Parse("2006-01-02", after)
		if after != "" && err != nil {
			return err
		}
		if since != "" {
			sinceDuration, err := time.ParseDuration(since)
			if err != nil {
				return err
			}
			afterDate = time.Now().Add(-sinceDuration)
		}
		afterOrSinceFlag := after != "" || since != ""

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

		// display reviews in a format useful for customer service
		reviewCount := 0
		responseCount := 0
		for _, review := range reviewsResponse.Reviews {
			if time.Time(review.Attributes.Created).Before(afterDate) {
				break
			}

			// print review summary
			reviewCount += 1
			date := review.Attributes.Created.Format("Jan _2 2006")
			stars := strings.Repeat("★", review.Attributes.Rating)
			hrule := strings.Repeat("-", 19)
			fmt.Printf("\n%s\n%s [%-5s] by %s\n", hrule, date, stars, review.Attributes.Reviewer)
			fmt.Printf("%s\n", review.Attributes.Title)

			// print review body only if we haven't responded
			responseData := review.Relationships.Response.Data
			if responseData != nil {
				responseCount += 1
				response, exists := responsesById[responseData.ID]
				if exists {
					fmt.Printf("    (responded %s)\n", response.Attributes.LastModified.Format("Jan _2 2006"))
				} else {
					fmt.Printf("    (responded)\n")
				}
			} else {
				fmt.Printf("    %s\n", review.Attributes.Body)
			}
		}

		// print summary, if any reviews were found, or if --verbose was specified
		if reviewCount > 0 || viper.GetBool("verbose") {
			if afterOrSinceFlag {
				fmt.Printf("\n%d reviews since %s\n", reviewCount, afterDate.Format("Jan _2 2006 15:04:05"))
			} else {
				fmt.Printf("\n%d reviews\n", reviewCount)
			}
			fmt.Printf("%d responses\n", responseCount)
			ratingsUrl := fmt.Sprintf("https://appstoreconnect.apple.com/apps/%s/distribution/activity/ios/ratingsResponses", id)
			fmt.Printf("\nTo respond, visit %s\n", ratingsUrl)
		}

		// exit 2 if no new reviews, this will aid scripting
		if reviewCount == 0 {
			os.Exit(2)
		}

		return nil
	},
}
