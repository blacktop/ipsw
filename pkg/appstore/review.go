package appstore

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/blacktop/ipsw/internal/download"
)

type Review struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		Rating      int    `json:"rating"`
		Title       string `json:"title"`
		Body 		string `json:"body"`
		Reviewer    string `json:"reviewerNickname"`
		Created     Date   `json:"createdDate"`
		Territory   string `json:"territory"`
	} `json:"attributes"`
	Relationships struct {
		Response struct {
			Links Links `json:"links"`
		} `json:"response"`
	} `json:"relationships"`
	Links Links `json:"links"`
}

type ReviewsResponse struct {
	Data  []Review `json:"data"`
	Links Links    `json:"links"`
	Meta  Meta     `json:"meta"`
}

// GetReviews returns a list of reviews.
func (as *AppStore) GetReviews(appID string) ([]Review, error) {

	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	url := fmt.Sprintf("https://api.appstoreconnect.apple.com/v1/apps/%s/customerReviews", appID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+as.token)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(as.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: as.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var eresp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&eresp); err != nil {
			return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
		}
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	var reviewsResponseList ReviewsResponse
	if err := json.NewDecoder(resp.Body).Decode(&reviewsResponseList); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return reviewsResponseList.Data, nil
}
