package appstore

import (
	"crypto/tls"
	"encoding/json"
	"fmt"

	"net/http"
	"net/url"
	"strings"

	"github.com/blacktop/ipsw/internal/download"
)

type CustomerReview struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		Rating    int    `json:"rating"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		Reviewer  string `json:"reviewerNickname"`
		Created   Date   `json:"createdDate"`
		Territory string `json:"territory"`
	} `json:"attributes"`
	Relationships struct {
		Response struct {
			Data *struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
			Links Links `json:"links"`
		} `json:"response"`
	} `json:"relationships"`
	Links Links `json:"links"`
}

type CustomerReviewResponse struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		Body         string `json:"responseBody"`
		LastModified Date   `json:"lastModifiedDate"`
		State        string `json:"string"`
	} `json:"attributes"`
	Relationships struct {
		Response struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"response"`
	} `json:"relationships"`
	Links Links `json:"links"`
}

type ReviewsListResponse struct {
	Reviews   []CustomerReview         `json:"data"`
	Responses []CustomerReviewResponse `json:"included"`
	Links     Links                    `json:"links"`
	Meta      Meta                     `json:"meta"`
}

// GetReviews returns a list of reviews.
func (as *AppStore) GetReviews(appID string) (ReviewsListResponse, error) {
	nilResponse := ReviewsListResponse{}

	if err := as.createToken(defaultJWTLife); err != nil {
		return nilResponse, fmt.Errorf("failed to create token: %v", err)
	}

	queryParams := url.Values{}
	queryParams.Add("include", "response")
	queryParams.Add("sort", "-createdDate")
	url := fmt.Sprintf("https://api.appstoreconnect.apple.com/v1/apps/%s/customerReviews?%s", appID, queryParams.Encode())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nilResponse, fmt.Errorf("failed to create http GET request: %v", err)
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
		return nilResponse, fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var eresp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&eresp); err != nil {
			return nilResponse, fmt.Errorf("failed to JSON decode http response: %v", err)
		}
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return nilResponse, fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	// For debugging, print the response body
	// body, _ := io.ReadAll(resp.Body)
	// return nil, fmt.Errorf("%s", body)

	var reviewsResponse ReviewsListResponse
	if err := json.NewDecoder(resp.Body).Decode(&reviewsResponse); err != nil {
		return nilResponse, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return reviewsResponse, nil
}
