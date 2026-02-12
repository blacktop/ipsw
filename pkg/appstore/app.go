package appstore

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/blacktop/ipsw/internal/download"
)

type subscriptionStatusUrlVersion string

const (
	V1      subscriptionStatusUrlVersion = "V1"
	V2      subscriptionStatusUrlVersion = "V2"
	LowerV1 subscriptionStatusUrlVersion = "v1"
	LowerV2 subscriptionStatusUrlVersion = "v2"
)

type AppAttributes struct {
	BundleID                               string                       `json:"bundleId"`
	Name                                   string                       `json:"name"`
	Locale                                 string                       `json:"primaryLocale"`
	SKU                                    string                       `json:"sku"`
	AvailableInNewTerritories              bool                         `json:"availableInNewTerritories,omitempty"`
	ContentRightsDeclaration               string                       `json:"contentRightsDeclaration"` //  DOES_NOT_USE_THIRD_PARTY_CONTENT, USES_THIRD_PARTY_CONTENT
	IsOrEverWasMadeForKids                 bool                         `json:"isOrEverWasMadeForKids"`
	SubscriptionStatusURL                  string                       `json:"subscriptionStatusUrl"`
	SubscriptionStatusURLForSandbox        string                       `json:"subscriptionStatusUrlForSandbox"`
	SubscriptionStatusURLVersion           subscriptionStatusUrlVersion `json:"subscriptionStatusUrlVersion"`
	SubscriptionStatusURLVersionForSandbox subscriptionStatusUrlVersion `json:"subscriptionStatusUrlVersionForSandbox"`
}

type App struct {
	ID            string        `json:"id"`
	Type          string        `json:"type"` // apps
	Attributes    AppAttributes `json:"attributes"`
	Relationships any           `json:"relationships"`
	Links         Links         `json:"links"`
}

type AppResponse struct {
	Data  App           `json:"data"`
	Links DocumentLinks `json:"links"`
}

type AppsResponse struct {
	Data  []App              `json:"data"`
	Links PagedDocumentLinks `json:"links"`
	Meta  Meta               `json:"meta"`
}

// GetApps returns a list of Apps resources.
func (as *AppStore) GetApps() ([]App, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", appsURL, nil)
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
		var errOut strings.Builder
		for idx, e := range eresp.Errors {
			errOut.WriteString(fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail))
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut.String())
	}

	var apps AppsResponse
	if err := json.NewDecoder(resp.Body).Decode(&apps); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return apps.Data, nil
}
