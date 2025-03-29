package appstore

import (
	"encoding/json"
	"strings"
	"time"
)

const (
	appsURL                 = "https://api.appstoreconnect.apple.com/v1/apps"
	bundleIDsURL            = "https://api.appstoreconnect.apple.com/v1/bundleIds"
	bundleIDCapabilitiesURL = "https://api.appstoreconnect.apple.com/v1/bundleIdCapabilities"
	certificatessURL        = "https://api.appstoreconnect.apple.com/v1/certificates"
	devicesURL              = "https://api.appstoreconnect.apple.com/v1/devices"
	profilesURL             = "https://api.appstoreconnect.apple.com/v1/profiles"
)

type Errors struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Source any    `json:"source"`
}

type ErrorResponse struct {
	Errors []Errors `json:"errors"`
}

type Links struct {
	Self    string `json:"self"`
	Related string `json:"related,omitempty"`
}

type DocumentLinks struct {
	Self string `json:"self"`
}

type ResourceLinks struct {
	Self string `json:"self"`
}

type PagedDocumentLinks struct {
	First string `json:"first"`
	Next  string `json:"next"`
	Self  string `json:"self"`
}

type Meta struct {
	Paging struct {
		Total int `json:"total"` // The total number of resources matching your request.
		Limit int `json:"limit"` // The maximum number of resources to return per page, from 0 to 200.
	} `json:"paging"`
}

type Date time.Time

func (d *Date) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), "\"")
	if s == "null" {
		return nil
	}
	t, err := time.Parse("2006-01-02T15:04:05.000+00:00", s)
	if err != nil {
		// If that fails, try parsing without milliseconds
		t, err = time.Parse("2006-01-02T15:04:05-07:00", s)
		if err != nil {
			return err
		}
	}
	*d = Date(t)
	return nil
}
func (d Date) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(d))
}
func (d Date) Format(s string) string {
	t := time.Time(d)
	return t.Format(s)
}
func (d Date) Before(d2 Date) bool {
	return time.Time(d).Before(time.Time(d2))
}

type AppStore struct {
	P8    string
	Iss   string
	Kid   string
	token string

	Proxy    string
	Insecure bool

	conf *ProvisionSigningFilesConfig
}

// NewAppStore creates a new App Store Connect API object
func NewAppStore(p8, iss, kid, jwt string) *AppStore {
	return &AppStore{
		P8:    p8,
		Iss:   iss,
		Kid:   kid,
		token: jwt,
	}
}
