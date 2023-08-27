package appstore

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/download"
)

type Certificate struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		SerialNumber       string `json:"serialNumber"`
		CertificateContent string `json:"certificateContent"`
		DisplayName        string `json:"displayName"`
		Name               string `json:"name"`
		CsrContent         any    `json:"csrContent"`
		Platform           string `json:"platform"`
		ExpirationDate     Date   `json:"expirationDate"`
		CertificateType    string `json:"certificateType"`
	} `json:"attributes"`
	Links Links `json:"links"`
}

func (c Certificate) IsExpired() bool {
	return time.Time(c.Attributes.ExpirationDate).Before(time.Now())
}

type CertificateResponse struct {
	Data  Certificate `json:"data"`
	Links Links       `json:"links"`
}

type CertificatesResponse struct {
	Data  []Certificate      `json:"data"`
	Links PagedDocumentLinks `json:"links"`
	Meta  Meta               `json:"meta"`
}

// GetCertificates returns a list certificates and download their data.
func (as *AppStore) GetCertificates() ([]Certificate, error) {

	if err := as.createToken(); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", certificatessURL, nil)
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

	var certsResp CertificatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&certsResp); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	certificateDataList := make([]Certificate, 0)
	for _, v := range certsResp.Data {
		if v.Type == "certificates" &&
			(v.Attributes.CertificateType == "IOS_DEVELOPMENT" ||
				v.Attributes.CertificateType == "MAC_APP_DEVELOPMENT" ||
				v.Attributes.CertificateType == "DEVELOPMENT") {
			certificateDataList = append(certificateDataList, v)
		}
	}

	return certificateDataList, nil
}
