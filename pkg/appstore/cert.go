package appstore

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/download"
)

type CertificateType string

const (
	CT_APPLE_PAY                   CertificateType = "APPLE_PAY"
	CT_APPLE_PAY_MERCHANT_IDENTITY CertificateType = "APPLE_PAY_MERCHANT_IDENTITY"
	CT_APPLE_PAY_PSP_IDENTITY      CertificateType = "APPLE_PAY_PSP_IDENTITY"
	CT_APPLE_PAY_RSA               CertificateType = "APPLE_PAY_RSA"
	CT_DEVELOPER_ID_KEXT           CertificateType = "DEVELOPER_ID_KEXT"
	CT_DEVELOPER_ID_KEXT_G2        CertificateType = "DEVELOPER_ID_KEXT_G2"
	CT_DEVELOPER_ID_APPLICATION    CertificateType = "DEVELOPER_ID_APPLICATION"
	CT_DEVELOPER_ID_APPLICATION_G2 CertificateType = "DEVELOPER_ID_APPLICATION_G2"
	CT_DEVELOPMENT                 CertificateType = "DEVELOPMENT"
	CT_DISTRIBUTION                CertificateType = "DISTRIBUTION"
	CT_IDENTITY_ACCESS             CertificateType = "IDENTITY_ACCESS"
	CT_IOS_DEVELOPMENT             CertificateType = "IOS_DEVELOPMENT"
	CT_IOS_DISTRIBUTION            CertificateType = "IOS_DISTRIBUTION"
	CT_MAC_APP_DISTRIBUTION        CertificateType = "MAC_APP_DISTRIBUTION"
	CT_MAC_INSTALLER_DISTRIBUTION  CertificateType = "MAC_INSTALLER_DISTRIBUTION"
	CT_MAC_APP_DEVELOPMENT         CertificateType = "MAC_APP_DEVELOPMENT"
	CT_PASS_TYPE_ID                CertificateType = "PASS_TYPE_ID"
	CT_PASS_TYPE_ID_WITH_NFC       CertificateType = "PASS_TYPE_ID_WITH_NFC"
)

var CertTypes = []string{
	string(CT_APPLE_PAY),
	string(CT_APPLE_PAY_MERCHANT_IDENTITY),
	string(CT_APPLE_PAY_PSP_IDENTITY),
	string(CT_APPLE_PAY_RSA),
	string(CT_DEVELOPER_ID_KEXT),
	string(CT_DEVELOPER_ID_KEXT_G2),
	string(CT_DEVELOPER_ID_APPLICATION),
	string(CT_DEVELOPER_ID_APPLICATION_G2),
	string(CT_DEVELOPMENT),
	string(CT_DISTRIBUTION),
	string(CT_IDENTITY_ACCESS),
	string(CT_IOS_DEVELOPMENT),
	string(CT_IOS_DISTRIBUTION),
	string(CT_MAC_APP_DISTRIBUTION),
	string(CT_MAC_INSTALLER_DISTRIBUTION),
	string(CT_MAC_APP_DEVELOPMENT),
	string(CT_PASS_TYPE_ID),
	string(CT_PASS_TYPE_ID_WITH_NFC),
}

type BundleIdPlatform string

const (
	BP_IOS       BundleIdPlatform = "IOS"
	BP_MAC       BundleIdPlatform = "MAC_OS"
	BP_UNIVERSAL BundleIdPlatform = "UNIVERSAL"
)

var BundleIdPlatforms = []string{
	string(BP_IOS),
	string(BP_MAC),
	string(BP_UNIVERSAL),
}

type Certificate struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		CertificateContent []byte           `json:"certificateContent"`
		DisplayName        string           `json:"displayName"`
		ExpirationDate     Date             `json:"expirationDate"`
		Name               string           `json:"name"`
		Platform           BundleIdPlatform `json:"platform"`
		SerialNumber       string           `json:"serialNumber"`
		CertificateType    CertificateType  `json:"certificateType"`
		CsrContent         any              `json:"csrContent"`
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

type CertificateCreateRequest struct {
	Data struct {
		Type       string `json:"type"` // certificates
		Attributes struct {
			CertificateType string `json:"certificateType"`
			CSRContent      string `json:"csrContent"`
		} `json:"attributes"`
	} `json:"data"`
}

// GetCertificates returns a list certificates and download their data.
func (as *AppStore) GetCertificates() ([]Certificate, error) {

	if err := as.createToken(defaultJWTLife); err != nil {
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
		if v.Type == "certificates" {
			certificateDataList = append(certificateDataList, v)
		}
	}

	return certificateDataList, nil
}

// CreateCertificate creates a new certificate using a certificate signing request.
func (as *AppStore) CreateCertificate(ctype string, csrData string) (*Certificate, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	var profileCreateRequest CertificateCreateRequest
	profileCreateRequest.Data.Type = "certificates"
	profileCreateRequest.Data.Attributes.CertificateType = ctype
	profileCreateRequest.Data.Attributes.CSRContent = csrData

	jsonStr, err := json.Marshal(&profileCreateRequest)
	if err != nil {
		return nil, err
	}
	// os.WriteFile("req.json", jsonStr, 0644)
	req, err := http.NewRequest("POST", certificatessURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+as.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

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

	if resp.StatusCode != 201 && resp.StatusCode != 409 {
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

	var cert CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &cert.Data, nil
}

// RevokeCertificate revokes a lost, stolen, compromised, or expiring signing certificate.
func (as *AppStore) RevokeCertificate(id string) error {
	if err := as.createToken(defaultJWTLife); err != nil {
		return fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("DELETE", certificatessURL+"/"+id, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+as.token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(as.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: as.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		var eresp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&eresp); err != nil {
			return fmt.Errorf("failed to JSON decode http response: %v", err)
		}
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	return nil
}
