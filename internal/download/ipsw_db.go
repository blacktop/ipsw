package download

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
)

const ipswDbURL = "https://raw.githubusercontent.com/blacktop/ipsw/master/pkg/info/data/ipsw_db.json"

// GetIpswDB pulls the most up-to-date ipsw_db.json from the repo
func GetIpswDB(proxy string, insecure bool) (*info.Devices, error) {
	var db info.Devices

	req, err := http.NewRequest("GET", ipswDbURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("User-Agent", utils.RandomAgent())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	if err := json.Unmarshal(body, &db); err != nil {
		return nil, fmt.Errorf("error unmarshaling ipsw_db.json: %v", err)
	}

	return &db, nil
}
