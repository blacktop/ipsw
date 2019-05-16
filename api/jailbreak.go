package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Jailbreak object
type Jailbreak struct {
	Jailbroken bool   `json:"jailbroken"`
	Name       string `json:"name"`
	URL        string `json:"url"`

	Firmwares struct {
		Start string `json:"start"`
		End   string `json:"end"`
	} `json:"ios"`

	Platforms []string `json:"platforms"`
	Caveats   string   `json:"caveats"`
}

// Jailbreaks object
type Jailbreaks struct {
	Jailbreaks []*Jailbreak `json:"jailbreaks"`
}

const canIJailbreakURL = "https://canijailbreak.com/jailbreaks.json"

// GetJailbreaks gets canijailbreak.com's JSON
func GetJailbreaks() (Jailbreaks, error) {
	jbs := Jailbreaks{}

	res, err := http.Get(canIJailbreakURL)
	if err != nil {
		return jbs, err
	}
	if res.StatusCode != http.StatusOK {
		return jbs, fmt.Errorf("api returned status: %s", res.Status)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return jbs, err
	}
	res.Body.Close()

	err = json.Unmarshal(body, &jbs)
	if err != nil {
		return jbs, err
	}

	return jbs, nil
}
