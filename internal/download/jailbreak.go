package download

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"

	"github.com/blacktop/ipsw/internal/utils"
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

var researchers = []string{"Ian Beer", "Johnathan Levin", "Siguza", "Brandon Azad", "Luca Todesco", "axi0mX", "xerub"}

func init() {
	rand.Seed(time.Now().Unix())
}

// CanIBreak will check if an iOS version is jailbreakable
func (j *Jailbreaks) CanIBreak(iOSVersion string) (bool, int, error) {
	v, err := version.NewVersion(iOSVersion)
	if err != nil {
		return false, -1, errors.Wrap(err, "failed to create version")
	}
	for idx, jb := range j.Jailbreaks {
		if len(jb.Firmwares.Start) > 0 && len(jb.Firmwares.End) > 0 {
			constraints, err := version.NewConstraint(fmt.Sprintf(">= %s, <= %s", jb.Firmwares.Start, jb.Firmwares.End))
			if err != nil {
				return false, -1, errors.Wrap(err, "failed to create new version constraint")
			}
			if constraints.Check(v) {
				utils.Indent(log.Debug, 1)(fmt.Sprintf("%s satisfies constraints %s", v.Original(), constraints))
				return jb.Jailbroken, idx, nil
			}
		} else if len(jb.Firmwares.Start) > 0 {
			constraints, err := version.NewConstraint(fmt.Sprintf(">= %s", jb.Firmwares.Start))
			if err != nil {
				return false, -1, errors.Wrap(err, "failed to create new version constraint")
			}
			if constraints.Check(v) {
				utils.Indent(log.Debug, 1)(fmt.Sprintf("%s satisfies constraints %s", v.Original(), constraints))
				return jb.Jailbroken, idx, nil
			}
		}
	}
	return false, -1, nil
}

// GetRandomResearcher returns a random iOS Vulnerability Researcher
func GetRandomResearcher() string {
	return researchers[rand.Intn(len(researchers))]
}

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

	body, err := io.ReadAll(res.Body)
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
