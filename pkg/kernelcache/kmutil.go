package kernelcache

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-plist"
)

func InspectKM(m *macho.File, filter string, explicitOnly, asJSON bool) (string, error) {
	re, err := regexp.Compile(filter)
	if err != nil {
		return "", fmt.Errorf("failed to compile filter regex: %v", err)
	}
	if sec := m.Section("__PRELINK_INFO", "__info"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return "", fmt.Errorf("failed to read __PRELINK_INFO.__info section: %v", err)
		}

		var prelink PrelinkInfo
		if err := plist.NewDecoder(bytes.NewReader(dat)).Decode(&prelink); err != nil {
			return "", fmt.Errorf("failed to decode prelink info: %v", err)
		}

		if asJSON {
			jsonPL, err := json.Marshal(prelink)
			if err != nil {
				return "", fmt.Errorf("failed to marshal prelink info: %v", err)
			}
			return string(jsonPL), nil
		}

		var out []string

		for _, bundle := range prelink.PrelinkInfoDictionary {
			if re.MatchString(bundle.ID) {
				log.Debugf("found bundle '%s' who matches filter", bundle.ID)
				continue
			}
			if len(bundle.OSBundleLibraries) == 0 {
				if explicitOnly {
					out = append(out, fmt.Sprintf("-b %s", bundle.ID))
				} else {
					out = append(out, bundle.ID)
				}
			} else {
				skip := false
				for name := range bundle.OSBundleLibraries {
					if re.MatchString(name) {
						log.Debugf("found bundle '%s' whose dependency matches filter", bundle.ID)
						skip = true
						break
					}
				}
				if !skip {
					if explicitOnly {
						out = append(out, fmt.Sprintf("-b %s", bundle.ID))
					} else {
						out = append(out, bundle.ID)
					}
				}
			}
		}

		if explicitOnly {
			return strings.Join(out, " "), nil
		}
		return strings.Join(out, "\n"), nil
	}

	return "", fmt.Errorf("failed to find __PRELINK_INFO.__info section")
}
