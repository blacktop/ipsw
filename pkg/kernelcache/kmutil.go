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
	"github.com/dominikbraun/graph"

	"github.com/blacktop/ipsw/internal/utils"
)

func InspectKM(m *macho.File, filter string, explicitOnly, asJSON bool) (string, error) {
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

		var whitelist []string

		if len(filter) == 0 { // NO FILTER (add all bundles to whitelist)
			for _, bundle := range prelink.PrelinkInfoDictionary {
				if explicitOnly {
					whitelist = append(whitelist, fmt.Sprintf("-b %s", bundle.ID))
				} else {
					whitelist = append(whitelist, bundle.ID)
				}
			}
		} else {
			re, err := regexp.Compile(filter)
			if err != nil {
				return "", fmt.Errorf("failed to compile filter regex: %v", err)
			}

			var filterlist []string
			var blacklist []string

			for _, bundle := range prelink.PrelinkInfoDictionary {
				if re.MatchString(bundle.ID) {
					filterlist = append(filterlist, bundle.ID)
				}
			}

			g := graph.New(graph.StringHash, graph.Directed(), graph.PreventCycles())

			// generate dependency graph
			for _, bundle := range prelink.PrelinkInfoDictionary {
				if len(bundle.OSBundleLibraries) > 0 {
					g.AddVertex(bundle.ID)
					for dependency := range bundle.OSBundleLibraries {
						g.AddVertex(dependency)
						if err := g.AddEdge(bundle.ID, dependency); err != nil {
							return "", fmt.Errorf("failed to add edge: %v", err)
						}
					}
				}
			}

			blacklist = append(blacklist, filterlist...)

			// blacklist all bundles that dependacy paths contain filtered bundles
			for _, skip := range filterlist {
				for _, bundle := range prelink.PrelinkInfoDictionary {
					path, err := graph.ShortestPath(g, bundle.ID, skip)
					if err != nil {
						continue
					}
					if len(path) > 0 {
						blacklist = append(blacklist, bundle.ID)
					}
				}
			}

			// whitelist all bundles that are not blacklisted
			for _, bundle := range prelink.PrelinkInfoDictionary {
				if utils.StrSliceContains(blacklist, bundle.ID) {
					utils.Indent(log.WithFields(log.Fields{
						"bundle": bundle.ID,
					}).Info, 2)("Filtered")
					continue
				}
				if explicitOnly {
					whitelist = append(whitelist, fmt.Sprintf("-b %s", bundle.ID))
				} else {
					whitelist = append(whitelist, bundle.ID)
				}
			}
		}

		if explicitOnly {
			return strings.Join(whitelist, " "), nil
		}
		return strings.Join(whitelist, "\n"), nil
	}

	return "", fmt.Errorf("failed to find __PRELINK_INFO.__info section")
}
