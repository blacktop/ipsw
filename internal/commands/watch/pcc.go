package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/blacktop/ipsw/internal/download"
)

const pccVPhoneStateVersion = 1

// PCCVPhoneState is the durable cursor for the PCC vphone600 watcher.
// KnownOSDigests prevents duplicate alerts across repeated releases and
// transparency-log tree rotations.
type PCCVPhoneState struct {
	Version        int      `json:"version"`
	Initialized    bool     `json:"initialized"`
	TreeID         uint64   `json:"tree_id"`
	HeadIndex      uint64   `json:"head_index"`
	KnownOSDigests []string `json:"known_os_digests,omitempty"`
}

// PCCVPhoneCheck is the result of evaluating one transparency-log snapshot.
type PCCVPhoneCheck struct {
	State       PCCVPhoneState
	NewReleases []*download.PCCRelease
	Pending     int
	Baselined   bool
}

// DefaultPCCVPhoneStatePath returns the per-user watcher state path.
func DefaultPCCVPhoneStatePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to locate user config directory: %w", err)
	}
	return filepath.Join(configDir, "ipsw", "watch", "pcc-vphone.json"), nil
}

// LoadPCCVPhoneState loads a watcher state file. A missing file is an
// uninitialized state, not an error.
func LoadPCCVPhoneState(path string) (PCCVPhoneState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return PCCVPhoneState{}, nil
	}
	if err != nil {
		return PCCVPhoneState{}, fmt.Errorf("failed to read PCC watch state %s: %w", path, err)
	}

	var state PCCVPhoneState
	if err := json.Unmarshal(data, &state); err != nil {
		return PCCVPhoneState{}, fmt.Errorf("failed to decode PCC watch state %s: %w", path, err)
	}
	if state.Version != pccVPhoneStateVersion {
		return PCCVPhoneState{}, fmt.Errorf(
			"unsupported PCC watch state version %d in %s",
			state.Version,
			path,
		)
	}
	return state, nil
}

// SavePCCVPhoneState atomically persists state without storing credentials.
func SavePCCVPhoneState(path string, state PCCVPhoneState) error {
	state.Version = pccVPhoneStateVersion
	state.KnownOSDigests = slices.Clone(state.KnownOSDigests)
	slices.Sort(state.KnownOSDigests)

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode PCC watch state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create PCC watch state directory %s: %w", dir, err)
	}
	file, err := os.CreateTemp(dir, ".pcc-vphone-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary PCC watch state: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)

	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("failed to secure temporary PCC watch state: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("failed to write temporary PCC watch state: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("failed to sync temporary PCC watch state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close temporary PCC watch state: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to replace PCC watch state %s: %w", path, err)
	}
	return nil
}

// CheckPCCVPhoneSnapshot resolves new OS assets and returns newly confirmed
// vphone600 releases. Unresolved assets hold the cursor so they are retried.
func CheckPCCVPhoneSnapshot(
	state PCCVPhoneState,
	snapshot *download.PCCLogSnapshot,
	notifyInitial bool,
	resolve func([]*download.PCCRelease),
) PCCVPhoneCheck {
	known := make(map[string]struct{}, len(state.KnownOSDigests))
	for _, digest := range state.KnownOSDigests {
		known[digest] = struct{}{}
	}

	if !state.Initialized && !notifyInitial {
		for _, release := range snapshot.Releases {
			if digest := release.OSAssetDigest(); digest != "" {
				known[digest] = struct{}{}
			}
		}
		state.Version = pccVPhoneStateVersion
		state.Initialized = true
		state.TreeID = snapshot.TreeID
		state.HeadIndex = snapshot.HeadIndex
		state.KnownOSDigests = sortedDigests(known)
		return PCCVPhoneCheck{State: state, Baselined: true}
	}

	startIndex := state.HeadIndex
	resetCursor := !state.Initialized ||
		state.TreeID != snapshot.TreeID ||
		state.HeadIndex > snapshot.HeadIndex
	if resetCursor {
		startIndex = 0
	}

	var candidates []*download.PCCRelease
	candidateDigests := make(map[string]struct{})
	for _, release := range snapshot.Releases {
		if release.Index < startIndex {
			continue
		}
		digest := release.OSAssetDigest()
		if digest == "" {
			continue
		}
		if _, ok := known[digest]; ok {
			continue
		}
		if _, ok := candidateDigests[digest]; ok {
			continue
		}
		candidateDigests[digest] = struct{}{}
		candidates = append(candidates, release)
	}

	if len(candidates) > 0 {
		resolve(candidates)
	}

	var newReleases []*download.PCCRelease
	var pending int
	for _, release := range candidates {
		if release.VPhone == nil {
			pending++
			continue
		}
		known[release.OSAssetDigest()] = struct{}{}
		if release.VPhone.Present {
			newReleases = append(newReleases, release)
		}
	}

	state.Version = pccVPhoneStateVersion
	state.Initialized = true
	state.TreeID = snapshot.TreeID
	state.HeadIndex = startIndex
	if pending == 0 {
		state.HeadIndex = snapshot.HeadIndex
	}
	state.KnownOSDigests = sortedDigests(known)

	return PCCVPhoneCheck{
		State:       state,
		NewReleases: newReleases,
		Pending:     pending,
	}
}

func sortedDigests(digests map[string]struct{}) []string {
	out := make([]string, 0, len(digests))
	for digest := range digests {
		out = append(out, digest)
	}
	slices.Sort(out)
	return out
}
