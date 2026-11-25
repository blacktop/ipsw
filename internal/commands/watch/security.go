package watch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/atomicfile"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
)

const securityStateVersion = 1

// SecurityState is the durable snapshot of every Apple security advisory the
// watcher has fetched, keyed by advisory ID. Apple edits advisories after
// release, so each poll diffs fresh content against this snapshot.
type SecurityState struct {
	Version     int                         `json:"version"`
	Initialized bool                        `json:"initialized"`
	Advisories  map[string]SecurityAdvisory `json:"advisories,omitempty"`
}

// SecurityAdvisory is the stored content and HTTP validators of one advisory.
type SecurityAdvisory struct {
	Name            string                           `json:"name"`
	ETag            string                           `json:"etag,omitempty"`
	LastModified    string                           `json:"last_modified,omitempty"`
	Vulnerabilities map[string]SecurityVulnerability `json:"vulnerabilities"`
}

// SecurityVulnerability is the stored content of one CVE entry.
type SecurityVulnerability struct {
	Component   string   `json:"component,omitempty"`
	Impact      string   `json:"impact,omitempty"`
	Description string   `json:"description,omitempty"`
	Credits     []string `json:"credits,omitempty"`
	Fixed       []string `json:"fixed,omitempty"`
}

// SecurityEventKind names a change to an advisory.
type SecurityEventKind string

const (
	SecurityNewAdvisory        SecurityEventKind = "new_advisory"
	SecurityCVEAdded           SecurityEventKind = "cve_added"
	SecurityCVERemoved         SecurityEventKind = "cve_removed"
	SecurityCreditsChanged     SecurityEventKind = "credits_changed"
	SecurityProductsChanged    SecurityEventKind = "products_changed"
	SecurityImpactChanged      SecurityEventKind = "impact_changed"
	SecurityDescriptionChanged SecurityEventKind = "description_changed"
)

// SecurityEvent is one change to one CVE. Credits holds the CVE's current names
// (its last names for cve_removed). Added and Removed hold credit names or
// product IDs; Old and New hold impact or description text.
type SecurityEvent struct {
	Kind        SecurityEventKind `json:"kind"`
	Advisory    string            `json:"advisory"`
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	ReleaseDate string            `json:"release_date"`
	CVE         string            `json:"cve"`
	Component   string            `json:"component,omitempty"`
	Credits     []string          `json:"credits,omitempty"`
	Added       []string          `json:"added,omitempty"`
	Removed     []string          `json:"removed,omitempty"`
	Old         string            `json:"old,omitempty"`
	New         string            `json:"new,omitempty"`
}

// SecurityPollOptions controls which events a poll reports.
type SecurityPollOptions struct {
	// NotifyInitial reports advisories found while creating state.
	NotifyInitial bool
	// Credits keeps only events whose credit names contain one of these
	// case-insensitive substrings. Empty keeps every event.
	Credits []string
}

// SecurityPoll is the result of one pass over Apple's security index.
// Unfetched holds one error per advisory that could not be read, each naming
// its advisory. Baselined reports that this pass finished creating state
// without reporting events.
type SecurityPoll struct {
	State       SecurityState
	Events      []SecurityEvent
	Unfetched   []error
	Checked     int
	NotModified int
	NoJSON      int
	Baselined   bool
}

// UnfetchedError names every advisory this poll could not read, or returns nil.
func (p SecurityPoll) UnfetchedError() error {
	if len(p.Unfetched) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(p.Unfetched))
	for _, err := range p.Unfetched {
		reasons = append(reasons, err.Error())
	}
	return fmt.Errorf("%d security advisories unfetched: %s", len(p.Unfetched), strings.Join(reasons, "; "))
}

// DefaultSecurityStatePath returns the per-user security watcher state path.
func DefaultSecurityStatePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to locate user config directory: %w", err)
	}
	return filepath.Join(configDir, "ipsw", "watch", "security.json"), nil
}

// LoadSecurityState loads a watcher state file. A missing file is an
// uninitialized state, not an error.
func LoadSecurityState(path string) (SecurityState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return SecurityState{}, nil
	}
	if err != nil {
		return SecurityState{}, fmt.Errorf("failed to read security watch state %s: %w", path, err)
	}
	var state SecurityState
	if err := json.Unmarshal(data, &state); err != nil {
		return SecurityState{}, fmt.Errorf("failed to decode security watch state %s: %w", path, err)
	}
	if state.Version != securityStateVersion {
		return SecurityState{}, fmt.Errorf("unsupported security watch state version %d in %s", state.Version, path)
	}
	return state, nil
}

// SaveSecurityState atomically persists state.
func SaveSecurityState(path string, state SecurityState) error {
	state.Version = securityStateVersion
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode security watch state: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create security watch state directory: %w", err)
	}
	if err := atomicfile.Write(path, 0o600, func(file *os.File) error {
		_, err := file.Write(data)
		return err
	}); err != nil {
		return fmt.Errorf("failed to write security watch state %s: %w", path, err)
	}
	return nil
}

// PollSecurity re-reads every advisory that has JSON and diffs it against state.
// Advisories that cannot be read keep their stored content and are listed in
// Unfetched. A persistent HTTP 429 ends the pass early because support.apple.com
// throttles every JSON path at once.
func PollSecurity(
	ctx context.Context,
	client *download.SecurityClient,
	state SecurityState,
	opts SecurityPollOptions,
) (SecurityPoll, error) {
	entries, err := client.Index(ctx)
	if err != nil {
		return SecurityPoll{}, fmt.Errorf("failed to fetch security index: %w", err)
	}

	next := SecurityState{Advisories: maps.Clone(state.Advisories)}
	if next.Advisories == nil {
		next.Advisories = make(map[string]SecurityAdvisory)
	}
	var poll SecurityPoll
	announce := state.Initialized || opts.NotifyInitial

	targets := securityTargets(entries)
	for index, entry := range targets {
		if err := pollSecurityAdvisory(ctx, client, entry, next.Advisories, &poll, announce); err != nil {
			if ctx.Err() != nil {
				return SecurityPoll{}, ctx.Err()
			}
			poll.Unfetched = append(poll.Unfetched, err)
			if securityThrottled(err) {
				poll.Unfetched = append(poll.Unfetched, skippedAfterThrottle(targets[index+1:])...)
				break
			}
		}
	}

	next.Initialized = announce || len(poll.Unfetched) == 0
	poll.Baselined = !announce && next.Initialized
	poll.State = next
	poll.Events = filterSecurityEvents(poll.Events, opts.Credits)
	return poll, nil
}

func pollSecurityAdvisory(
	ctx context.Context,
	client *download.SecurityClient,
	entry download.SecurityIndexEntry,
	advisories map[string]SecurityAdvisory,
	poll *SecurityPoll,
	announce bool,
) error {
	previous, known := advisories[entry.ID]
	resp, err := client.Advisory(ctx, entry.ID, previous.ETag, previous.LastModified)
	if errors.Is(err, download.ErrSecurityAdvisoryNotFound) {
		poll.NoJSON++
		log.Debugf("Skipping security advisory %s (%s): no JSON published", entry.ID, entry.Name)
		return nil
	}
	if err != nil {
		return err
	}
	poll.Checked++
	if resp.NotModified {
		poll.NotModified++
		previous.ETag, previous.LastModified = resp.ETag, resp.LastModified
		advisories[entry.ID] = previous
		return nil
	}

	current, order := securityAdvisoryContent(entry, resp)
	switch {
	case known:
		poll.Events = append(poll.Events, diffSecurityAdvisory(entry, previous, current, order)...)
	case announce:
		for _, cve := range order {
			poll.Events = append(poll.Events, newSecurityEvent(SecurityNewAdvisory, entry, cve, current.Vulnerabilities[cve]))
		}
	}
	advisories[entry.ID] = current
	return nil
}

func securityTargets(entries []download.SecurityIndexEntry) []download.SecurityIndexEntry {
	seen := make(map[string]struct{})
	var targets []download.SecurityIndexEntry
	for _, entry := range entries {
		if !entry.ExpectsJSON() {
			continue
		}
		if _, ok := seen[entry.ID]; ok {
			continue
		}
		seen[entry.ID] = struct{}{}
		targets = append(targets, entry)
	}
	return targets
}

func securityThrottled(err error) bool {
	var statusErr *download.SecurityStatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == 429
}

func skippedAfterThrottle(entries []download.SecurityIndexEntry) []error {
	skipped := make([]error, 0, len(entries))
	for _, entry := range entries {
		skipped = append(skipped, fmt.Errorf("security advisory %s: not requested after HTTP 429 throttling", entry.ID))
	}
	return skipped
}

func securityAdvisoryContent(
	entry download.SecurityIndexEntry,
	resp download.SecurityAdvisoryResponse,
) (SecurityAdvisory, []string) {
	advisory := SecurityAdvisory{
		Name:            entry.Name,
		ETag:            resp.ETag,
		LastModified:    resp.LastModified,
		Vulnerabilities: make(map[string]SecurityVulnerability, len(resp.Advisory.Vulnerabilities)),
	}
	order := make([]string, 0, len(resp.Advisory.Vulnerabilities))
	for _, vuln := range resp.Advisory.Vulnerabilities {
		if _, ok := advisory.Vulnerabilities[vuln.CVE]; ok {
			log.Warnf("Security advisory %s lists %s more than once; keeping the last entry", entry.ID, vuln.CVE)
		} else {
			order = append(order, vuln.CVE)
		}
		advisory.Vulnerabilities[vuln.CVE] = SecurityVulnerability{
			Component:   vuln.Title,
			Impact:      vuln.Note("summary"),
			Description: vuln.Note("details"),
			Credits:     sortedUnique(vuln.CreditNames()),
			Fixed:       sortedUnique(vuln.ProductStatus.Fixed),
		}
	}
	return advisory, order
}

func diffSecurityAdvisory(
	entry download.SecurityIndexEntry,
	previous, current SecurityAdvisory,
	order []string,
) []SecurityEvent {
	var events []SecurityEvent
	for _, cve := range order {
		now := current.Vulnerabilities[cve]
		before, ok := previous.Vulnerabilities[cve]
		if !ok {
			events = append(events, newSecurityEvent(SecurityCVEAdded, entry, cve, now))
			continue
		}
		events = append(events, diffSecurityVulnerability(entry, cve, before, now)...)
	}
	var removed []string
	for cve := range previous.Vulnerabilities {
		if _, ok := current.Vulnerabilities[cve]; !ok {
			removed = append(removed, cve)
		}
	}
	slices.Sort(removed)
	for _, cve := range removed {
		events = append(events, newSecurityEvent(SecurityCVERemoved, entry, cve, previous.Vulnerabilities[cve]))
	}
	return events
}

func diffSecurityVulnerability(
	entry download.SecurityIndexEntry,
	cve string,
	before, now SecurityVulnerability,
) []SecurityEvent {
	var events []SecurityEvent
	emit := func(kind SecurityEventKind, added, removed []string, oldText, newText string) {
		if len(added) == 0 && len(removed) == 0 && oldText == newText {
			return
		}
		event := newSecurityEvent(kind, entry, cve, now)
		event.Added, event.Removed, event.Old, event.New = added, removed, oldText, newText
		events = append(events, event)
	}
	creditsAdded, creditsRemoved := diffSorted(before.Credits, now.Credits)
	emit(SecurityCreditsChanged, creditsAdded, creditsRemoved, "", "")
	fixedAdded, fixedRemoved := diffSorted(before.Fixed, now.Fixed)
	emit(SecurityProductsChanged, fixedAdded, fixedRemoved, "", "")
	emit(SecurityImpactChanged, nil, nil, before.Impact, now.Impact)
	emit(SecurityDescriptionChanged, nil, nil, before.Description, now.Description)
	return events
}

func newSecurityEvent(
	kind SecurityEventKind,
	entry download.SecurityIndexEntry,
	cve string,
	vuln SecurityVulnerability,
) SecurityEvent {
	return SecurityEvent{
		Kind:        kind,
		Advisory:    entry.ID,
		Name:        entry.Name,
		URL:         entry.URL,
		ReleaseDate: entry.ReleaseDate.Format("2006-01-02"),
		CVE:         cve,
		Component:   vuln.Component,
		Credits:     slices.Clone(vuln.Credits),
	}
}

func filterSecurityEvents(events []SecurityEvent, credits []string) []SecurityEvent {
	if len(credits) == 0 {
		return events
	}
	credited := func(name string) bool { return utils.StrContainsStrSliceItem(name, credits) }
	return slices.DeleteFunc(events, func(event SecurityEvent) bool {
		keep := slices.ContainsFunc(event.Credits, credited) ||
			event.Kind == SecurityCreditsChanged && slices.ContainsFunc(event.Removed, credited)
		return !keep
	})
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}

func diffSorted(before, after []string) (added, removed []string) {
	for _, value := range after {
		if _, found := slices.BinarySearch(before, value); !found {
			added = append(added, value)
		}
	}
	for _, value := range before {
		if _, found := slices.BinarySearch(after, value); !found {
			removed = append(removed, value)
		}
	}
	return added, removed
}
