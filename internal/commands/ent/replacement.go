/*
Copyright © 2018-2025 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package ent

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gorm.io/gorm"
)

// VersionComparator represents an iOS version for comparison purposes
type VersionComparator struct {
	MajorMinor string // e.g., "26.0", "18.5"
	Build      string // e.g., "22G87", "beta6", "22F76"
	Raw        string // Original version string
}

// ReplacementConfig holds configuration for replacement operations
type ReplacementConfig struct {
	Strategy string // auto, prompt, force
	DryRun   bool
}

// ReplacementPlan represents a planned replacement operation
type ReplacementPlan struct {
	ToReplace    []IPSWInfo
	NewIPSW      IPSWInfo
	Config       *ReplacementConfig
	ReasonMsg    string
	ConflictType string
}

// IPSWInfo represents basic information about an IPSW
type IPSWInfo struct {
	Version  string
	BuildID  string
	ID       string // Database ID
	Name     string // Filename
	Platform string // Platform (iOS, macOS, etc.)
}

// ParseVersionComparator creates a VersionComparator from a version string
func ParseVersionComparator(version, build string) VersionComparator {
	majorMinor := extractMajorMinorVersion(version)
	return VersionComparator{
		MajorMinor: majorMinor,
		Build:      build,
		Raw:        version,
	}
}

// extractMajorMinorVersion extracts major.minor from version string
// Examples: "26.0.1" -> "26.0", "18.5" -> "18.5"
func extractMajorMinorVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return version
}

// ShouldReplace determines if an existing version should be replaced by a new version
func ShouldReplace(existing, new VersionComparator) bool {
	// Only replace if same major.minor version
	if existing.MajorMinor != new.MajorMinor {
		return false
	}

	// If versions are identical, compare builds
	if existing.Raw == new.Raw {
		return CompareBuildVersions(existing.Build, new.Build) < 0
	}

	// Compare full versions (e.g., 26.0.1 vs 26.0.2)
	return CompareVersionStrings(existing.Raw, new.Raw) < 0
}

// ShouldReplaceWithPlatform determines if an existing IPSW should be replaced by a new one
// considering both platform and version
func ShouldReplaceWithPlatform(existingIPSW, newIPSW IPSWInfo) bool {
	// Only replace if same platform
	if existingIPSW.Platform != newIPSW.Platform {
		return false
	}

	// Use existing version comparison logic
	existingComparator := ParseVersionComparator(existingIPSW.Version, existingIPSW.BuildID)
	newComparator := ParseVersionComparator(newIPSW.Version, newIPSW.BuildID)

	return ShouldReplace(existingComparator, newComparator)
}

// CompareBuildVersions compares two build version strings
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func CompareBuildVersions(a, b string) int {
	// Handle beta versions
	if strings.Contains(a, "beta") || strings.Contains(b, "beta") {
		return compareBetaBuilds(a, b)
	}

	// Handle numeric build IDs (e.g., 22G87 vs 22G89)
	if isNumericBuild(a) && isNumericBuild(b) {
		return compareNumericBuilds(a, b)
	}

	// Fallback to string comparison
	if a < b {
		return -1
	} else if a > b {
		return 1
	}
	return 0
}

// CompareVersionStrings compares two version strings (e.g., "26.0.1" vs "26.0.2")
func CompareVersionStrings(a, b string) int {
	aParts := parseVersionParts(a)
	bParts := parseVersionParts(b)

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		aVal := 0
		bVal := 0

		if i < len(aParts) {
			aVal = aParts[i]
		}
		if i < len(bParts) {
			bVal = bParts[i]
		}

		if aVal < bVal {
			return -1
		} else if aVal > bVal {
			return 1
		}
	}

	return 0
}

// parseVersionParts parses a version string into numeric parts
func parseVersionParts(version string) []int {
	parts := strings.Split(version, ".")
	result := make([]int, len(parts))

	for i, part := range parts {
		if val, err := strconv.Atoi(part); err == nil {
			result[i] = val
		}
	}

	return result
}

// compareBetaBuilds compares beta build versions
func compareBetaBuilds(a, b string) int {
	betaRegex := regexp.MustCompile(`beta(\d+)`)

	aMatches := betaRegex.FindStringSubmatch(a)
	bMatches := betaRegex.FindStringSubmatch(b)

	// If both are beta versions
	if len(aMatches) > 1 && len(bMatches) > 1 {
		aNum, _ := strconv.Atoi(aMatches[1])
		bNum, _ := strconv.Atoi(bMatches[1])

		if aNum < bNum {
			return -1
		} else if aNum > bNum {
			return 1
		}
		return 0
	}

	// Beta versions are considered "less than" release versions
	if len(aMatches) > 1 && len(bMatches) == 0 {
		return -1
	}
	if len(aMatches) == 0 && len(bMatches) > 1 {
		return 1
	}

	// Fallback to string comparison
	return strings.Compare(a, b)
}

// isNumericBuild checks if a build ID follows numeric pattern (e.g., 22G87)
func isNumericBuild(build string) bool {
	match, _ := regexp.MatchString(`^\d+[A-Z]+\d+$`, build)
	return match
}

// compareNumericBuilds compares numeric build IDs
func compareNumericBuilds(a, b string) int {
	// Extract prefix numbers and suffix numbers
	aPrefix, aSuffix := extractBuildParts(a)
	bPrefix, bSuffix := extractBuildParts(b)

	// Compare prefixes first
	if aPrefix != bPrefix {
		if aPrefix < bPrefix {
			return -1
		}
		return 1
	}

	// Compare suffixes
	if aSuffix < bSuffix {
		return -1
	} else if aSuffix > bSuffix {
		return 1
	}
	return 0
}

// extractBuildParts extracts numeric parts from build ID (e.g., "22G87" -> 22, 87)
func extractBuildParts(build string) (int, int) {
	regex := regexp.MustCompile(`^(\d+)[A-Z]+(\d+)$`)
	matches := regex.FindStringSubmatch(build)

	if len(matches) < 3 {
		return 0, 0
	}

	prefix, _ := strconv.Atoi(matches[1])
	suffix, _ := strconv.Atoi(matches[2])

	return prefix, suffix
}

// CreateReplacementPlan analyzes what would be replaced and creates a plan
func CreateReplacementPlan(newIPSW IPSWInfo, existingIPSWs []IPSWInfo, config *ReplacementConfig) *ReplacementPlan {
	var toReplace []IPSWInfo
	var reasonMsg string

	for _, existing := range existingIPSWs {
		if ShouldReplaceWithPlatform(existing, newIPSW) {
			toReplace = append(toReplace, existing)
		}
	}

	if len(toReplace) > 0 {
		if len(toReplace) == 1 {
			reasonMsg = fmt.Sprintf("Replacing %s %s (build %s) with %s %s (build %s)",
				toReplace[0].Platform, toReplace[0].Version, toReplace[0].BuildID,
				newIPSW.Platform, newIPSW.Version, newIPSW.BuildID)
		} else {
			newComparator := ParseVersionComparator(newIPSW.Version, newIPSW.BuildID)
			reasonMsg = fmt.Sprintf("Replacing %d older builds of %s %s with newer build %s",
				len(toReplace), newIPSW.Platform, newComparator.MajorMinor, newIPSW.BuildID)
		}
	} else {
		newComparator := ParseVersionComparator(newIPSW.Version, newIPSW.BuildID)
		reasonMsg = fmt.Sprintf("No older builds found for %s %s - will add as new entry", newIPSW.Platform, newComparator.MajorMinor)
	}

	return &ReplacementPlan{
		ToReplace:    toReplace,
		NewIPSW:      newIPSW,
		Config:       config,
		ReasonMsg:    reasonMsg,
		ConflictType: determineConflictType(toReplace, newIPSW),
	}
}

// determineConflictType categorizes the type of replacement
func determineConflictType(toReplace []IPSWInfo, newIPSW IPSWInfo) string {
	if len(toReplace) == 0 {
		return "new"
	}

	if len(toReplace) == 1 {
		existing := toReplace[0]
		if existing.Version == newIPSW.Version {
			return "build_update"
		}
		return "version_update"
	}

	return "multiple_replace"
}

// ReplacementStrategy interface for different replacement implementations
type ReplacementStrategy interface {
	SupportsVersionBasedReplacement() bool
	CreateReplacementPlan(newIPSW IPSWInfo, existingIPSWs []IPSWInfo, config *ReplacementConfig) (*ReplacementPlan, error)
	ExecuteReplacement(plan *ReplacementPlan) error
	GetExistingIPSWs(platform, version string) ([]IPSWInfo, error)
}

// SQLiteReplacementStrategy handles replacements for SQLite databases
type SQLiteReplacementStrategy struct {
	service *DatabaseService
}

// NewSQLiteReplacementStrategy creates a new SQLite replacement strategy
func NewSQLiteReplacementStrategy(service *DatabaseService) *SQLiteReplacementStrategy {
	return &SQLiteReplacementStrategy{service: service}
}

// SupportsVersionBasedReplacement returns true for SQLite strategy
func (s *SQLiteReplacementStrategy) SupportsVersionBasedReplacement() bool {
	return true
}

// CreateReplacementPlan creates a replacement plan for SQLite
func (s *SQLiteReplacementStrategy) CreateReplacementPlan(newIPSW IPSWInfo, existingIPSWs []IPSWInfo, config *ReplacementConfig) (*ReplacementPlan, error) {
	return CreateReplacementPlan(newIPSW, existingIPSWs, config), nil
}

// ExecuteReplacement executes the replacement plan atomically
func (s *SQLiteReplacementStrategy) ExecuteReplacement(plan *ReplacementPlan) error {
	if s.service.gormDB == nil {
		return fmt.Errorf("GORM database required for replacement operations")
	}

	// If dry run, just log what would happen
	if plan.Config.DryRun {
		fmt.Printf("DRY RUN: %s\n", plan.ReasonMsg)
		return nil
	}

	// Prompt user if strategy is prompt
	if plan.Config.Strategy == "prompt" && len(plan.ToReplace) > 0 {
		if !promptUserForReplacement(plan) {
			fmt.Printf("Replacement cancelled by user\n")
			return nil
		}
	}

	// Execute atomic replacement transaction
	return s.service.gormDB.Transaction(func(tx *gorm.DB) error {
		// Step 1: Delete old IPSW data
		for _, oldIPSW := range plan.ToReplace {
			if err := s.deleteIPSWData(tx, oldIPSW.ID); err != nil {
				return fmt.Errorf("failed to delete old IPSW %s: %w", oldIPSW.ID, err)
			}
		}

		fmt.Printf("✓ %s\n", plan.ReasonMsg)
		return nil
	})
}

// GetExistingIPSWs retrieves existing IPSWs for version comparison
func (s *SQLiteReplacementStrategy) GetExistingIPSWs(platform, version string) ([]IPSWInfo, error) {
	if s.service.gormDB == nil {
		return nil, fmt.Errorf("GORM database required")
	}

	majorMinor := extractMajorMinorVersion(version)

	// Query IPSWs with same platform and major.minor version
	var ipsws []struct {
		ID       string
		Name     string
		Version  string
		BuildID  string
		Platform string
	}

	err := s.service.gormDB.Table("ipsws").
		Select("id, name, version, buildid as build_id, platform").
		Where("platform = ? AND version LIKE ?", platform, majorMinor+"%").
		Find(&ipsws).Error

	if err != nil {
		return nil, fmt.Errorf("failed to query existing IPSWs: %w", err)
	}

	result := make([]IPSWInfo, len(ipsws))
	for i, ipsw := range ipsws {
		result[i] = IPSWInfo{
			ID:       ipsw.ID,
			Name:     ipsw.Name,
			Version:  ipsw.Version,
			BuildID:  ipsw.BuildID,
			Platform: ipsw.Platform,
		}
	}

	return result, nil
}

// deleteIPSWData deletes all data associated with an IPSW
func (s *SQLiteReplacementStrategy) deleteIPSWData(tx *gorm.DB, ipswID string) error {
	// Delete entitlements (cascading delete handles references)
	if err := tx.Exec("DELETE FROM entitlements WHERE ipsw_id = ?", ipswID).Error; err != nil {
		return fmt.Errorf("failed to delete entitlements: %w", err)
	}

	// Delete IPSW record
	if err := tx.Exec("DELETE FROM ipsws WHERE id = ?", ipswID).Error; err != nil {
		return fmt.Errorf("failed to delete IPSW record: %w", err)
	}

	// Clean up orphaned references
	return s.cleanupOrphanedReferences(tx)
}

// cleanupOrphanedReferences removes unused paths, keys, and values
func (s *SQLiteReplacementStrategy) cleanupOrphanedReferences(tx *gorm.DB) error {
	// Remove paths not referenced by any entitlements
	if err := tx.Exec(`
		DELETE FROM paths 
		WHERE id NOT IN (SELECT DISTINCT path_id FROM entitlements WHERE path_id IS NOT NULL)
	`).Error; err != nil {
		return fmt.Errorf("failed to cleanup orphaned paths: %w", err)
	}

	// Remove keys not referenced by any entitlements
	if err := tx.Exec(`
		DELETE FROM entitlement_keys 
		WHERE id NOT IN (SELECT DISTINCT key_id FROM entitlements WHERE key_id IS NOT NULL)
	`).Error; err != nil {
		return fmt.Errorf("failed to cleanup orphaned keys: %w", err)
	}

	// Remove values not referenced by any entitlements
	if err := tx.Exec(`
		DELETE FROM entitlement_values 
		WHERE id NOT IN (SELECT DISTINCT value_id FROM entitlements WHERE value_id IS NOT NULL)
	`).Error; err != nil {
		return fmt.Errorf("failed to cleanup orphaned values: %w", err)
	}

	return nil
}

// PostgreSQLReplacementStrategy handles replacements for PostgreSQL databases
type PostgreSQLReplacementStrategy struct {
	service *DatabaseService
}

// NewPostgreSQLReplacementStrategy creates a new PostgreSQL replacement strategy
func NewPostgreSQLReplacementStrategy(service *DatabaseService) *PostgreSQLReplacementStrategy {
	return &PostgreSQLReplacementStrategy{service: service}
}

// SupportsVersionBasedReplacement returns true for PostgreSQL strategy
func (p *PostgreSQLReplacementStrategy) SupportsVersionBasedReplacement() bool {
	return true
}

// CreateReplacementPlan creates a replacement plan for PostgreSQL
func (p *PostgreSQLReplacementStrategy) CreateReplacementPlan(newIPSW IPSWInfo, existingIPSWs []IPSWInfo, config *ReplacementConfig) (*ReplacementPlan, error) {
	return CreateReplacementPlan(newIPSW, existingIPSWs, config), nil
}

// ExecuteReplacement executes the replacement plan atomically
func (p *PostgreSQLReplacementStrategy) ExecuteReplacement(plan *ReplacementPlan) error {
	// Same implementation as SQLite for now since both use GORM
	sqliteStrategy := &SQLiteReplacementStrategy{service: p.service}
	return sqliteStrategy.ExecuteReplacement(plan)
}

// GetExistingIPSWs retrieves existing IPSWs for version comparison
func (p *PostgreSQLReplacementStrategy) GetExistingIPSWs(platform, version string) ([]IPSWInfo, error) {
	// Same implementation as SQLite for now since both use GORM
	sqliteStrategy := &SQLiteReplacementStrategy{service: p.service}
	return sqliteStrategy.GetExistingIPSWs(platform, version)
}

// LegacyReplacementStrategy handles replacements for legacy database formats
type LegacyReplacementStrategy struct{}

// NewLegacyReplacementStrategy creates a new legacy replacement strategy
func NewLegacyReplacementStrategy() *LegacyReplacementStrategy {
	return &LegacyReplacementStrategy{}
}

// SupportsVersionBasedReplacement returns false for legacy strategy (simple overwrite)
func (l *LegacyReplacementStrategy) SupportsVersionBasedReplacement() bool {
	return false
}

// CreateReplacementPlan creates a simple replacement plan for legacy format
func (l *LegacyReplacementStrategy) CreateReplacementPlan(newIPSW IPSWInfo, existingIPSWs []IPSWInfo, config *ReplacementConfig) (*ReplacementPlan, error) {
	return &ReplacementPlan{
		ToReplace:    existingIPSWs, // Replace all existing data
		NewIPSW:      newIPSW,
		Config:       config,
		ReasonMsg:    "Legacy format: replacing entire database with new data",
		ConflictType: "legacy_overwrite",
	}, nil
}

// ExecuteReplacement executes simple overwrite for legacy format
func (l *LegacyReplacementStrategy) ExecuteReplacement(plan *ReplacementPlan) error {
	if plan.Config.DryRun {
		fmt.Printf("DRY RUN: %s\n", plan.ReasonMsg)
		return nil
	}

	fmt.Printf("✓ %s\n", plan.ReasonMsg)
	// For legacy format, the actual overwrite is handled by the calling code
	return nil
}

// GetExistingIPSWs returns empty list for legacy format
func (l *LegacyReplacementStrategy) GetExistingIPSWs(platform, version string) ([]IPSWInfo, error) {
	return []IPSWInfo{}, nil
}

// promptUserForReplacement prompts the user to confirm replacement
func promptUserForReplacement(plan *ReplacementPlan) bool {
	fmt.Printf("\n%s\n", plan.ReasonMsg)

	if len(plan.ToReplace) > 0 {
		fmt.Printf("This will delete the following existing data:\n")
		for _, ipsw := range plan.ToReplace {
			fmt.Printf("  - %s (iOS %s, build %s)\n", ipsw.Name, ipsw.Version, ipsw.BuildID)
		}
	}

	fmt.Printf("\nDo you want to continue? (y/N): ")

	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		response := strings.ToLower(strings.TrimSpace(scanner.Text()))
		return response == "y" || response == "yes"
	}

	return false
}
