package ent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/pkg/info"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DatabaseService handles entitlement database operations
type DatabaseService struct {
	db     db.Database
	gormDB *gorm.DB
}

// NewDatabaseService creates a new database service
func NewDatabaseService(database db.Database) *DatabaseService {
	ds := &DatabaseService{db: database}
	
	// Try to get GORM database if available
	switch dbImpl := database.(type) {
	case *db.Sqlite:
		ds.gormDB = dbImpl.GetDB()
	case *db.Postgres:
		ds.gormDB = dbImpl.GetDB()
	}
	
	return ds
}

// StoreEntitlements stores entitlements from a database into the SQLite database
func (ds *DatabaseService) StoreEntitlements(ipswPath string, entDB map[string]string) error {
	// Get or create IPSW record
	var ipswRecord *model.Ipsw

	if ipswPath != "" {
		// Parse IPSW info from file
		ipswInfo, err := info.Parse(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW info: %v", err)
		}

		ipswRecord = &model.Ipsw{
			ID:      generateIPSWID(ipswInfo.Plists.BuildManifest.ProductVersion, ipswInfo.Plists.BuildManifest.ProductBuildVersion),
			Name:    filepath.Base(ipswPath),
			Version: ipswInfo.Plists.BuildManifest.ProductVersion,
			BuildID: ipswInfo.Plists.BuildManifest.ProductBuildVersion,
		}

		// Add devices
		for _, deviceName := range ipswInfo.Plists.BuildManifest.SupportedProductTypes {
			device := &model.Device{Name: deviceName}
			ipswRecord.Devices = append(ipswRecord.Devices, device)
		}

		// Create or update IPSW record (proper upsert)
		if ds.gormDB != nil {
			// Check if IPSW record already exists
			var existingIPSW model.Ipsw
			result := ds.gormDB.Where("id = ?", ipswRecord.ID).First(&existingIPSW)
			
			if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
				return fmt.Errorf("failed to check existing IPSW record: %v", result.Error)
			}
			
			if result.Error == gorm.ErrRecordNotFound {
				// Record doesn't exist, create it
				if err := ds.gormDB.Create(ipswRecord).Error; err != nil {
					return fmt.Errorf("failed to create IPSW record: %v", err)
				}
			} else {
				// Record exists, update it
				if err := ds.gormDB.Model(&existingIPSW).Updates(ipswRecord).Error; err != nil {
					return fmt.Errorf("failed to update IPSW record: %v", err)
				}
				// Use the existing record for further processing
				ipswRecord = &existingIPSW
			}
		} else {
			// Fallback for other database types
			if err := ds.db.Create(ipswRecord); err != nil {
				return fmt.Errorf("failed to create IPSW record: %v", err)
			}
		}
	} else {
		// Create a minimal IPSW record for standalone usage
		ipswRecord = &model.Ipsw{
			ID:      generateIPSWID("unknown", "unknown"),
			Version: "unknown",
			BuildID: "unknown",
		}
	}

	// Store entitlements using bulk operations for better performance
	if err := ds.storeEntitlementsBulk(ipswRecord, entDB); err != nil {
		return fmt.Errorf("failed to bulk store entitlements: %v", err)
	}

	return nil
}

// storeEntitlementsBulk stores entitlements using bulk operations for much better performance
func (ds *DatabaseService) storeEntitlementsBulk(ipswRecord *model.Ipsw, entDB map[string]string) error {
	if ds.gormDB == nil {
		return fmt.Errorf("GORM database required for bulk entitlement storage")
	}

	// Collect all unique keys, values, and paths first
	var allKeys []model.EntitlementUniqueKey
	var allValues []model.EntitlementUniqueValue
	var allPaths []model.EntitlementUniquePath
	var webEntries []model.EntitlementWebSearch

	// Maps to avoid duplicates during collection
	keySet := make(map[string]bool)
	valueSet := make(map[string]bool)  // using hash as key
	pathSet := make(map[string]bool)

	// Build device list string once
	var deviceNames []string
	for _, device := range ipswRecord.Devices {
		deviceNames = append(deviceNames, device.Name)
	}
	deviceList := strings.Join(deviceNames, ",")

	// First pass: collect all unique keys, values, and paths
	for filePath, entPlist := range entDB {
		if len(entPlist) == 0 {
			continue
		}

		// Add path if not seen before
		if !pathSet[filePath] {
			allPaths = append(allPaths, model.EntitlementUniquePath{Path: filePath})
			pathSet[filePath] = true
		}

		// Parse entitlement plist
		ents := make(map[string]any)
		if err := plist.NewDecoder(bytes.NewReader([]byte(entPlist))).Decode(&ents); err != nil {
			continue // Skip invalid plists
		}

		for key, value := range ents {
			// Add key if not seen before
			if !keySet[key] {
				allKeys = append(allKeys, model.EntitlementUniqueKey{Key: key})
				keySet[key] = true
			}

			// Determine value string and type
			var valueStr, valueType string
			switch v := value.(type) {
			case bool:
				valueType = "bool"
				if v {
					valueStr = "true"
				} else {
					valueStr = "false"
				}
			case string:
				valueType = "string"
				valueStr = v
			case int, int64, uint64:
				valueType = "number"
				if num, ok := v.(int64); ok {
					valueStr = fmt.Sprintf("%d", num)
				} else if num, ok := v.(int); ok {
					valueStr = fmt.Sprintf("%d", num)
				} else if num, ok := v.(uint64); ok {
					valueStr = fmt.Sprintf("%d", num)
				}
			case []any:
				valueType = "array"
				if jsonData, err := json.Marshal(v); err == nil {
					valueStr = string(jsonData)
				}
			case map[string]any:
				valueType = "dict"
				if jsonData, err := json.Marshal(v); err == nil {
					valueStr = string(jsonData)
				}
			default:
				valueType = "unknown"
				valueStr = fmt.Sprintf("%v", v)
			}

			// Add value if not seen before
			valueHash := createValueHash(valueType, valueStr)
			if !valueSet[valueHash] {
				allValues = append(allValues, model.EntitlementUniqueValue{
					Value:     valueStr,
					ValueType: valueType,
					ValueHash: valueHash,
				})
				valueSet[valueHash] = true
			}
		}
	}

	// Bulk insert unique keys, values, and paths with ON CONFLICT DO NOTHING
	if len(allKeys) > 0 {
		if err := ds.gormDB.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(allKeys, 1000).Error; err != nil {
			return fmt.Errorf("failed to bulk insert unique keys: %v", err)
		}
	}

	if len(allValues) > 0 {
		if err := ds.gormDB.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(allValues, 1000).Error; err != nil {
			return fmt.Errorf("failed to bulk insert unique values: %v", err)
		}
	}

	if len(allPaths) > 0 {
		if err := ds.gormDB.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(allPaths, 1000).Error; err != nil {
			return fmt.Errorf("failed to bulk insert unique paths: %v", err)
		}
	}

	// Query back only the keys, values, and paths we need to get their IDs
	keyMap := make(map[string]uint)
	valueMap := make(map[string]uint) // hash -> ID
	pathMap := make(map[string]uint)

	// Get key IDs for only the keys we need
	if len(keySet) > 0 {
		keyNames := make([]string, 0, len(keySet))
		for key := range keySet {
			keyNames = append(keyNames, key)
		}
		
		var dbKeys []model.EntitlementUniqueKey
		if err := ds.gormDB.Where("key IN ?", keyNames).Find(&dbKeys).Error; err != nil {
			return fmt.Errorf("failed to query unique keys: %v", err)
		}
		for _, key := range dbKeys {
			keyMap[key.Key] = key.ID
		}
	}

	// Get value IDs for only the values we need  
	if len(valueSet) > 0 {
		valueHashes := make([]string, 0, len(valueSet))
		for hash := range valueSet {
			valueHashes = append(valueHashes, hash)
		}
		
		var dbValues []model.EntitlementUniqueValue
		if err := ds.gormDB.Where("value_hash IN ?", valueHashes).Find(&dbValues).Error; err != nil {
			return fmt.Errorf("failed to query unique values: %v", err)
		}
		for _, value := range dbValues {
			valueMap[value.ValueHash] = value.ID
		}
	}

	// Get path IDs for only the paths we need
	if len(pathSet) > 0 {
		pathNames := make([]string, 0, len(pathSet))
		for path := range pathSet {
			pathNames = append(pathNames, path)
		}
		
		var dbPaths []model.EntitlementUniquePath
		if err := ds.gormDB.Where("path IN ?", pathNames).Find(&dbPaths).Error; err != nil {
			return fmt.Errorf("failed to query unique paths: %v", err)
		}
		for _, path := range dbPaths {
			pathMap[path.Path] = path.ID
		}
	}

	// Second pass: create web entries with resolved IDs
	for filePath, entPlist := range entDB {
		if len(entPlist) == 0 {
			continue
		}

		pathID, exists := pathMap[filePath]
		if !exists {
			continue // Skip if path not found
		}

		// Parse entitlement plist
		ents := make(map[string]any)
		if err := plist.NewDecoder(bytes.NewReader([]byte(entPlist))).Decode(&ents); err != nil {
			continue // Skip invalid plists
		}

		for key, value := range ents {
			keyID, keyExists := keyMap[key]
			if !keyExists {
				continue
			}

			// Determine value string and type (same logic as before)
			var valueStr, valueType string
			switch v := value.(type) {
			case bool:
				valueType = "bool"
				if v {
					valueStr = "true"
				} else {
					valueStr = "false"
				}
			case string:
				valueType = "string"
				valueStr = v
			case int, int64, uint64:
				valueType = "number"
				if num, ok := v.(int64); ok {
					valueStr = fmt.Sprintf("%d", num)
				} else if num, ok := v.(int); ok {
					valueStr = fmt.Sprintf("%d", num)
				} else if num, ok := v.(uint64); ok {
					valueStr = fmt.Sprintf("%d", num)
				}
			case []any:
				valueType = "array"
				if jsonData, err := json.Marshal(v); err == nil {
					valueStr = string(jsonData)
				}
			case map[string]any:
				valueType = "dict"
				if jsonData, err := json.Marshal(v); err == nil {
					valueStr = string(jsonData)
				}
			default:
				valueType = "unknown"
				valueStr = fmt.Sprintf("%v", v)
			}

			valueHash := createValueHash(valueType, valueStr)
			valueID, valueExists := valueMap[valueHash]
			if !valueExists {
				continue
			}

			// Create web entry
			webEntry := model.EntitlementWebSearch{
				IOSVersion: ipswRecord.Version,
				BuildID:    ipswRecord.BuildID,
				DeviceList: deviceList,
				PathID:     pathID,
				KeyID:      keyID,
				ValueID:    valueID,
			}
			webEntries = append(webEntries, webEntry)
		}
	}

	// Bulk insert web entries with ON CONFLICT DO NOTHING
	if len(webEntries) > 0 {
		if err := ds.gormDB.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(webEntries, 1000).Error; err != nil {
			return fmt.Errorf("failed to bulk insert web entries: %v", err)
		}
	}

	return nil
}

// storeEntitlement stores entitlement data directly to the normalized structure
func (ds *DatabaseService) storeEntitlement(ipswRecord *model.Ipsw, filePath, entPlist string) error {
	if ds.gormDB == nil {
		return fmt.Errorf("GORM database required for normalized entitlement storage")
	}

	// Parse entitlement plist if not empty
	if len(entPlist) > 0 {
		ents := make(map[string]any)
		if err := plist.NewDecoder(bytes.NewReader([]byte(entPlist))).Decode(&ents); err == nil {
			// Build device list string
			var deviceNames []string
			for _, device := range ipswRecord.Devices {
				deviceNames = append(deviceNames, device.Name)
			}
			deviceList := strings.Join(deviceNames, ",")

			// Process each entitlement key-value pair directly
			for key, value := range ents {
				// Get or create unique key ID
				keyID, err := ds.getOrCreateUniqueKey(key)
				if err != nil {
					return fmt.Errorf("failed to get unique key ID for '%s': %v", key, err)
				}

				// Determine the value string and type based on value type
				var valueStr, valueType string
				switch v := value.(type) {
				case bool:
					valueType = "bool"
					if v {
						valueStr = "true"
					} else {
						valueStr = "false"
					}
				case string:
					valueType = "string"
					valueStr = v
				case int, int64, uint64:
					valueType = "number"
					if num, ok := v.(int64); ok {
						valueStr = fmt.Sprintf("%d", num)
					} else if num, ok := v.(int); ok {
						valueStr = fmt.Sprintf("%d", num)
					} else if num, ok := v.(uint64); ok {
						valueStr = fmt.Sprintf("%d", num)
					}
				case []any:
					valueType = "array"
					if jsonData, err := json.Marshal(v); err == nil {
						valueStr = string(jsonData)
					}
				case map[string]any:
					valueType = "dict"
					if jsonData, err := json.Marshal(v); err == nil {
						valueStr = string(jsonData)
					}
				default:
					valueType = "unknown"
					valueStr = fmt.Sprintf("%v", v)
				}

				// Get or create unique value ID
				valueID, err := ds.getOrCreateUniqueValue(valueType, valueStr)
				if err != nil {
					return fmt.Errorf("failed to get unique value ID for '%s' (type: %s): %v", valueStr, valueType, err)
				}

				// Get or create unique path ID
				pathID, err := ds.getOrCreateUniquePath(filePath)
				if err != nil {
					return fmt.Errorf("failed to get unique path ID for '%s': %v", filePath, err)
				}

				// Create or update web search entry (idempotent)
				webEntry := &model.EntitlementWebSearch{
					IOSVersion: ipswRecord.Version,
					BuildID:    ipswRecord.BuildID,
					DeviceList: deviceList,
					PathID:     pathID,
					KeyID:      keyID,
					ValueID:    valueID,
				}

				// Check if this exact combination already exists
				var existingEntry model.EntitlementWebSearch
				result := ds.gormDB.Where("ios_version = ? AND build_id = ? AND path_id = ? AND key_id = ? AND value_id = ?",
					webEntry.IOSVersion, webEntry.BuildID, webEntry.PathID, webEntry.KeyID, webEntry.ValueID).First(&existingEntry)

				if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
					return fmt.Errorf("failed to check existing web search entry: %v", result.Error)
				}

				if result.Error == gorm.ErrRecordNotFound {
					// Entry doesn't exist, create it
					if err := ds.gormDB.Create(webEntry).Error; err != nil {
						return fmt.Errorf("failed to create web search entry: %v", err)
					}
				}
				// If entry exists, skip it (idempotent behavior)
			}
		}
	}

	return nil
}

// generateIPSWID creates a unique ID for an IPSW based on version and build
func generateIPSWID(version, build string) string {
	return fmt.Sprintf("%s_%s", version, build)
}

// createValueHash creates a hash for a value to ensure uniqueness
func createValueHash(valueType, value string) string {
	hashInput := fmt.Sprintf("%s:%s", valueType, value)
	hash := sha256.Sum256([]byte(hashInput))
	return hex.EncodeToString(hash[:])
}

// getOrCreateUniqueKey ensures a unique key exists and returns its ID
func (ds *DatabaseService) getOrCreateUniqueKey(key string) (uint, error) {
	var uniqueKey model.EntitlementUniqueKey
	
	// Try to find existing key
	if err := ds.gormDB.Where("key = ?", key).First(&uniqueKey).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// Create new unique key
			uniqueKey = model.EntitlementUniqueKey{Key: key}
			if err := ds.gormDB.Create(&uniqueKey).Error; err != nil {
				return 0, fmt.Errorf("failed to create unique key: %v", err)
			}
		} else {
			return 0, fmt.Errorf("failed to query unique key: %v", err)
		}
	}
	
	return uniqueKey.ID, nil
}

// getOrCreateUniqueValue ensures a unique value exists and returns its ID
func (ds *DatabaseService) getOrCreateUniqueValue(valueType, value string) (uint, error) {
	valueHash := createValueHash(valueType, value)
	var uniqueValue model.EntitlementUniqueValue
	
	// Try to find existing value
	if err := ds.gormDB.Where("value_hash = ?", valueHash).First(&uniqueValue).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// Create new unique value
			uniqueValue = model.EntitlementUniqueValue{
				Value:     value,
				ValueType: valueType,
				ValueHash: valueHash,
			}
			if err := ds.gormDB.Create(&uniqueValue).Error; err != nil {
				return 0, fmt.Errorf("failed to create unique value: %v", err)
			}
		} else {
			return 0, fmt.Errorf("failed to query unique value: %v", err)
		}
	}
	
	return uniqueValue.ID, nil
}

// getOrCreateUniquePath ensures a unique path exists and returns its ID
func (ds *DatabaseService) getOrCreateUniquePath(path string) (uint, error) {
	var uniquePath model.EntitlementUniquePath
	
	// Try to find existing path
	if err := ds.gormDB.Where("path = ?", path).First(&uniquePath).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// Create new unique path
			uniquePath = model.EntitlementUniquePath{Path: path}
			if err := ds.gormDB.Create(&uniquePath).Error; err != nil {
				return 0, fmt.Errorf("failed to create unique path: %v", err)
			}
		} else {
			return 0, fmt.Errorf("failed to query unique path: %v", err)
		}
	}
	
	return uniquePath.ID, nil
}

// GetIOSVersions returns all available iOS versions in the database
func (ds *DatabaseService) GetIOSVersions() ([]string, error) {
	if ds.gormDB == nil {
		return nil, fmt.Errorf("GORM database required for version queries")
	}

	var versions []string
	if err := ds.gormDB.Model(&model.EntitlementWebSearch{}).
		Distinct("ios_version").
		Order("ios_version DESC").
		Pluck("ios_version", &versions).Error; err != nil {
		return nil, fmt.Errorf("failed to get iOS versions: %v", err)
	}

	return versions, nil
}

// SearchWebEntitlements performs optimized queries for the web UI
func (ds *DatabaseService) SearchWebEntitlements(version, keyPattern, filePattern string, limit int) ([]*model.EntitlementWebSearch, error) {
	if ds.gormDB == nil {
		return nil, fmt.Errorf("GORM database required for web search")
	}

	query := ds.gormDB.Model(&model.EntitlementWebSearch{}).
		Preload("UniquePath").
		Preload("UniqueKey").
		Preload("UniqueValue")

	// Filter by iOS version (required for optimal HTTP_RANGE performance)
	if version != "" {
		query = query.Where("ios_version = ?", version)
	}

	// Filter by key pattern (now requires join with unique keys table)
	if keyPattern != "" {
		query = query.Joins("JOIN entitlement_unique_keys ON entitlement_unique_keys.id = entitlement_keys.key_id").
			Where("entitlement_unique_keys.key LIKE ?", "%"+keyPattern+"%")
	}

	// Filter by file pattern (now requires join with unique paths table)
	if filePattern != "" {
		query = query.Joins("JOIN entitlement_unique_paths ON entitlement_unique_paths.id = entitlement_keys.path_id").
			Where("entitlement_unique_paths.path LIKE ?", "%"+filePattern+"%")
	}

	// Order by path_id for consistent results
	query = query.Order("path_id, key_id")

	// Apply limit
	if limit > 0 {
		query = query.Limit(limit)
	}

	var results []*model.EntitlementWebSearch
	if err := query.Find(&results).Error; err != nil {
		return nil, fmt.Errorf("failed to search web entitlements: %v", err)
	}

	return results, nil
}

// GetStatistics returns database statistics using the new normalized structure
func (ds *DatabaseService) GetStatistics() (map[string]interface{}, error) {
	if ds.gormDB == nil {
		return nil, fmt.Errorf("statistics not supported with this database type")
	}

	stats := make(map[string]interface{})

	var ipswCount int64
	if err := ds.gormDB.Model(&model.Ipsw{}).Count(&ipswCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count IPSWs: %v", err)
	}
	stats["ipsw_count"] = ipswCount

	var mappingCount int64
	if err := ds.gormDB.Model(&model.EntitlementWebSearch{}).Count(&mappingCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count entitlement mappings: %v", err)
	}
	stats["entitlement_mapping_count"] = mappingCount

	var uniqueKeyCount int64
	if err := ds.gormDB.Model(&model.EntitlementUniqueKey{}).Count(&uniqueKeyCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count unique keys: %v", err)
	}
	stats["unique_key_count"] = uniqueKeyCount

	var uniqueValueCount int64
	if err := ds.gormDB.Model(&model.EntitlementUniqueValue{}).Count(&uniqueValueCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count unique values: %v", err)
	}
	stats["unique_value_count"] = uniqueValueCount

	var uniquePathCount int64
	if err := ds.gormDB.Model(&model.EntitlementUniquePath{}).Count(&uniquePathCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count unique paths: %v", err)
	}
	stats["unique_path_count"] = uniquePathCount

	// Get top 10 most common entitlement keys
	var topKeys []struct {
		Key   string
		Count int64
	}
	if err := ds.gormDB.Table("entitlement_keys ek").
		Joins("JOIN entitlement_unique_keys uk ON uk.id = ek.key_id").
		Select("uk.key, COUNT(*) as count").
		Group("uk.key").
		Order("COUNT(*) DESC").  // Use COUNT(*) instead of alias in ORDER BY
		Limit(10).
		Scan(&topKeys).Error; err != nil {
		return nil, fmt.Errorf("failed to get top keys: %v", err)
	}
	stats["top_keys"] = topKeys

	// Get top 10 least common entitlement keys (excluding single occurrences)
	var leastKeys []struct {
		Key   string
		Count int64
	}
	if err := ds.gormDB.Table("entitlement_keys ek").
		Joins("JOIN entitlement_unique_keys uk ON uk.id = ek.key_id").
		Select("uk.key, COUNT(*) as count").
		Group("uk.key").
		Having("COUNT(*) > 1").  // Use COUNT(*) instead of alias in HAVING clause
		Order("COUNT(*) ASC").   // Use COUNT(*) instead of alias in ORDER BY
		Limit(10).
		Scan(&leastKeys).Error; err != nil {
		return nil, fmt.Errorf("failed to get least common keys: %v", err)
	}
	stats["least_keys"] = leastKeys

	return stats, nil
}