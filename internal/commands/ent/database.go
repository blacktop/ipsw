package ent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/pkg/info"
	"gorm.io/gorm"
)

// DatabaseService handles entitlement database operations
type DatabaseService struct {
	db     db.Database
	gormDB *gorm.DB
}

// NewDatabaseService creates a new database service for entitlements
func NewDatabaseService(database db.Database) *DatabaseService {
	service := &DatabaseService{db: database}

	// Try to get the underlying GORM DB for advanced queries
	if sqliteDB, ok := database.(*db.Sqlite); ok {
		service.gormDB = sqliteDB.GetDB()
	}

	return service
}

// StoreEntitlements processes and stores entitlements for either IPSW or folder input
func (ds *DatabaseService) StoreEntitlements(ipswPath string, entDB map[string]string) error {
	var ipswRecord *model.Ipsw

	// Handle IPSW vs folder input
	if ipswPath != "" {
		// Parse IPSW info to get metadata
		i, err := info.Parse(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW: %v", err)
		}

		// Create or get IPSW record
		ipswRecord = &model.Ipsw{
			ID:      generateIPSWID(i.Plists.BuildManifest.ProductVersion, i.Plists.BuildManifest.ProductBuildVersion),
			Name:    filepath.Base(ipswPath),
			Version: i.Plists.BuildManifest.ProductVersion,
			BuildID: i.Plists.BuildManifest.ProductBuildVersion,
		}

		// Add supported devices
		for _, deviceType := range i.Plists.BuildManifest.SupportedProductTypes {
			device := &model.Device{Name: deviceType}
			ipswRecord.Devices = append(ipswRecord.Devices, device)
		}

		// Create IPSW record (will be skipped if exists)
		if err := ds.db.Create(ipswRecord); err != nil {
			// Continue even if IPSW already exists
		}
	} else {
		// For folder input, create a generic record
		ipswRecord = &model.Ipsw{
			ID:      "folder-input",
			Name:    "Folder Input",
			Version: "unknown",
			BuildID: "unknown",
		}
	}

	// Store entitlements
	for filePath, entPlist := range entDB {
		if err := ds.storeEntitlement(ipswRecord.ID, filePath, entPlist); err != nil {
			return fmt.Errorf("failed to store entitlement for %s: %v", filePath, err)
		}
	}

	return nil
}

// storeEntitlement stores a single entitlement record
func (ds *DatabaseService) storeEntitlement(ipswID, filePath, entPlist string) error {
	entitlement := &model.Entitlement{
		FilePath: filePath,
		IpswID:   ipswID,
		RawPlist: entPlist,
	}

	// Parse entitlement plist if not empty
	if len(entPlist) > 0 {
		ents := make(map[string]any)
		if err := plist.NewDecoder(bytes.NewReader([]byte(entPlist))).Decode(&ents); err == nil {
			// Parse each entitlement key-value pair
			for key, value := range ents {
				entKey := &model.EntitlementKey{
					Key: key,
				}

				switch v := value.(type) {
				case bool:
					entKey.ValueType = "bool"
					entKey.BoolValue = &v
				case string:
					entKey.ValueType = "string"
					entKey.StringValue = v
				case int, int64, uint64:
					entKey.ValueType = "number"
					if num, ok := v.(int64); ok {
						entKey.NumberValue = &num
					} else if num, ok := v.(int); ok {
						num64 := int64(num)
						entKey.NumberValue = &num64
					} else if num, ok := v.(uint64); ok {
						num64 := int64(num)
						entKey.NumberValue = &num64
					}
				case []any:
					entKey.ValueType = "array"
					if jsonData, err := json.Marshal(v); err == nil {
						entKey.ArrayValue = string(jsonData)
					}
				case map[string]any:
					entKey.ValueType = "dict"
					if jsonData, err := json.Marshal(v); err == nil {
						entKey.DictValue = string(jsonData)
					}
				default:
					entKey.ValueType = "unknown"
					entKey.StringValue = fmt.Sprintf("%v", v)
				}

				entitlement.Keys = append(entitlement.Keys, entKey)
			}
		}
	}

	return ds.db.Create(entitlement)
}

// SearchEntitlements searches for entitlements based on criteria
func (ds *DatabaseService) SearchEntitlements(query *model.EntitlementQuery) ([]*model.Entitlement, error) {
	// Use the database-specific search method
	if sqliteDB, ok := ds.db.(*db.Sqlite); ok {
		return sqliteDB.SearchEntitlements(query)
	}
	return nil, fmt.Errorf("search not implemented for this database type")
}

// GetEntitlementsByIPSW gets all entitlements for an IPSW
func (ds *DatabaseService) GetEntitlementsByIPSW(ipswID string) ([]*model.Entitlement, error) {
	if sqliteDB, ok := ds.db.(*db.Sqlite); ok {
		return sqliteDB.GetEntitlementsByIPSW(ipswID)
	}
	return nil, fmt.Errorf("method not implemented for this database type")
}

// generateIPSWID creates a unique ID for an IPSW based on version and build
func generateIPSWID(version, build string) string {
	return fmt.Sprintf("%s_%s", version, build)
}

// GetIPSWsWithEntitlements returns all IPSWs that have entitlement data
func (ds *DatabaseService) GetIPSWsWithEntitlements() ([]*model.Ipsw, error) {
	// This would need to be implemented based on the specific database interface
	// For now, return error indicating not implemented
	return nil, fmt.Errorf("GetIPSWsWithEntitlements not yet implemented")
}

// QueryEntitlementsByKey searches for entitlements containing a specific key pattern
func (ds *DatabaseService) QueryEntitlementsByKey(keyPattern string) ([]*model.Entitlement, error) {
	if ds.gormDB == nil {
		return nil, fmt.Errorf("advanced queries not supported with this database type")
	}

	var entitlements []*model.Entitlement
	if err := ds.gormDB.Preload("Keys", "key LIKE ?", "%"+keyPattern+"%").
		Preload("Ipsw").
		Find(&entitlements).Error; err != nil {
		return nil, fmt.Errorf("failed to query entitlements by key: %v", err)
	}
	return entitlements, nil
}

// QueryEntitlementsByValue searches for entitlements containing a specific value pattern
func (ds *DatabaseService) QueryEntitlementsByValue(valuePattern string) ([]*model.Entitlement, error) {
	if ds.gormDB == nil {
		return nil, fmt.Errorf("advanced queries not supported with this database type")
	}

	var entitlements []*model.Entitlement
	if err := ds.gormDB.Preload("Keys", "string_value LIKE ? OR array_value LIKE ? OR dict_value LIKE ?",
		"%"+valuePattern+"%", "%"+valuePattern+"%", "%"+valuePattern+"%").
		Preload("Ipsw").
		Find(&entitlements).Error; err != nil {
		return nil, fmt.Errorf("failed to query entitlements by value: %v", err)
	}
	return entitlements, nil
}

// QueryEntitlementsByFile searches for entitlements for a specific file path pattern
func (ds *DatabaseService) QueryEntitlementsByFile(filePattern string) ([]*model.Entitlement, error) {
	if ds.gormDB == nil {
		return nil, fmt.Errorf("advanced queries not supported with this database type")
	}

	var entitlements []*model.Entitlement
	if err := ds.gormDB.Preload("Keys").
		Preload("Ipsw").
		Where("file_path LIKE ?", "%"+filePattern+"%").
		Find(&entitlements).Error; err != nil {
		return nil, fmt.Errorf("failed to query entitlements by file: %v", err)
	}
	return entitlements, nil
}

// QueryEntitlementsByIPSW searches for entitlements for a specific IPSW version/build
func (ds *DatabaseService) QueryEntitlementsByIPSW(version, build string) ([]*model.Entitlement, error) {
	if ds.gormDB == nil {
		return nil, fmt.Errorf("advanced queries not supported with this database type")
	}

	var entitlements []*model.Entitlement
	query := ds.gormDB.Preload("Keys").Preload("Ipsw")

	if version != "" {
		query = query.Joins("JOIN ipsws ON ipsws.id = entitlements.ipsw_id").
			Where("ipsws.version = ?", version)
	}
	if build != "" {
		query = query.Joins("JOIN ipsws ON ipsws.id = entitlements.ipsw_id").
			Where("ipsws.build_id = ?", build)
	}

	if err := query.Find(&entitlements).Error; err != nil {
		return nil, fmt.Errorf("failed to query entitlements by IPSW: %v", err)
	}
	return entitlements, nil
}

// GetStatistics returns database statistics
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

	var entitlementCount int64
	if err := ds.gormDB.Model(&model.Entitlement{}).Count(&entitlementCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count entitlements: %v", err)
	}
	stats["entitlement_count"] = entitlementCount

	var keyCount int64
	if err := ds.gormDB.Model(&model.EntitlementKey{}).Count(&keyCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count entitlement keys: %v", err)
	}
	stats["key_count"] = keyCount

	// Get top 10 most common entitlement keys
	var topKeys []struct {
		Key   string
		Count int64
	}
	if err := ds.gormDB.Model(&model.EntitlementKey{}).
		Select("key, COUNT(*) as count").
		Group("key").
		Order("count DESC").
		Limit(10).
		Scan(&topKeys).Error; err != nil {
		return nil, fmt.Errorf("failed to get top keys: %v", err)
	}
	stats["top_keys"] = topKeys

	return stats, nil
}
