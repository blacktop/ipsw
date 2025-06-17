package model

import (
	"time"
)


// EntitlementUniqueKey represents unique entitlement keys
type EntitlementUniqueKey struct {
	ID  uint   `gorm:"primaryKey" json:"id"`
	Key string `gorm:"uniqueIndex;not null" json:"key"`
}

// EntitlementUniqueValue represents unique entitlement values with their types
type EntitlementUniqueValue struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Value     string `gorm:"type:text;not null" json:"value"`
	ValueType string `gorm:"not null" json:"value_type"` // bool, string, array, dict, number
	ValueHash string `gorm:"uniqueIndex;not null" json:"value_hash"` // hash of type:value for uniqueness
}

// EntitlementUniquePath represents unique file paths
type EntitlementUniquePath struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Path string `gorm:"uniqueIndex;not null" json:"path"`
}

// EntitlementWebSearch represents the optimized mapping table for web queries
// This replaces the denormalized table with foreign key references
type EntitlementWebSearch struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	IOSVersion  string    `gorm:"index:idx_version_key,priority:1;not null" json:"ios_version"`
	BuildID     string    `gorm:"index;not null" json:"build_id"`
	DeviceList  string    `gorm:"index" json:"device_list"` // comma-separated device names
	PathID      uint      `gorm:"index:idx_version_path,priority:2;not null" json:"path_id"`
	KeyID       uint      `gorm:"index:idx_version_key,priority:2;not null" json:"key_id"`
	ValueID     uint      `gorm:"index;not null" json:"value_id"`
	ReleaseDate *time.Time `json:"release_date,omitempty"`
	
	// Foreign key relationships
	UniquePath  *EntitlementUniquePath  `gorm:"foreignKey:PathID" json:"unique_path,omitempty"`
	UniqueKey   *EntitlementUniqueKey   `gorm:"foreignKey:KeyID" json:"unique_key,omitempty"`
	UniqueValue *EntitlementUniqueValue `gorm:"foreignKey:ValueID" json:"unique_value,omitempty"`
}

// TableName returns the table name for EntitlementWebSearch
func (EntitlementWebSearch) TableName() string {
	return "entitlement_keys" // Match the expected table name in web UI
}

// EntitlementQuery represents query parameters for searching entitlements
type EntitlementQuery struct {
	Version      string
	Build        string
	Device       string
	KeyPattern   string
	ValuePattern string
	FilePath     string
}
