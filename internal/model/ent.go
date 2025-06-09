package model

import (
	"time"
)

// Entitlement represents an entitlement entry for a specific file
type Entitlement struct {
	ID        uint              `gorm:"primaryKey" json:"id"`
	FilePath  string            `gorm:"index;not null" json:"file_path"`
	IpswID    string            `gorm:"index" json:"ipsw_id"`
	Ipsw      *Ipsw             `gorm:"foreignKey:IpswID" json:"ipsw,omitempty"`
	RawPlist  string            `gorm:"type:text" json:"raw_plist,omitempty"`
	Keys      []*EntitlementKey `gorm:"foreignKey:EntitlementID" json:"keys,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// EntitlementKey represents a specific entitlement key-value pair
type EntitlementKey struct {
	ID            uint   `gorm:"primaryKey" json:"id"`
	EntitlementID uint   `gorm:"index;not null" json:"entitlement_id"`
	Key           string `gorm:"index;not null" json:"key"`
	ValueType     string `gorm:"not null" json:"value_type"` // bool, string, array, dict, number
	StringValue   string `json:"string_value,omitempty"`
	BoolValue     *bool  `json:"bool_value,omitempty"`
	NumberValue   *int64 `json:"number_value,omitempty"`
	ArrayValue    string `gorm:"type:text" json:"array_value,omitempty"` // JSON encoded
	DictValue     string `gorm:"type:text" json:"dict_value,omitempty"`  // JSON encoded
}

// TableName returns the table name for EntitlementKey
func (EntitlementKey) TableName() string {
	return "entitlement_keys_normalized" // Use a different table name to avoid conflicts
}

// EntitlementWebSearch represents a denormalized table optimized for web queries
// This table is designed to be efficient for HTTP_RANGE requests and sql.js-httpvfs
type EntitlementWebSearch struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	IOSVersion   string `gorm:"index:idx_version_key,priority:1;not null" json:"ios_version"`
	BuildID      string `gorm:"index;not null" json:"build_id"`
	DeviceList   string `gorm:"index" json:"device_list"` // comma-separated device names
	FilePath     string `gorm:"index:idx_version_file,priority:2;not null" json:"file_path"`
	Key          string `gorm:"index:idx_version_key,priority:2;not null" json:"key"`
	ValueType    string `gorm:"not null" json:"value_type"`
	StringValue  string `gorm:"index" json:"string_value,omitempty"`
	BoolValue    *bool  `json:"bool_value,omitempty"`
	NumberValue  *int64 `json:"number_value,omitempty"`
	ArrayValue   string `gorm:"type:text" json:"array_value,omitempty"`
	DictValue    string `gorm:"type:text" json:"dict_value,omitempty"`
	ReleaseDate  *time.Time `json:"release_date,omitempty"`
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
