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

// EntitlementQuery represents query parameters for searching entitlements
type EntitlementQuery struct {
	Version      string
	Build        string
	Device       string
	KeyPattern   string
	ValuePattern string
	FilePath     string
}
