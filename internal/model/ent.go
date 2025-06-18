package model

// EntitlementKey represents unique entitlement keys
type EntitlementKey struct {
	ID  uint   `gorm:"primaryKey" json:"id"`
	Key string `gorm:"type:text;uniqueIndex;not null" json:"key"`
}

// TableName returns the table name for EntitlementKey
func (EntitlementKey) TableName() string {
	return "entitlement_keys"
}

// EntitlementValue represents unique entitlement values with their types
type EntitlementValue struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Value     string `gorm:"type:text;not null" json:"value"`
	ValueType string `gorm:"type:varchar(10);not null;check:value_type IN ('bool','string','array','dict','number')" json:"value_type"`
	ValueHash string `gorm:"type:char(16);uniqueIndex;not null" json:"value_hash"` // Shortened hash for uniqueness
}

// TableName returns the table name for EntitlementValue
func (EntitlementValue) TableName() string {
	return "entitlement_values"
}

// Entitlement represents the mapping between keys, values, paths and IPSWs
type Entitlement struct {
	ID      uint64 `gorm:"primaryKey" json:"id"`
	IpswID  string `gorm:"uniqueIndex:idx_unique_entitlement,priority:1;not null" json:"ipsw_id"`
	PathID  uint   `gorm:"uniqueIndex:idx_unique_entitlement,priority:2;not null" json:"path_id"`
	KeyID   uint   `gorm:"uniqueIndex:idx_unique_entitlement,priority:3;not null" json:"key_id"`
	ValueID uint   `gorm:"uniqueIndex:idx_unique_entitlement,priority:4;not null" json:"value_id"`

	// Foreign key relationships
	Ipsw  *Ipsw             `gorm:"foreignKey:IpswID" json:"ipsw,omitempty"`
	Path  *Path             `gorm:"foreignKey:PathID" json:"path,omitempty"`
	Key   *EntitlementKey   `gorm:"foreignKey:KeyID" json:"key,omitempty"`
	Value *EntitlementValue `gorm:"foreignKey:ValueID" json:"value,omitempty"`
}

// TableName returns the table name for Entitlement
func (Entitlement) TableName() string {
	return "entitlements"
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
