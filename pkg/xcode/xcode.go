//go:generate statik -src=./data -dest=../..

package xcode

import (
	"encoding/json"
	"io/ioutil"

	// importing statik data
	_ "github.com/blacktop/ipsw/statik"
	"github.com/rakyll/statik/fs"
)

// Device object
type Device struct {
	Target                   string      `gorm:"column:Target;primary_key" json:"target,omitempty"`
	TargetType               string      `gorm:"column:TargetType" json:"target_type,omitempty"`
	TargetVariant            string      `gorm:"column:TargetVariant" json:"target_variant,omitempty"`
	Platform                 string      `gorm:"column:Platform" json:"platform,omitempty"`
	ProductType              string      `gorm:"column:ProductType" json:"product_type,omitempty"`
	ProductDescription       string      `gorm:"column:ProductDescription" json:"product_description,omitempty"`
	CompatibleDeviceFallback string      `gorm:"column:CompatibleDeviceFallback" json:"compatible_device_fallback,omitempty"`
	DeviceTrait              DeviceTrait `gorm:"foreignkey:DeviceTraitSet" json:"traits,omitempty"`
	DeviceTraitSet           int         `gorm:"column:DeviceTraitSet" json:"-"`
}

// TableName returns the table name for the Device object
func (Device) TableName() string {
	return "Devices"
}

type Devices []Device

func (d Devices) Len() int      { return len(d) }
func (d Devices) Swap(i, j int) { d[i], d[j] = d[j], d[i] }

type ByProductType struct{ Devices }

func (s ByProductType) Less(i, j int) bool { return s.Devices[i].ProductType < s.Devices[j].ProductType }

// DeviceTrait object
type DeviceTrait struct {
	DeviceTraitSetID             int    `gorm:"column:DeviceTraitSetID;primary_key" json:"-"`
	PreferredArchitecture        string `gorm:"column:PreferredArchitecture" json:"preferred_architecture,omitempty"`
	ArtworkDeviceIdiom           string `gorm:"column:ArtworkDeviceIdiom" json:"artwork_device_idiom,omitempty"`
	ArtworkHostedIdioms          string `gorm:"column:ArtworkHostedIdioms" json:"artwork_hosted_idioms,omitempty"`
	ArtworkScaleFactor           int    `gorm:"column:ArtworkScaleFactor" json:"artwork_scale_factor,omitempty"`
	ArtworkDeviceSubtype         int    `gorm:"column:ArtworkDeviceSubtype" json:"artwork_device_subtype,omitempty"`
	ArtworkDisplayGamut          string `gorm:"column:ArtworkDisplayGamut" json:"artwork_display_gamut,omitempty"`
	ArtworkDynamicDisplayMode    string `gorm:"column:ArtworkDynamicDisplayMode" json:"artwork_dynamic_display_mode,omitempty"`
	DevicePerformanceMemoryClass int    `gorm:"column:DevicePerformanceMemoryClass" json:"device_performance_memory_class,omitempty"`
	GraphicsFeatureSetClass      string `gorm:"column:GraphicsFeatureSetClass" json:"graphics_feature_set_class,omitempty"`
	GraphicsFeatureSetFallbacks  string `gorm:"column:GraphicsFeatureSetFallbacks" json:"graphics_feature_set_fallbacks,omitempty"`
}

// TableName returns the table name for the DeviceTrait object
func (DeviceTrait) TableName() string {
	return "DeviceTraits"
}

// WriteToJSON writes the data to JSON
func WriteToJSON(devices []Device) error {
	dJSON, err := json.Marshal(devices)
	if err != nil {
		return err
	}
	return ioutil.WriteFile("xcode/data/device_traits.json", dJSON, 0644)
}

// GetDevices reads the devices from embedded JSON
func GetDevices() ([]Device, error) {
	var devices []Device

	statikFS, err := fs.New()
	if err != nil {
		return nil, err
	}
	traits, err := statikFS.Open("/device_traits.json")
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(traits)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &devices)
	if err != nil {
		return nil, err
	}

	return devices, nil
}
