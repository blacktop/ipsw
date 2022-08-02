package lockdown

import (
	"fmt"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/usb/types"
	"github.com/mitchellh/mapstructure"
)

type DeviceDetail struct {
	CPUArchitecture        string   `json:"cpu_architecture,omitempty"`
	ChipID                 uint64   `json:"chip_id,omitempty"`
	DeviceClass            string   `json:"device_class,omitempty"`
	DeviceName             string   `json:"device_name,omitempty"`
	HasSiDP                bool     `json:"has_sidp,omitempty"`
	ProductVersion         string   `json:"product_version,omitempty"`
	SupportedDeviceClasses []string `json:"supported_device_classes,omitempty"`
	BoardId                uint64   `json:"board_id,omitempty"`
	ProtocolVersion        string   `json:"protocol_version,omitempty"`
	UniqueDeviceID         string   `json:"unique_device_id,omitempty"`
	WiFiAddress            string   `json:"wifi_address,omitempty"`
	BuildVersion           string   `json:"build_version,omitempty"`
	HardwareModel          string   `json:"hardware_model,omitempty"`
	PartitionType          string   `json:"partition_type,omitempty"`
	ProductType            string   `json:"product_type,omitempty"`
	TelephonyCapability    bool     `json:"telephony_capability,omitempty"`
	UniqueChipID           uint64   `json:"unique_chip_id,omitempty"`
	DeviceColor            string   `json:"device_color,omitempty"`
	DieID                  uint64   `json:"die_id,omitempty"`
	ProductName            string   `json:"product_name,omitempty"`
	ProductionSOC          bool     `json:"production_soc,omitempty"`
}

type ValueRequest struct {
	Label           string      `plist:"Label"`
	ProtocolVersion string      `plist:"ProtocolVersion"`
	Request         RequestType `plist:"Request"`
	Domain          string      `plist:"Domain,omitempty"`
	Key             string      `plist:"Key,omitempty"`
	Value           interface{} `plist:"Value,omitempty"`
}

type ValueResponse struct {
	Request string      `plist:"Request"`
	Error   string      `plist:"Error"`
	Key     string      `plist:"Key"`
	Value   interface{} `plist:"Value"`
}

func (ld *Client) GetValue(dev types.Device, domain, key string) (*ValueResponse, error) {

	data, err := plist.Marshal(ValueRequest{
		Label:           types.BundleID,
		ProtocolVersion: protocolVersion,
		Request:         "GetValue",
		Domain:          domain,
		Key:             key,
	}, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	if err := ld.SendData(data); err != nil {
		return nil, fmt.Errorf("failed to send lockdown get value request: %v", err)
	}

	resp := &ValueResponse{}
	if err := ld.ReadData(resp); err != nil {
		return nil, fmt.Errorf("failed to read lockdown get value response: %v", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf(resp.Error)
	}

	return resp, nil
}

func (ld *Client) GetDeviceDetail(dev types.Device) (*DeviceDetail, error) {
	v, err := ld.GetValue(dev, "", "")
	if err != nil {
		return nil, err
	}

	var dd DeviceDetail
	if err := mapstructure.Decode(v.Value, &dd); err != nil {
		return nil, err
	}

	return &dd, nil
}
