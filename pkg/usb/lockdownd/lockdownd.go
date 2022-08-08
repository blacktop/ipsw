package lockdownd

import (
	"fmt"

	"github.com/blacktop/ipsw/pkg/usb"
)

type Client struct {
	*usb.Client
}

type startSessionRequest struct {
	Label           string
	ProtocolVersion string
	Request         string
	HostID          string
	SystemBUID      string
}

type startSessionResponse struct {
	Request          string
	Result           string
	EnableSessionSSL bool
	SessionID        string
}

func NewClient(udid string) (*Client, error) {
	cli, err := usb.NewClient(udid, 62078)
	if err != nil {
		return nil, err
	}
	req := &startSessionRequest{
		Label:           usb.BundleID,
		ProtocolVersion: "2",
		Request:         "StartSession",
		HostID:          cli.PairRecord().HostID,
		SystemBUID:      cli.PairRecord().SystemBUID,
	}
	var resp startSessionResponse
	if err := cli.Request(req, &resp); err != nil {
		return nil, err
	}

	if resp.EnableSessionSSL {
		if err := cli.EnableSSL(); err != nil {
			return nil, err
		}
	}

	return &Client{cli}, nil
}

func NewClientForService(serviceName, udid string, withEscrowBag bool) (*usb.Client, error) {
	lc, err := NewClient(udid)
	if err != nil {
		return nil, err
	}
	defer func(lc *Client) {
		_ = lc.Close()
	}(lc)

	svc, err := lc.StartService(serviceName, withEscrowBag)
	if err != nil {
		return nil, err
	}

	cli, err := usb.NewClient(udid, svc.Port)
	if err != nil {
		return nil, err
	}
	if svc.EnableServiceSSL {
		_ = cli.EnableSSL()
	}

	return cli, nil
}

type startServiceRequest struct {
	Label     string
	Request   string `plist:"Request"`
	Service   string
	EscrowBag []byte `plist:",omitempty"`
}

type StartServiceResponse struct {
	Request          string
	Result           string
	Service          string
	Port             int
	EnableServiceSSL bool
}

func (lc *Client) StartService(service string, withEscrowBag bool) (*StartServiceResponse, error) {
	req := &startServiceRequest{
		Label:   usb.BundleID,
		Request: "StartService",
		Service: service,
	}
	if withEscrowBag {
		req.EscrowBag = lc.PairRecord().EscrowBag
	}

	var resp StartServiceResponse
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

type DeviceValues struct {
	ActivationState             string `plist:"ActivationState,omitempty" json:"activation_state,omitempty"`
	ActivationStateAcknowledged bool   `plist:"ActivationStateAcknowledged,omitempty" json:"activation_state_acknowledged,omitempty"`
	BasebandCertId              int    `plist:"BasebandCertId,omitempty" json:"baseband_cert_id,omitempty"`
	BasebandKeyHashInformation  struct {
		AKeyStatus int    `plist:"AKeyStatus,omitempty" json:"a_key_status,omitempty"`
		SKeyHash   []byte `plist:"SKeyHash,omitempty" json:"s_key_hash,omitempty"`
		SKeyStatus int    `plist:"SKeyStatus,omitempty" json:"s_key_status,omitempty"`
	} `plist:"BasebandKeyHashInformation,omitempty" json:"baseband_key_hash_information,omitempty"`
	BasebandMasterKeyHash                         string           `plist:"BasebandMasterKeyHash,omitempty" json:"baseband_master_key_hash,omitempty"`
	BasebandRegionSKU                             []byte           `plist:"BasebandRegionSKU,omitempty" json:"baseband_region_sku,omitempty"`
	BasebandSerialNumber                          []byte           `plist:"BasebandSerialNumber,omitempty" json:"baseband_serial_number,omitempty"`
	BasebandStatus                                string           `plist:"BasebandStatus,omitempty" json:"baseband_status,omitempty"`
	BasebandVersion                               string           `plist:"BasebandVersion,omitempty" json:"baseband_version,omitempty"`
	BluetoothAddress                              string           `plist:"BluetoothAddress,omitempty" json:"bluetooth_address,omitempty"`
	BoardId                                       int              `plist:"BoardId,omitempty" json:"board_id,omitempty"`
	BootSessionID                                 string           `plist:"BootSessionID,omitempty" json:"boot_session_id,omitempty"`
	BrickState                                    bool             `plist:"BrickState,omitempty" json:"brick_state,omitempty"`
	BuildVersion                                  string           `plist:"BuildVersion,omitempty" json:"build_version,omitempty"`
	CertID                                        int              `plist:"CertID,omitempty" json:"cert_id,omitempty"`
	ChipID                                        int              `plist:"ChipID,omitempty" json:"chip_id,omitempty"`
	ChipSerialNo                                  []byte           `plist:"ChipSerialNo,omitempty" json:"chip_serial_no,omitempty"`
	CPUArchitecture                               string           `plist:"CPUArchitecture,omitempty" json:"cpu_architecture,omitempty"`
	CarrierBundleInfoArray                        []map[string]any `plist:"CarrierBundleInfoArray,omitempty" json:"carrier_bundle_info_array,omitempty"`
	DeviceClass                                   string           `plist:"DeviceClass,omitempty" json:"device_class,omitempty"`
	DeviceColor                                   string           `plist:"DeviceColor,omitempty" json:"device_color,omitempty"`
	DeviceName                                    string           `plist:"DeviceName,omitempty" json:"device_name,omitempty"`
	DieID                                         int              `plist:"DieID,omitempty" json:"die_id,omitempty"`
	EthernetAddress                               string           `plist:"EthernetAddress,omitempty" json:"ethernet_address,omitempty"`
	FirmwareVersion                               string           `plist:"FirmwareVersion,omitempty" json:"firmware_version,omitempty"`
	FusingStatus                                  int              `plist:"FusingStatus,omitempty" json:"fusing_status,omitempty"`
	GID1                                          string           `plist:"GID1,omitempty" json:"gid_1,omitempty"`
	GID2                                          string           `plist:"GID2,omitempty" json:"gid_2,omitempty"`
	HardwareModel                                 string           `plist:"HardwareModel,omitempty" json:"hardware_model,omitempty"`
	HardwarePlatform                              string           `plist:"HardwarePlatform,omitempty" json:"hardware_platform,omitempty"`
	HasSiDP                                       bool             `plist:"HasSiDP,omitempty" json:"has_si_dp,omitempty"`
	HostAttached                                  bool             `plist:"HostAttached,omitempty" json:"host_attached,omitempty"`
	IntegratedCircuitCardIdentity                 string           `plist:"IntegratedCircuitCardIdentity,omitempty" json:"integrated_circuit_card_identity,omitempty"`
	InternationalMobileEquipmentIdentity          string           `plist:"InternationalMobileEquipmentIdentity,omitempty" json:"international_mobile_equipment_identity,omitempty"`
	InternationalMobileEquipmentIdentity2         string           `plist:"InternationalMobileEquipmentIdentity2,omitempty" json:"international_mobile_equipment_identity_2,omitempty"`
	InternationalMobileSubscriberIdentity         string           `plist:"InternationalMobileSubscriberIdentity,omitempty" json:"international_mobile_subscriber_identity,omitempty"`
	InternationalMobileSubscriberIdentityOverride bool             `plist:"InternationalMobileSubscriberIdentityOverride,omitempty" json:"international_mobile_subscriber_identity_override,omitempty"`
	MLBSerialNumber                               string           `plist:"MLBSerialNumber,omitempty" json:"mlb_serial_number,omitempty"`
	MobileEquipmentIdentifier                     string           `plist:"MobileEquipmentIdentifier,omitempty" json:"mobile_equipment_identifier,omitempty"`
	MobileSubscriberCountryCode                   string           `plist:"MobileSubscriberCountryCode,omitempty" json:"mobile_subscriber_country_code,omitempty"`
	MobileSubscriberNetworkCode                   string           `plist:"MobileSubscriberNetworkCode,omitempty" json:"mobile_subscriber_network_code,omitempty"`
	ModelNumber                                   string           `plist:"ModelNumber,omitempty" json:"model_number,omitempty"`
	NonVolatileRAM                                map[string]any   `plist:"NonVolatileRAM,omitempty" json:"non_volatile_ram,omitempty"`
	PRIVersion_Major                              int              `plist:"PRIVersion_Major,omitempty" json:"pri_version___major,omitempty"`
	PRIVersion_Minor                              int              `plist:"PRIVersion_Minor,omitempty" json:"pri_version___minor,omitempty"`
	PRIVersion_ReleaseNo                          int              `plist:"PRIVersion_ReleaseNo,omitempty" json:"pri_version___release_no,omitempty"`
	PairRecordProtectionClass                     int              `plist:"PairRecordProtectionClass,omitempty" json:"pair_record_protection_class,omitempty"`
	PartitionType                                 string           `plist:"PartitionType,omitempty" json:"partition_type,omitempty"`
	PasswordProtected                             bool             `plist:"PasswordProtected,omitempty" json:"password_protected,omitempty"`
	PhoneNumber                                   string           `plist:"PhoneNumber,omitempty" json:"phone_number,omitempty"`
	PkHash                                        []byte           `plist:"PkHash,omitempty" json:"pk_hash,omitempty"`
	ProductName                                   string           `plist:"ProductName,omitempty" json:"product_name,omitempty"`
	ProductType                                   string           `plist:"ProductType,omitempty" json:"product_type,omitempty"`
	ProductVersion                                string           `plist:"ProductVersion,omitempty" json:"product_version,omitempty"`
	ProductionSOC                                 bool             `plist:"ProductionSOC,omitempty" json:"production_soc,omitempty"`
	ProtocolVersion                               string           `plist:"ProtocolVersion,omitempty" json:"protocol_version,omitempty"`
	ProximitySensorCalibration                    []byte           `plist:"ProximitySensorCalibration,omitempty" json:"proximity_sensor_calibration,omitempty"`
	RegionInfo                                    string           `plist:"RegionInfo,omitempty" json:"region_info,omitempty"`
	ReleaseType                                   string           `plist:"ReleaseType,omitempty" json:"release_type,omitempty"`
	SIM1IsEmbedded                                bool             `plist:"SIM1IsEmbedded,omitempty" json:"sim_1_is_embedded,omitempty"`
	SIMGID1                                       []byte           `plist:"SIMGID1,omitempty" json:"simgid_1,omitempty"`
	SIMGID2                                       []byte           `plist:"SIMGID2,omitempty" json:"simgid_2,omitempty"`
	SIMStatus                                     any              `plist:"SIMStatus,omitempty" json:"sim_status,omitempty"`
	SIMTrayStatus                                 any              `plist:"SIMTrayStatus,omitempty" json:"sim_tray_status,omitempty"`
	SerialNumber                                  string           `plist:"SerialNumber,omitempty" json:"serial_number,omitempty"`
	SoftwareBehavior                              []byte           `plist:"SoftwareBehavior,omitempty" json:"software_behavior,omitempty"`
	SoftwareBundleVersion                         string           `plist:"SoftwareBundleVersion,omitempty" json:"software_bundle_version,omitempty"`
	SupportedDeviceFamilies                       []int            `plist:"SupportedDeviceFamilies,omitempty" json:"supported_device_families,omitempty"`
	TelephonyCapability                           bool             `plist:"TelephonyCapability,omitempty" json:"telephony_capability,omitempty"`
	TimeIntervalSince1970                         float64          `plist:"TimeIntervalSince1970,omitempty" json:"time_interval_since_1970,omitempty"`
	TimeZone                                      string           `plist:"TimeZone,omitempty" json:"time_zone,omitempty"`
	TimeZoneOffsetFromUTC                         float64          `plist:"TimeZoneOffsetFromUTC,omitempty" json:"time_zone_offset_from_utc,omitempty"`
	TrustedHostAttached                           bool             `plist:"TrustedHostAttached,omitempty" json:"trusted_host_attached,omitempty"`
	UniqueChipID                                  int64            `plist:"UniqueChipID,omitempty" json:"unique_chip_id,omitempty"`
	UniqueDeviceID                                string           `plist:"UniqueDeviceID,omitempty" json:"unique_device_id,omitempty"`
	UntrustedHostBUID                             string           `plist:"UntrustedHostBUID,omitempty" json:"untrusted_host_buid,omitempty"`
	UseRaptorCerts                                bool             `plist:"UseRaptorCerts,omitempty" json:"use_raptor_certs,omitempty"`
	Uses24HourClock                               bool             `plist:"Uses24HourClock,omitempty" json:"uses_24_hour_clock,omitempty"`
	WiFiAddress                                   string           `plist:"WiFiAddress,omitempty" json:"wi_fi_address,omitempty"`
	WirelessBoardSerialNumber                     string           `plist:"WirelessBoardSerialNumber,omitempty" json:"wireless_board_serial_number,omitempty"`
	CTPostponementInfoPRIVersion                  string           `plist:"kCTPostponementInfoPRIVersion,omitempty" json:"ct_postponement_info_pri_version,omitempty"`
	CTPostponementInfoPRLName                     int              `plist:"kCTPostponementInfoPRLName,omitempty" json:"ct_postponement_info_prl_name,omitempty"`
	CTPostponementInfoServiceProvisioningState    bool             `plist:"kCTPostponementInfoServiceProvisioningState,omitempty" json:"ct_postponement_info_service_provisioning_state,omitempty"`
	CTPostponementStatus                          string           `plist:"kCTPostponementStatus,omitempty" json:"ct_postponement_status,omitempty"`
}

func (dv DeviceValues) String() string {
	return fmt.Sprintf(
		"Device Name:         %s\n"+
			"Device Color:        %s\n"+
			"Device Class:        %s\n"+
			"Product Name:        %s\n"+
			"Product Type:        %s\n"+
			"HardwareModel:       %s\n"+
			"BoardId:             %d\n"+
			"BuildVersion:        %s\n"+
			"Product Version:     %s\n"+
			"ChipID:              %#x (%s)\n"+
			"HardwarePlatform:    %s\n"+
			"ProductionSOC:       %t\n"+
			"HasSiDP:             %t\n"+
			"TelephonyCapability: %t\n"+
			"WiFiAddress:         %s\n"+
			"EthernetAddress:     %s\n"+
			"BluetoothAddress:    %s\n"+
			"FirmwareVersion:     %s\n"+
			"UniqueChipID:        %#x\n"+
			"DieID:               %#x\n"+
			"PartitionType:       %s\n"+
			"UniqueDeviceID:      %s\n"+
			"SerialNumber:        %s\n"+
			"TimeZone:            %s\n"+
			"ReleaseType:         %s\n"+
			"HostAttached:        %t\n"+
			"TrustedHostAttached: %t\n"+
			"ActivationState:     %s\n\n",
		dv.DeviceName,
		dv.DeviceColor,
		dv.DeviceClass,
		dv.ProductName,
		dv.ProductType,
		dv.HardwareModel,
		dv.BoardId,
		dv.BuildVersion,
		dv.ProductVersion,
		dv.ChipID,
		dv.CPUArchitecture,
		dv.HardwarePlatform,
		dv.ProductionSOC,
		dv.HasSiDP,
		dv.TelephonyCapability,
		dv.WiFiAddress,
		dv.EthernetAddress,
		dv.BluetoothAddress,
		dv.FirmwareVersion,
		dv.UniqueChipID,
		dv.DieID,
		dv.PartitionType,
		dv.UniqueDeviceID,
		dv.SerialNumber,
		dv.TimeZone,
		dv.ReleaseType,
		dv.HostAttached,
		dv.TrustedHostAttached,
		dv.ActivationState,
	)
}

type getValueRequest struct {
	Label   string
	Request string
	Domain  string `plist:"Domain,omitempty"`
	Key     string `plist:"Key,omitempty"`
}

type getValueResponse struct {
	Request string
	Result  string
	Value   *DeviceValues
}

func (lc *Client) GetValues() (*DeviceValues, error) {
	req := &getValueRequest{
		Label:   usb.BundleID,
		Request: "GetValue",
		Domain:  "",
		Key:     "",
	}
	var resp getValueResponse
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}

	return resp.Value, nil
}

type queryTypeRequest struct {
	Request string `plist:"Request"`
}

type queryTypeResponse struct {
	Request string
	Result  string
	Type    string
}

func (lc *Client) QueryType() (string, error) {
	req := &queryTypeRequest{
		Request: "QueryType",
	}
	var resp queryTypeResponse
	if err := lc.Request(req, &resp); err != nil {
		return "", err
	}

	return resp.Type, nil
}

func (lc *Client) Close() error {
	return lc.Client.Close()
}
