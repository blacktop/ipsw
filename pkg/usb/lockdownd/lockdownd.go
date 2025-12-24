package lockdownd

import (
	"fmt"

	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/pkg/usb"
)

const lockdownPort = 62078

var colorFaint = colors.FaintHiBlue().SprintFunc()
var colorBold = colors.Bold().SprintFunc()

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
	cli, err := usb.NewClient(udid, lockdownPort)
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
			return nil, fmt.Errorf("failed to enable SSL for lockdown service: %v", err)
		}
	}

	return &Client{cli}, nil
}

func NewClientForService(serviceName, udid string, withEscrowBag bool) (*usb.Client, error) {
	lc, err := NewClient(udid)
	if err != nil {
		return nil, fmt.Errorf("failed to create lockdownd client for service %s: %v", serviceName, err)
	}
	defer lc.Close()

	svc, err := lc.StartService(serviceName, withEscrowBag)
	if err != nil {
		return nil, fmt.Errorf("failed to start service %s: %v", serviceName, err)
	}

	cli, err := usb.NewClient(udid, svc.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to create usbmux client for service %s on port %d: %v", serviceName, svc.Port, err)
	}

	if svc.EnableServiceSSL {
		if err := cli.EnableSSL(); err != nil {
			return nil, fmt.Errorf("failed to enable SSL for lockdown service %s: %v", serviceName, err)
		}
	}

	return cli, nil
}

type startServiceRequest struct {
	Label     string
	Request   string `plist:"Request"`
	Service   string
	EscrowBag []byte `plist:"EscrowBag,omitempty"`
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
	ActivationState                 string `plist:"ActivationState,omitempty" json:"activation_state,omitempty"`
	ActivationStateAcknowledged     bool   `plist:"ActivationStateAcknowledged,omitempty" json:"activation_state_acknowledged,omitempty"`
	BasebandActivationTicketVersion string `plist:"BasebandActivationTicketVersion,omitempty" json:"baseband_activation_ticket_version,omitempty"`
	BasebandCertID                  int    `plist:"BasebandCertId,omitempty" json:"baseband_cert_id,omitempty"`
	BasebandChipID                  int    `plist:"BasebandChipID,omitempty" json:"baseband_chip_id,omitempty"`
	BasebandKeyHashInformation      struct {
		AKeyStatus int    `plist:"AKeyStatus,omitempty" json:"a_key_status,omitempty"`
		SKeyHash   []byte `plist:"SKeyHash,omitempty" json:"s_key_hash,omitempty"`
		SKeyStatus int    `plist:"SKeyStatus,omitempty" json:"s_key_status,omitempty"`
	} `plist:"BasebandKeyHashInformation,omitempty" json:"baseband_key_hash_information"`
	BasebandMasterKeyHash                         string           `plist:"BasebandMasterKeyHash,omitempty" json:"baseband_master_key_hash,omitempty"`
	BasebandRegionSKU                             []byte           `plist:"BasebandRegionSKU,omitempty" json:"baseband_region_sku,omitempty"`
	BasebandSerialNumber                          []byte           `plist:"BasebandSerialNumber,omitempty" json:"baseband_serial_number,omitempty"`
	BasebandStatus                                string           `plist:"BasebandStatus,omitempty" json:"baseband_status,omitempty"`
	BasebandVersion                               string           `plist:"BasebandVersion,omitempty" json:"baseband_version,omitempty"`
	BluetoothAddress                              string           `plist:"BluetoothAddress,omitempty" json:"bluetooth_address,omitempty"`
	BoardID                                       int              `plist:"BoardId,omitempty" json:"board_id,omitempty"`
	BootSessionID                                 string           `plist:"BootSessionID,omitempty" json:"boot_session_id,omitempty"`
	BootstrapVersion                              string           `plist:"BootstrapVersion,omitempty" json:"bootstrap_version,omitempty"`
	BrickState                                    bool             `plist:"BrickState,omitempty" json:"brick_state"`
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
	HasSiDP                                       bool             `plist:"HasSiDP,omitempty" json:"has_si_dp"`
	HostAttached                                  bool             `plist:"HostAttached,omitempty" json:"host_attached"`
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
	PasswordProtected                             bool             `plist:"PasswordProtected,omitempty" json:"password_protected"`
	PhoneNumber                                   string           `plist:"PhoneNumber,omitempty" json:"phone_number,omitempty"`
	PkHash                                        []byte           `plist:"PkHash,omitempty" json:"pk_hash,omitempty"`
	ProductName                                   string           `plist:"ProductName,omitempty" json:"product_name,omitempty"`
	ProductType                                   string           `plist:"ProductType,omitempty" json:"product_type,omitempty"`
	ProductVersion                                string           `plist:"ProductVersion,omitempty" json:"product_version,omitempty"`
	ProductionSOC                                 bool             `plist:"ProductionSOC,omitempty" json:"production_soc"`
	ProtocolVersion                               string           `plist:"ProtocolVersion,omitempty" json:"protocol_version,omitempty"`
	ProximitySensorCalibration                    []byte           `plist:"ProximitySensorCalibration,omitempty" json:"proximity_sensor_calibration,omitempty"`
	RegionInfo                                    string           `plist:"RegionInfo,omitempty" json:"region_info,omitempty"`
	ReleaseType                                   string           `plist:"ReleaseType,omitempty" json:"release_type,omitempty"`
	SIM1IsBootstrap                               bool             `plist:"SIM1IsBootstrap,omitempty" json:"sim1_is_bootstrap"`
	SIM1IsEmbedded                                bool             `plist:"SIM1IsEmbedded,omitempty" json:"sim_1_is_embedded"`
	SIMGID1                                       []byte           `plist:"SIMGID1,omitempty" json:"simgid_1,omitempty"`
	SIMGID2                                       []byte           `plist:"SIMGID2,omitempty" json:"simgid_2,omitempty"`
	SIMStatus                                     any              `plist:"SIMStatus,omitempty" json:"sim_status,omitempty"`
	SIMTrayStatus                                 any              `plist:"SIMTrayStatus,omitempty" json:"sim_tray_status,omitempty"`
	SerialNumber                                  string           `plist:"SerialNumber,omitempty" json:"serial_number,omitempty"`
	SoftwareBehavior                              []byte           `plist:"SoftwareBehavior,omitempty" json:"software_behavior,omitempty"`
	SoftwareBundleVersion                         string           `plist:"SoftwareBundleVersion,omitempty" json:"software_bundle_version,omitempty"`
	SupportedDeviceFamilies                       []int            `plist:"SupportedDeviceFamilies,omitempty" json:"supported_device_families,omitempty"`
	TelephonyCapability                           bool             `plist:"TelephonyCapability,omitempty" json:"telephony_capability"`
	TimeIntervalSince1970                         float64          `plist:"TimeIntervalSince1970,omitempty" json:"time_interval_since_1970,omitempty"`
	TimeZone                                      string           `plist:"TimeZone,omitempty" json:"time_zone,omitempty"`
	TimeZoneOffsetFromUTC                         float64          `plist:"TimeZoneOffsetFromUTC,omitempty" json:"time_zone_offset_from_utc,omitempty"`
	TrustedHostAttached                           bool             `plist:"TrustedHostAttached,omitempty" json:"trusted_host_attached"`
	UniqueChipID                                  int64            `plist:"UniqueChipID,omitempty" json:"unique_chip_id,omitempty"`
	UniqueDeviceID                                string           `plist:"UniqueDeviceID,omitempty" json:"unique_device_id,omitempty"`
	UntrustedHostBUID                             string           `plist:"UntrustedHostBUID,omitempty" json:"untrusted_host_buid,omitempty"`
	UseRaptorCerts                                bool             `plist:"UseRaptorCerts,omitempty" json:"use_raptor_certs"`
	Uses24HourClock                               bool             `plist:"Uses24HourClock,omitempty" json:"uses_24_hour_clock"`
	WiFiAddress                                   string           `plist:"WiFiAddress,omitempty" json:"wi_fi_address,omitempty"`
	WirelessBoardSerialNumber                     string           `plist:"WirelessBoardSerialNumber,omitempty" json:"wireless_board_serial_number,omitempty"`
	CTPostponementInfoPRIVersion                  string           `plist:"kCTPostponementInfoPRIVersion,omitempty" json:"ct_postponement_info_pri_version,omitempty"`
	CTPostponementInfoPRLName                     int              `plist:"kCTPostponementInfoPRLName,omitempty" json:"ct_postponement_info_prl_name,omitempty"`
	CTPostponementInfoServiceProvisioningState    bool             `plist:"kCTPostponementInfoServiceProvisioningState,omitempty" json:"ct_postponement_info_service_provisioning_state"`
	CTPostponementStatus                          string           `plist:"kCTPostponementStatus,omitempty" json:"ct_postponement_status,omitempty"`
	Image4Supported                               bool             `plist:"Image4Supported,omitempty" json:"img4_supported"`
	ApNonce                                       []byte           `plist:"ApNonce,omitempty" json:"ap_nonce,omitempty"`
	SEPNonce                                      []byte           `plist:"SEPNonce,omitempty" json:"sep_nonce,omitempty"`
	FirmwarePreflightInfo                         map[string]any   `plist:"FirmwarePreflightInfo,omitempty" json:"preflight_info,omitempty"`
}

func (dv DeviceValues) String() string {
	releaseType := dv.ReleaseType
	if releaseType == "" {
		releaseType = "Release"
	}
	return fmt.Sprintf(
		colorFaint("Device Name:         ")+colorBold("%s\n")+
			colorFaint("Device Color:        ")+colorBold("%s\n")+
			colorFaint("Device Class:        ")+colorBold("%s\n")+
			colorFaint("Product Name:        ")+colorBold("%s\n")+
			colorFaint("Product Type:        ")+colorBold("%s\n")+
			colorFaint("HardwareModel:       ")+colorBold("%s\n")+
			colorFaint("BoardId:             ")+colorBold("%d\n")+
			colorFaint("BuildVersion:        ")+colorBold("%s\n")+
			colorFaint("Product Version:     ")+colorBold("%s\n")+
			colorFaint("ChipID:              ")+colorBold("%#x (%s)\n")+
			colorFaint("HardwarePlatform:    ")+colorBold("%s\n")+
			colorFaint("ProductionSOC:       ")+colorBold("%t\n")+
			colorFaint("HasSiDP:             ")+colorBold("%t\n")+
			colorFaint("TelephonyCapability: ")+colorBold("%t\n")+
			colorFaint("WiFiAddress:         ")+colorBold("%s\n")+
			colorFaint("EthernetAddress:     ")+colorBold("%s\n")+
			colorFaint("BluetoothAddress:    ")+colorBold("%s\n")+
			colorFaint("FirmwareVersion:     ")+colorBold("%s\n")+
			colorFaint("UniqueChipID:        ")+colorBold("%#x\n")+
			colorFaint("DieID:               ")+colorBold("%#x\n")+
			colorFaint("PartitionType:       ")+colorBold("%s\n")+
			colorFaint("UniqueDeviceID:      ")+colorBold("%s\n")+
			colorFaint("SerialNumber:        ")+colorBold("%s\n")+
			colorFaint("TimeZone:            ")+colorBold("%s\n")+
			colorFaint("ReleaseType:         ")+colorBold("%s\n")+
			colorFaint("HostAttached:        ")+colorBold("%t\n")+
			colorFaint("TrustedHostAttached: ")+colorBold("%t\n")+
			colorFaint("ActivationState:     ")+colorBold("%s\n\n"),
		dv.DeviceName,
		dv.DeviceColor,
		dv.DeviceClass,
		dv.ProductName,
		dv.ProductType,
		dv.HardwareModel,
		dv.BoardID,
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
		releaseType,
		dv.HostAttached,
		dv.TrustedHostAttached,
		dv.ActivationState,
	)
}

type setValueRequest struct {
	Request string
	Label   string
	Domain  string `plist:"Domain,omitempty"`
	Key     string `plist:"Key,omitempty"`
	Value   any    `plist:"Value,omitempty"`
}

type getValueRequest struct {
	Request string
	Label   string
	Domain  string `plist:"Domain,omitempty"`
	Key     string `plist:"Key,omitempty"`
}

type getValuesResponse struct {
	Domain  string `plist:"Domain,omitempty"`
	Error   string `plist:"Error,omitempty"`
	Key     string `plist:"Key,omitempty"`
	Request string `plist:"Request,omitempty"`
	Result  string `plist:"Result,omitempty"`
	Value   *DeviceValues
}

type getValueResponse struct {
	Domain  string `plist:"Domain,omitempty"`
	Error   string `plist:"Error,omitempty"`
	Key     string `plist:"Key,omitempty"`
	Request string `plist:"Request,omitempty"`
	Value   any    `plist:"Value,omitempty"`
}

type getBoolResponse struct {
	Domain  string `plist:"Domain,omitempty"`
	Error   string `plist:"Error,omitempty"`
	Key     string `plist:"Key,omitempty"`
	Request string `plist:"Request,omitempty"`
	Value   bool   `plist:"Value,omitempty"`
}

type wifiConnections struct {
	BonjourFullServiceName string `plist:"BonjourFullServiceName,omitempty"`
	EnableWifiConnections  bool   `plist:"EnableWifiConnections,omitempty"`
	EnableWifiDebugging    bool   `plist:"EnableWifiDebugging,omitempty"`
	EnableWifiPairing      bool   `plist:"EnableWifiPairing,omitempty"`
	SupportsWifi           bool   `plist:"SupportsWifi,omitempty"`
	SupportsWifiSyncing    bool   `plist:"SupportsWifiSyncing,omitempty"`
}

func (w wifiConnections) String() string {
	return fmt.Sprintf(
		colorFaint("BonjourFullServiceName: ")+colorBold("%s\n")+
			colorFaint("EnableWifiConnections:  ")+colorBold("%t\n")+
			colorFaint("EnableWifiDebugging:    ")+colorBold("%t\n")+
			colorFaint("EnableWifiPairing:      ")+colorBold("%t\n")+
			colorFaint("SupportsWifi:           ")+colorBold("%t\n")+
			colorFaint("SupportsWifiSyncing:    ")+colorBold("%t\n"),
		w.BonjourFullServiceName,
		w.EnableWifiConnections,
		w.EnableWifiDebugging,
		w.EnableWifiPairing,
		w.SupportsWifi,
		w.SupportsWifiSyncing,
	)
}

type getWifiConnectionsResponse struct {
	Request string
	Value   wifiConnections
}

func (lc *Client) getValues(domain, key string) (any, error) {
	req := &getValueRequest{
		Request: "GetValue",
		Label:   usb.BundleID,
		Domain:  domain,
		Key:     key,
	}
	var resp any
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (lc *Client) setValues(domain, key string, value any) (any, error) {
	req := &setValueRequest{
		Request: "SetValue",
		Label:   usb.BundleID,
		Domain:  domain,
		Key:     key,
		Value:   value,
	}
	var resp any
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (lc *Client) removeValues(domain, key string) (any, error) {
	req := &getValueRequest{
		Request: "RemoveValue",
		Label:   usb.BundleID,
		Domain:  domain,
		Key:     key,
	}
	var resp any
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (lc *Client) GetValues() (*DeviceValues, error) {
	req := &getValueRequest{
		Request: "GetValue",
		Label:   usb.BundleID,
		Domain:  "",
		Key:     "",
	}
	var resp getValuesResponse
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("failed to get value: %s", resp.Error)
	}
	if v, e := lc.GetValue("", "Image4Supported"); e == nil {
		resp.Value.Image4Supported = v.(bool)
	}
	if v, e := lc.GetValue("", "ApNonce"); e == nil {
		resp.Value.ApNonce = v.([]byte)
	}
	if v, e := lc.GetValue("", "SEPNonce"); e == nil {
		resp.Value.SEPNonce = v.([]byte)
	}
	if v, e := lc.GetValue("", "FirmwarePreflightInfo"); e == nil {
		resp.Value.FirmwarePreflightInfo = v.(map[string]any)
	}
	return resp.Value, nil
}

func (lc *Client) GetValue(domain, key string) (any, error) {
	req := &getValueRequest{
		Request: "GetValue",
		Label:   usb.BundleID,
		Domain:  domain,
		Key:     key,
	}
	var resp getValueResponse
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("failed to get value: %s", resp.Error)
	}
	return resp.Value, nil
}

func (lc *Client) DeveloperModeEnabled() (bool, error) {
	req := &getValueRequest{
		Request: "GetValue",
		Label:   usb.BundleID,
		Domain:  "com.apple.security.mac.amfi",
		Key:     "DeveloperModeStatus",
	}
	var resp getBoolResponse
	if err := lc.Request(req, &resp); err != nil {
		return false, err
	}
	if resp.Error == "MissingValue" { // this is a device without developer mode support
		return true, nil
	}
	return resp.Value, nil
}

func (lc *Client) WifiConnections() (*wifiConnections, error) {
	req := &getValueRequest{
		Request: "GetValue",
		Label:   usb.BundleID,
		Domain:  "com.apple.mobile.wireless_lockdown",
		Key:     "",
	}
	var resp getWifiConnectionsResponse
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Value, nil
}

func (lc *Client) SetWifiConnections(on bool) error {
	req := &setValueRequest{
		Request: "SetValue",
		Label:   usb.BundleID,
		Domain:  "com.apple.mobile.wireless_lockdown",
		Key:     "EnableWifiPairing",
		Value:   on,
	}
	var resp any
	if err := lc.Request(req, &resp); err != nil {
		return err
	}
	req = &setValueRequest{
		Request: "SetValue",
		Label:   usb.BundleID,
		Domain:  "com.apple.mobile.wireless_lockdown",
		Key:     "EnableWifiConnections",
		Value:   on,
	}
	if err := lc.Request(req, &resp); err != nil {
		return err
	}
	return nil
}

type queryTypeRequest struct {
	Label   string
	Request string `plist:"Request"`
}

type queryTypeResponse struct {
	Request string
	Result  string
	Type    string
	Error   string `plist:"Error,omitempty"`
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

func (lc *Client) EnterRecovery() (string, error) {
	req := &queryTypeRequest{
		Request: "EnterRecovery",
		Label:   usb.BundleID,
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
