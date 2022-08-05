package types

import "fmt"

type ReadDevicesType struct {
	MessageType         string
	BundleID            string
	ProgName            string
	ClientVersionString string
	LibUSBMuxVersion    int
}

type DeviceProperties struct {
	DeviceID        int
	ConnectionType  string
	ConnectionSpeed int
	ProductID       int
	LocationID      int
	SerialNumber    string
	UDID            string
	USBSerialNumber string
}

type Device struct {
	MessageType string
	DeviceID    int
	Properties  DeviceProperties
}

func (d Device) String() string {
	return fmt.Sprintf(
		"DeviceID: %d\n"+
			"    ConnectionType:  %s\n"+
			"    ConnectionSpeed: %d\n"+
			"    ProductID:       %#x\n"+
			"    LocationID:      %d\n"+
			"    SerialNumber:    %s\n"+
			"    UDID:            %s\n"+
			"    USBSerialNumber: %s\n",
		d.DeviceID,
		d.Properties.ConnectionType,
		d.Properties.ConnectionSpeed,
		d.Properties.ProductID,
		d.Properties.LocationID,
		d.Properties.SerialNumber,
		d.Properties.UDID,
		d.Properties.USBSerialNumber,
	)
}
