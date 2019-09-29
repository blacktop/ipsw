// +build darwin,cgo

package xcode

import (
	"fmt"

	"github.com/jinzhu/gorm"
	// importing the sqlite dialects
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/pkg/errors"
)

// ReadDeviceTraitsDB parse the XCode device_traits.db
func ReadDeviceTraitsDB() ([]Device, error) {
	var allDevices []Device

	for _, osType := range []string{"iPhoneOS", "AppleTVOS", "WatchOS"} {
		dbFile := fmt.Sprintf("/Applications/Xcode.app/Contents/Developer/Platforms/%s.platform/usr/standalone/device_traits.db", osType)
		db, err := gorm.Open("sqlite3", dbFile)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to open database: %s", dbFile)
		}
		defer db.Close()

		var devices []Device
		db.Preload("DeviceTrait").Find(&devices)

		allDevices = append(allDevices, devices...)
	}

	return allDevices, nil
}
