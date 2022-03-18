//go:build darwin && cgo

package xcode

import (
	"fmt"
	"os"

	"github.com/jinzhu/gorm"
	// importing the sqlite dialects
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/pkg/errors"
)

func uniqueDevices(d []Device) []Device {
	unique := make(map[string]bool, len(d))
	bs := make([]Device, len(unique))
	for _, elem := range d {
		if len(elem.ProductType) != 0 && len(elem.Target) != 0 {
			if !unique[elem.ProductType+"_"+elem.Target] {
				bs = append(bs, elem)
				unique[elem.ProductType+"_"+elem.Target] = true
			}
		}
	}

	return bs
}

// ReadDeviceTraitsDB parse the XCode device_traits.db
func ReadDeviceTraitsDB() ([]Device, error) {
	var allDevices []Device

	for _, osType := range []string{"iPhoneOS", "AppleTVOS", "WatchOS"} {
		for _, releaseType := range []string{"", "-beta"} {
			dbFile := fmt.Sprintf("/Applications/Xcode%s.app/Contents/Developer/Platforms/%s.platform/usr/standalone/device_traits.db", releaseType, osType)
			if _, err := os.Stat(dbFile); err == nil {
				db, err := gorm.Open("sqlite3", dbFile)
				if err != nil {
					return nil, errors.Wrapf(err, "unable to open database: %s", dbFile)
				}
				defer db.Close()

				var devices []Device
				db.Preload("DeviceTrait").Find(&devices)

				allDevices = append(allDevices, devices...)
			}
		}
	}

	return uniqueDevices(allDevices), nil
}
