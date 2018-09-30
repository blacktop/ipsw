package api

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const ipswMeURL = "https://api.ipsw.me/v4/"

// Device struct
type Device struct {
	Name        string `json:"name,omitempty"`
	Identifier  string `json:"identifier,omitempty"`
	BoardConfig string `json:"boardconfig,omitempty"`
	Platform    string `json:"platform,omitempty"`
	CpID        int    `json:"cpid,omitempty"`
	BdID        int    `json:"bdid,omitempty"`
	Firmwares   []IPSW `json:"firmwares,omitempty"`
}

// IPSW struct
type IPSW struct {
	Identifier  string    `json:"identifier,omitempty"`
	Version     string    `json:"version,omitempty"`
	BuildID     string    `json:"buildid,omitempty"`
	SHA1        string    `json:"sha1sum,omitempty"`
	MD5         string    `json:"md5sum,omitempty"`
	Filesize    int       `json:"filesize,omitempty"`
	URL         string    `json:"url,omitempty"`
	ReleaseDate time.Time `json:"releasedate,omitempty"`
	UploadDate  time.Time `json:"uploaddate,omitempty"`
	Signed      bool      `json:"signed,omitempty"`
}

// GetAllDevices returns a list of all devices
func GetAllDevices() []Device {

	res, err := http.Get(ipswMeURL + "devices")
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	res.Body.Close()

	devices := []Device{}
	err = json.Unmarshal(body, &devices)
	if err != nil {
		log.Fatal(err)
	}

	return devices
}

// GetDevice returns a device from it's identifier
func GetDevice(identifier string) Device {

	res, err := http.Get(ipswMeURL + "device" + "/" + identifier)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	res.Body.Close()

	d := Device{}
	err = json.Unmarshal(body, &d)
	if err != nil {
		log.Fatal(err)
	}

	return d
}

// GetAllIPSW finds all IPSW files for a given iOS version
func GetAllIPSW(version string) []IPSW {
	res, err := http.Get(ipswMeURL + "ipsw/" + version)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	res.Body.Close()

	ipsws := []IPSW{}
	err = json.Unmarshal(body, &ipsws)
	if err != nil {
		log.Fatal(err)
	}

	return ipsws
}

// GetIPSW will get an IPSW when supplied an identifier and build ID
func GetIPSW(identifier, buildID string) IPSW {
	res, err := http.Get(ipswMeURL + "ipsw/" + identifier + "/" + buildID)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	i := IPSW{}
	err = json.Unmarshal(body, &i)
	if err != nil {
		log.Fatal(err)
	}

	return i
}

// https://api.ipsw.me/v4/releases
// func GetReleases() []Release {}
