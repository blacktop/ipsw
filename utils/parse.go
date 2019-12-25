package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/blacktop/go-plist"
)

type buildManifest struct {
	BuildIdentities       interface{} `plist:"BuildIdentities,omitempty"`
	ManifestVersion       uint64      `plist:"ManifestVersion,omitempty"`
	ProductBuildVersion   string      `plist:"ProductBuildVersion,omitempty"`
	ProductVersion        string      `plist:"ProductVersion,omitempty"`
	SupportedProductTypes []string    `plist:"SupportedProductTypes,omitempty"`
}

func parseBuildManifest() {
	dat, err := ioutil.ReadFile("BuildManifest.plist")
	if err != nil {
		log.Fatal(err)
	}
	var data buildManifest
	decoder := plist.NewDecoder(bytes.NewReader(dat))
	err = decoder.Decode(&data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("===> PARSING BuildManifest.plist")
	// fmt.Println("BuildIdentities: ", data.BuildIdentities)
	// fmt.Println("ManifestVersion: ", data.ManifestVersion)
	fmt.Println("ProductVersion: ", data.ProductVersion)
	fmt.Println("ProductBuildVersion: ", data.ProductBuildVersion)
	fmt.Println("SupportedProductTypes: ")
	for _, prodType := range data.SupportedProductTypes {
		fmt.Println(" - ", prodType)
	}
}
