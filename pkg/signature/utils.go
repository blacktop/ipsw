package signature

import (
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	semver "github.com/hashicorp/go-version"
)

func checkVersion(kv *kernelcache.Version, sigs Symbolicator) (bool, error) {
	darwin, err := semver.NewVersion(kv.Darwin)
	if err != nil {
		return false, fmt.Errorf("failed to convert kernel version into semver object: %v", err)
	}
	minVer, err := semver.NewVersion(sigs.Version.Min)
	if err != nil {
		log.Fatal("failed to convert signature min version into semver object")
	}
	maxVer, err := semver.NewVersion(sigs.Version.Max)
	if err != nil {
		log.Fatal("failed to convert signature max version into semver object")
	}
	if darwin.GreaterThanOrEqual(minVer) && darwin.LessThanOrEqual(maxVer) {
		return true, nil
	}
	return false, nil
}

func truncate(in string, length int) string {
	if len(in) > length {
		return in[:length] + "..."
	}
	return in
}
