package utils

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/apex/log"
)

// NOTE: security cms -D -i <file>

func PrintCMSData(data []byte) {
	tmp, err := os.CreateTemp("", "cmsdata")
	if err != nil {
		log.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		log.Errorf("failed to write CMS data to temp file: %v", err)
	}
	tmp.Close()

	// openssl cms -inform DER -cmsout -print -in <file>
	cmd := exec.Command("openssl", "cms", "-inform", "DER", "-cmsout", "-print", "-in", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("%v: %s", err, out)
	}

	fmt.Println(string(out))
}

func PrintAsn1Data(data []byte) {
	tmp, err := os.CreateTemp("", "asn1data")
	if err != nil {
		log.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		log.Errorf("failed to write CMS data to temp file: %v", err)
	}
	tmp.Close()

	// openssl asn1parse -i -inform DER -in <file>
	cmd := exec.Command("openssl", "asn1parse", "-i", "-inform", "DER", "-in", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("%v: %s", err, out)
	}

	fmt.Println(string(out))
}
