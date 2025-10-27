package aea

import "errors"

var (
	// ErrFCSKeyURLNotFound indicates the IPSW metadata does not include a URL for fetching the FCS key.
	ErrFCSKeyURLNotFound = errors.New("aea: fcs-key-url key not found")
	// ErrFCSResponseMissing indicates the AEA metadata does not include the HPKE response payload.
	ErrFCSResponseMissing = errors.New("aea: com.apple.wkms.fcs-response missing")
	// ErrHPKEDecrypt indicates the HPKE unwrap operation failed.
	ErrHPKEDecrypt = errors.New("aea: hpke decrypt failed")
	// ErrBadSymmetricKey indicates the provided symmetric key (or PEM DB entry) is incorrect for the DMG.
	ErrBadSymmetricKey = errors.New("aea: invalid symmetric key")
)
