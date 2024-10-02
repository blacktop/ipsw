package fw

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/types"
)

type hashType uint8

const (
	PAGE_SIZE_BITS = 12
	PAGE_SIZE      = 1 << PAGE_SIZE_BITS

	HASHTYPE_NOHASH           hashType = 0
	HASHTYPE_SHA1             hashType = 1
	HASHTYPE_SHA256           hashType = 2
	HASHTYPE_SHA256_TRUNCATED hashType = 3
	HASHTYPE_SHA384           hashType = 4
	HASHTYPE_SHA512           hashType = 5

	HASH_SIZE_SHA1             = 20
	HASH_SIZE_SHA256           = 32
	HASH_SIZE_SHA256_TRUNCATED = 20

	CDHASH_LEN    = 20 /* always - larger hashes are truncated */
	HASH_MAX_SIZE = 48 /* max size of the hash we'll support */
)

func (c hashType) String() string {
	switch c {
	case HASHTYPE_NOHASH:
		return "no-hash"
	case HASHTYPE_SHA1:
		return "sha1"
	case HASHTYPE_SHA256:
		return "sha256"
	case HASHTYPE_SHA256_TRUNCATED:
		return "sha256 (Truncated)"
	case HASHTYPE_SHA384:
		return "sha384"
	case HASHTYPE_SHA512:
		return "sha512"
	default:
		return fmt.Sprintf("hashType(%d)", c)
	}
}

type tcFlags uint8

const (
	CS_TRUST_CACHE_AMFID tcFlags = 1 // valid cdhash for amfid
	CS_TRUST_CACHE_ANE   tcFlags = 2 // ANE model hash
)

func (c tcFlags) String() string {
	var flags []string
	if c&CS_TRUST_CACHE_AMFID != 0 {
		flags = append(flags, "AMFID")
	}
	if c&CS_TRUST_CACHE_ANE != 0 {
		flags = append(flags, "ANE")
	}
	if len(flags) == 0 {
		return ""
	}
	return fmt.Sprintf(" flags=%s", strings.Join(flags, "|"))
}

type TrustCache struct {
	TCHeader
	Entries []any
}

type TCHeader struct {
	Version    uint32
	UUID       types.UUID
	NumEntries uint32
}

type CDHash [CDHASH_LEN]byte

func (c CDHash) String() string {
	return hex.EncodeToString(c[:])
}

type TrustCacheEntryV1 struct {
	CDHash   CDHash
	HashType hashType
	Flags    tcFlags
}

func (tc TrustCacheEntryV1) String() string {
	return fmt.Sprintf("%s %s%s", tc.CDHash, tc.HashType, tc.Flags)
}

/*
https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056

Constraint Categories (from TrustCache, new in version 2):

	Category 0:
	    No Constraints

	Category 1:
	    Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
	    Parent Constraint: is-init-proc

	Category 2:
	    Self Constraint: on-authorized-authapfs-volume || on-system-volume

	Category 3:
	    Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && (launch-type == 0 || launch-type == 1) && validation-category == 1

	Category 4:
	    Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && (launch-type == 0 || launch-type == 1) && validation-category == 1
	    Parent Constraint: (on-system-volume && signing-identifier == "com.apple.mbfloagent" && validation-category == 1) || is-init-proc

	Category 5:
	    Self Constraint: validation-category == 1
	    Parent Constraint: (on-system-volume && signing-identifier == "com.apple.mbfloagent" && validation-category == 1) || is-init-proc

	Category 6:
	    Self Constraint: (!in-tc-with-constraint-category || is-sip-protected || on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
	    Parent Constraint: (apple-internal && entitlements["com.apple.private.set-launch-type.internal"] == 1) || is-init-proc

	Category 7:
	    Self Constraint: validation-category == 1
*/
type TrustCacheEntryV2 struct {
	CDHash             CDHash
	HashType           hashType
	Flags              tcFlags
	ConstraintCategory uint8
	_                  uint8
}

func (tc TrustCacheEntryV2) String() string {
	var cat string
	if tc.ConstraintCategory != 0 {
		cat = fmt.Sprintf(" category=%d", tc.ConstraintCategory)
	}
	return fmt.Sprintf("%s %s%s%s", tc.CDHash, tc.HashType, cat, tc.Flags)
}

func (tc TrustCache) String() string {
	var out string
	out += fmt.Sprintf("UUID:       %s\n", tc.UUID)
	out += fmt.Sprintf("Version:    %d\n", tc.Version)
	out += fmt.Sprintf("NumEntries: %d\n", tc.NumEntries)
	for _, entry := range tc.Entries {
		out += fmt.Sprintf("    %s\n", entry)
	}
	return out
}

func ParseTrustCache(data []byte) (*TrustCache, error) {
	var tc TrustCache

	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.LittleEndian, &tc.TCHeader); err != nil {
		return nil, err
	}

	for i := 0; i < int(tc.NumEntries); i++ {
		switch tc.Version {
		case 1:
			var entry TrustCacheEntryV1
			if err := binary.Read(r, binary.LittleEndian, &entry); err != nil {
				return nil, err
			}
			tc.Entries = append(tc.Entries, entry)
		case 2:
			var entry TrustCacheEntryV2
			if err := binary.Read(r, binary.LittleEndian, &entry); err != nil {
				return nil, err
			}
			tc.Entries = append(tc.Entries, entry)
		default:
			return nil, fmt.Errorf("unsupported trust cache version: %d", tc.Version)
		}
	}

	return &tc, nil
}
