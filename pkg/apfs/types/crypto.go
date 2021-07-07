package types

import "github.com/blacktop/go-macho/types"

/** Encryption Types **/
type cp_key_class_t uint32
type cp_key_os_version_t uint32
type cp_key_revision_t uint16
type crypto_flags_t uint32

type j_crypto_key_t struct {
	Hdr JKeyT
} // __attribute__((packed))

type wrapped_crypto_state_t struct {
	MajorVersion    uint16
	MinorVersion    uint16
	Cpflags         crypto_flags_t
	PersistentClass cp_key_class_t
	KeyOsVersion    cp_key_os_version_t
	KeyRevision     cp_key_revision_t
	KeyLen          uint16
	PersistentKey   [0]byte
} // __attribute__((aligned(2), packed))

const CP_MAX_WRAPPEDKEYSIZE = 128

type j_crypto_val_t struct {
	Refcnt uint32
	State  wrapped_crypto_state_t
} // __attribute__((aligned(4), packed))

type wrapped_meta_crypto_state_t struct {
	MajorVersion    uint16
	MinorVersion    uint16
	Cpflags         crypto_flags_t
	PersistentClass cp_key_class_t
	KeyOsVersion    cp_key_os_version_t
	KeyRevision     cp_key_revision_t
	_               uint16
} // __attribute__((aligned(2), packed))

const (
	/** Protection Classes **/
	PROTECTION_CLASS_DIR_NONE = 0
	PROTECTION_CLASS_A        = 1
	PROTECTION_CLASS_B        = 2
	PROTECTION_CLASS_C        = 3
	PROTECTION_CLASS_D        = 4
	PROTECTION_CLASS_F        = 6
	PROTECTION_CLASS_M        = 14

	CP_EFFECTIVE_CLASSMASK = 0x0000001f

	/** Encryption Identifiers **/
	CRYPTO_SW_ID      = 4
	CRYPTO_RESERVED_5 = 5

	APFS_UNASSIGNED_CRYPTO_ID = 0xFFFFFFFFFFFFFFFF // ~0ULL
)

type keybag_entry_t struct {
	UUID    types.UUID
	Tag     uint16
	Keylen  uint16
	Padding [4]byte
	Keydata []byte
}

const (
	APFS_VOL_KEYBAG_ENTRY_MAX_SIZE     = 512
	APFS_FV_PERSONAL_RECOVERY_KEY_UUID = "EBC6C064-0000-11AA-AA11-00306543ECAC"
)

type kb_locker_t struct {
	Version uint16
	Nkeys   uint16
	Nbytes  uint32
	Padding [8]byte
	Entries []keybag_entry_t
}

const APFS_KEYBAG_VERSION = 2

type media_keybag_t struct {
	Obj    ObjPhysT
	Locker kb_locker_t
}

const (
	/** Keybag Tags **/
	KB_TAG_UNKNOWN    = 0
	KB_TAG_RESERVED_1 = 1

	KB_TAG_VOLUME_KEY             = 2
	KB_TAG_VOLUME_UNLOCK_RECORDS  = 3
	KB_TAG_VOLUME_PASSPHRASE_HINT = 4

	KB_TAG_WRAPPING_M_KEY = 5
	KB_TAG_VOLUME_M_KEY   = 6

	KB_TAG_RESERVED_F8 = 0xf8
)
