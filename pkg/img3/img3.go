package img3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/ipsw/pkg/lzfse"
)

const Magic = "Img3"

// Img3 object
type Img3 struct {
	Header
	Tags []Tag // continues until end of file
}

// Header img3 header object
type Header struct {
	Magic        [4]byte // ASCII_LE("Img3")
	FullSize     uint32  // full size of fw image
	SizeNoPack   uint32  // size of fw image without header
	SigCheckArea uint32  // although that is just my name for it, this is the
	// size of the start of the data section (the code) up to
	// the start of the RSA signature (SHSH section)
	Ident [4]byte // identifier of image, used when bootrom is parsing images
	// list to find LLB (illb), LLB parsing it to find iBoot (ibot),
	// etc.
}

// Tag img3 tag object
type Tag struct {
	TagHeader
	Data []byte // [dataLength]
	Pad  []byte // Typically padded to 4 byte multiple [totalLength - dataLength - 12]
}

// TagHeader img3 tag header object
type TagHeader struct {
	Magic       [4]byte // see below
	TotalLength uint32  // length of tag including "magic" and these two length values
	DataLength  uint32  // length of tag data
}

// KBAG structures for different AES key sizes
// Note: The IMG3 tag header (magic, fullSize, tagDataSize) is handled by the Tag structure
// KBAG data starts directly with cryptState and aesType
type KBagHeader struct {
	CryptState uint32 // 1 if encrypted with GID Key, 2 if encrypted with Development GID Key
	AESType    uint32 // 0x80 = aes128, 0xc0 = aes192, 0x100 = aes256
}

type KBAG128 struct {
	KBagHeader
	EncIV  [16]byte // IV for the firmware file, encrypted with the GID Key
	EncKey [16]byte // Key for the firmware file, encrypted with the GID Key
}

type KBAG192 struct {
	KBagHeader
	EncIV  [16]byte // IV for the firmware file, encrypted with the GID Key
	EncKey [24]byte // Key for the firmware file, encrypted with the GID Key
}

type KBAG256 struct {
	KBagHeader
	EncIV  [16]byte // IV for the firmware file, encrypted with the GID Key
	EncKey [32]byte // Key for the firmware file, encrypted with the GID Key
}

// KBagData represents the decrypted KBAG data
type KBagData struct {
	CryptState uint32
	AESType    uint32
	IV         []byte
	Key        []byte
}

/*
VERS: iBoot version of the image
SEPO: Security Epoch
SDOM: Security Domain
PROD: Production Mode
CHIP: Chip to be used with. example: 0x8900 for S5L8900.
BORD: Board to be used with
KBAG: Contains the IV and key required to decrypt; encrypted with the GID Key
SHSH: RSA encrypted SHA1 hash of the file
CERT: Certificate
ECID: Exclusive Chip ID unique to every device
TYPE: Type of image, should contain the same string as the header's ident
DATA: Real content of the file
NONC: Nonce used when file was signed.
CEPO: Chip epoch
OVRD:
RAND:
SALT:
*/

// ParseImg3 parses an IMG3 file from a byte slice
func ParseImg3(data []byte) (*Img3, error) {
	var i Img3

	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.LittleEndian, &i.Header); err != nil {
		return nil, fmt.Errorf("failed to read IMG3 header: %v", err)
	}

	// Verify magic
	if string(reverseBytes(i.Magic[:])) != Magic {
		return nil, fmt.Errorf("invalid IMG3 magic: %s", string(reverseBytes(i.Magic[:])))
	}

	for {
		var tag Tag

		err := binary.Read(r, binary.LittleEndian, &tag.TagHeader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read IMG3 tag header: %v", err)
		}

		tag.Data = make([]byte, tag.DataLength)
		tag.Pad = make([]byte, tag.TotalLength-tag.DataLength-12)

		if err := binary.Read(r, binary.LittleEndian, &tag.Data); err != nil {
			return nil, fmt.Errorf("failed to read IMG3 tag data: %v", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &tag.Pad); err != nil {
			return nil, fmt.Errorf("failed to read IMG3 tag pad: %v", err)
		}

		i.Tags = append(i.Tags, tag)
	}

	return &i, nil
}

// GetDataTag returns the DATA tag from the IMG3 file
func (i *Img3) GetDataTag() ([]byte, error) {
	for _, tag := range i.Tags {
		if string(reverseBytes(tag.Magic[:])) == "DATA" {
			return tag.Data, nil
		}
	}
	return nil, fmt.Errorf("no DATA tag found in IMG3")
}

// GetKBagTag returns the KBAG tag from the IMG3 file
func (i *Img3) GetKBagTag() ([]byte, error) {
	for _, tag := range i.Tags {
		if string(reverseBytes(tag.Magic[:])) == "KBAG" {
			return tag.Data, nil
		}
	}
	return nil, fmt.Errorf("no KBAG tag found in IMG3")
}

// GetAllKBagTags returns all KBAG tags from the IMG3 file
func (i *Img3) GetAllKBagTags() ([][]byte, error) {
	var kbags [][]byte
	for _, tag := range i.Tags {
		if string(reverseBytes(tag.Magic[:])) == "KBAG" {
			kbags = append(kbags, tag.Data)
		}
	}
	if len(kbags) == 0 {
		return nil, fmt.Errorf("no KBAG tags found in IMG3")
	}
	return kbags, nil
}

// ParseKBag parses a KBAG tag and returns the encrypted IV and key
func ParseKBag(data []byte) (*KBagData, error) {
	if len(data) < 40 { // 4 + 4 + 16 + 16 = minimum for AES128
		return nil, fmt.Errorf("KBAG data too short: got %d bytes, need at least 40", len(data))
	}

	var header KBagHeader
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read KBAG header: %v", err)
	}

	kbag := &KBagData{
		CryptState: header.CryptState,
		AESType:    header.AESType,
	}

	switch header.AESType {
	case 0x80: // AES128
		kbag.IV = make([]byte, 16)
		kbag.Key = make([]byte, 16)
		if _, err := r.Read(kbag.IV); err != nil {
			return nil, fmt.Errorf("failed to read AES128 IV: %v", err)
		}
		if _, err := r.Read(kbag.Key); err != nil {
			return nil, fmt.Errorf("failed to read AES128 key: %v", err)
		}
	case 0xc0: // AES192
		kbag.IV = make([]byte, 16)
		kbag.Key = make([]byte, 24)
		if _, err := r.Read(kbag.IV); err != nil {
			return nil, fmt.Errorf("failed to read AES192 IV: %v", err)
		}
		if _, err := r.Read(kbag.Key); err != nil {
			return nil, fmt.Errorf("failed to read AES192 key: %v", err)
		}
	case 0x100: // AES256
		kbag.IV = make([]byte, 16)
		kbag.Key = make([]byte, 32)
		if _, err := r.Read(kbag.IV); err != nil {
			return nil, fmt.Errorf("failed to read AES256 IV: %v", err)
		}
		if _, err := r.Read(kbag.Key); err != nil {
			return nil, fmt.Errorf("failed to read AES256 key: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported AES type: 0x%x", header.AESType)
	}

	return kbag, nil
}

// DecryptKBag decrypts the KBAG using the provided GID key
// The gidKey should be the device's GID key (usually obtained through exploits)
func DecryptKBag(kbag *KBagData, gidKey []byte) error {
	if len(gidKey) != 16 {
		return fmt.Errorf("GID key must be 16 bytes")
	}

	// Create AES cipher with GID key
	block, err := aes.NewCipher(gidKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Decrypt IV (always 16 bytes, no padding needed)
	if len(kbag.IV) != 16 {
		return fmt.Errorf("IV must be 16 bytes")
	}

	// Decrypt IV in-place
	block.Decrypt(kbag.IV, kbag.IV)

	// Decrypt Key
	if len(kbag.Key)%aes.BlockSize != 0 {
		return fmt.Errorf("key length must be a multiple of AES block size")
	}

	// Decrypt key in 16-byte blocks
	for i := 0; i < len(kbag.Key); i += aes.BlockSize {
		block.Decrypt(kbag.Key[i:i+aes.BlockSize], kbag.Key[i:i+aes.BlockSize])
	}

	return nil
}

// DecryptData decrypts IMG3 data using the provided IV and key
func DecryptData(data, iv, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("IMG3 data too short")
	}

	// CBC mode always works in whole blocks
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("IMG3 data is not a multiple of the block size")
	}

	// Create a copy of the data to decrypt
	decrypted := make([]byte, len(data))
	copy(decrypted, data)

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, decrypted)

	// Try to remove PKCS#7 padding, but continue without it if it fails
	if paddingRemoved, err := removePKCS7Padding(decrypted); err == nil {
		decrypted = paddingRemoved
	}

	// Check if data is LZFSE compressed
	if len(decrypted) >= 4 && bytes.Contains(decrypted[:4], []byte("bvx2")) {
		decompressed, err := lzfse.NewDecoder(decrypted).DecodeBuffer()
		if err != nil {
			return nil, fmt.Errorf("failed to LZFSE decompress: %v", err)
		}
		return decompressed, nil
	}

	return decrypted, nil
}

// removePKCS7Padding removes PKCS#7 padding from the decrypted data
func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	// The last byte tells us how many padding bytes there are
	paddingLength := int(data[len(data)-1])

	// Validate padding length
	if paddingLength == 0 || paddingLength > aes.BlockSize || paddingLength > len(data) {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLength)
	}

	// Check if all padding bytes are correct
	for i := len(data) - paddingLength; i < len(data); i++ {
		if data[i] != byte(paddingLength) {
			return nil, fmt.Errorf("invalid padding at position %d: expected %d, got %d", i, paddingLength, data[i])
		}
	}

	// Remove padding
	return data[:len(data)-paddingLength], nil
}

// Decrypt decrypts an IMG3 file using the provided IV and key
// This function assumes the IV and key are already decrypted
func Decrypt(data, iv, key []byte) ([]byte, error) {
	img3, err := ParseImg3(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IMG3: %v", err)
	}

	dataTag, err := img3.GetDataTag()
	if err != nil {
		return nil, fmt.Errorf("failed to get DATA tag: %v", err)
	}

	return DecryptData(dataTag, iv, key)
}

// ExtractData extracts and decompresses data from an unencrypted IMG3 file
// This function is for IMG3 files that don't require decryption
func ExtractData(data []byte) ([]byte, error) {
	img3, err := ParseImg3(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IMG3: %v", err)
	}

	dataTag, err := img3.GetDataTag()
	if err != nil {
		return nil, fmt.Errorf("failed to get DATA tag: %v", err)
	}

	// Check if data is LZFSE compressed
	if len(dataTag) >= 4 && bytes.Contains(dataTag[:4], []byte("bvx2")) {
		decompressed, err := lzfse.NewDecoder(dataTag).DecodeBuffer()
		if err != nil {
			return nil, fmt.Errorf("failed to LZFSE decompress: %v", err)
		}
		return decompressed, nil
	}

	return dataTag, nil
}

// DecryptWithGIDKey decrypts an IMG3 file using the provided GID key
// This function handles the complete decryption process including KBAG decryption
// It tries all available KBAGs until one works
func DecryptWithGIDKey(data, gidKey []byte) ([]byte, error) {
	img3, err := ParseImg3(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IMG3: %v", err)
	}

	kbagDataList, err := img3.GetAllKBagTags()
	if err != nil {
		return nil, fmt.Errorf("failed to get KBAG tags: %v", err)
	}

	dataTag, err := img3.GetDataTag()
	if err != nil {
		return nil, fmt.Errorf("failed to get DATA tag: %v", err)
	}

	var lastErr error
	for i, kbagData := range kbagDataList {
		kbag, err := ParseKBag(kbagData)
		if err != nil {
			lastErr = fmt.Errorf("failed to parse KBAG %d: %v", i+1, err)
			continue
		}

		// Make a copy of the KBAG for decryption attempt
		kbagCopy := &KBagData{
			CryptState: kbag.CryptState,
			AESType:    kbag.AESType,
			IV:         make([]byte, len(kbag.IV)),
			Key:        make([]byte, len(kbag.Key)),
		}
		copy(kbagCopy.IV, kbag.IV)
		copy(kbagCopy.Key, kbag.Key)

		if err := DecryptKBag(kbagCopy, gidKey); err != nil {
			lastErr = fmt.Errorf("failed to decrypt KBAG %d (CryptState=%d): %v", i+1, kbag.CryptState, err)
			continue
		}

		// Try to decrypt the data with this KBAG
		decryptedData, err := DecryptData(dataTag, kbagCopy.IV, kbagCopy.Key)
		if err != nil {
			lastErr = fmt.Errorf("failed to decrypt data with KBAG %d (CryptState=%d): %v", i+1, kbag.CryptState, err)
			continue
		}

		// Check if the decrypted data looks reasonable (not all zeros or random garbage)
		// A simple heuristic: if the first 16 bytes are not all the same value, it's likely valid
		if len(decryptedData) >= 16 {
			firstByte := decryptedData[0]
			allSame := true
			for j := 1; j < 16; j++ {
				if decryptedData[j] != firstByte {
					allSame = false
					break
				}
			}
			if !allSame {
				// This looks like valid decrypted data
				return decryptedData, nil
			}
		}

		lastErr = fmt.Errorf("KBAG %d (CryptState=%d) produced invalid decrypted data", i+1, kbag.CryptState)
	}

	return nil, fmt.Errorf("failed to decrypt with any available KBAG: %v", lastErr)
}

// DecryptWithKBAGKey decrypts an IMG3 file using the provided KBAG decryption key
// This function implements the two-stage decryption process:
// 1. Use the provided key to decrypt the KBAG (which contains the encrypted IV+Key for the data)
// 2. Use the decrypted KBAG's IV+Key to decrypt the actual data
func DecryptWithKBAGKey(data, kbagKey []byte) ([]byte, error) {
	img3, err := ParseImg3(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IMG3: %v", err)
	}

	kbagDataList, err := img3.GetAllKBagTags()
	if err != nil {
		return nil, fmt.Errorf("failed to get KBAG tags: %v", err)
	}

	dataTag, err := img3.GetDataTag()
	if err != nil {
		return nil, fmt.Errorf("failed to get DATA tag: %v", err)
	}

	// Split the KBAG key into IV and Key - but for ECB mode we only need the Key part
	if len(kbagKey) != 32 {
		return nil, fmt.Errorf("KBAG key must be 32 bytes (64 hex characters), got %d bytes", len(kbagKey))
	}
	// For KBAG decryption, we typically use the second half as the key
	kbagKeyOnly := kbagKey[16:32]

	var lastErr error
	for i, kbagData := range kbagDataList {
		kbag, err := ParseKBag(kbagData)
		if err != nil {
			lastErr = fmt.Errorf("failed to parse KBAG %d: %v", i+1, err)
			continue
		}

		// Decrypt the KBAG using the provided KBAG Key
		// The KBAG contains encrypted IV and Key that we need for data decryption
		decryptedIV, err := decryptKBAGWithKey(kbag.IV, kbagKeyOnly)
		if err != nil {
			lastErr = fmt.Errorf("failed to decrypt KBAG %d IV (CryptState=%d): %v", i+1, kbag.CryptState, err)
			continue
		}

		decryptedKey, err := decryptKBAGWithKey(kbag.Key, kbagKeyOnly)
		if err != nil {
			lastErr = fmt.Errorf("failed to decrypt KBAG %d Key (CryptState=%d): %v", i+1, kbag.CryptState, err)
			continue
		}

		// Truncate decrypted key to match expected AES key size
		var finalKey []byte
		switch kbag.AESType {
		case 0x80: // AES128
			if len(decryptedKey) >= 16 {
				finalKey = decryptedKey[:16]
			} else {
				finalKey = decryptedKey
			}
		case 0xc0: // AES192
			if len(decryptedKey) >= 24 {
				finalKey = decryptedKey[:24]
			} else {
				finalKey = decryptedKey
			}
		case 0x100: // AES256
			if len(decryptedKey) >= 32 {
				finalKey = decryptedKey[:32]
			} else {
				finalKey = decryptedKey
			}
		default:
			finalKey = decryptedKey
		}

		// Truncate decrypted IV to 16 bytes
		var finalIV []byte
		if len(decryptedIV) >= 16 {
			finalIV = decryptedIV[:16]
		} else {
			finalIV = decryptedIV
		}

		// Now use the decrypted IV and Key to decrypt the actual data
		decryptedData, err := DecryptData(dataTag, finalIV, finalKey)
		if err != nil {
			lastErr = fmt.Errorf("failed to decrypt data with KBAG %d (CryptState=%d): %v", i+1, kbag.CryptState, err)
			continue
		}

		// Check if the decrypted data looks reasonable
		if len(decryptedData) >= 16 {
			firstByte := decryptedData[0]
			allSame := true
			for j := 1; j < 16; j++ {
				if decryptedData[j] != firstByte {
					allSame = false
					break
				}
			}
			if !allSame {
				// This looks like valid decrypted data
				return decryptedData, nil
			}
		}

		lastErr = fmt.Errorf("KBAG %d (CryptState=%d) produced invalid decrypted data", i+1, kbag.CryptState)
	}

	return nil, fmt.Errorf("failed to decrypt with any available KBAG: %v", lastErr)
}

// decryptKBAGWithKey decrypts KBAG data (IV or Key) using the provided KBAG IV and key in ECB mode
func decryptKBAGWithKey(data, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("KBAG key must be 16 bytes")
	}

	// Create AES cipher with KBAG key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Ensure data length is a multiple of AES block size
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data length must be a multiple of AES block size")
	}

	// Create a copy of the data to decrypt
	decrypted := make([]byte, len(data))
	copy(decrypted, data)

	// Use ECB mode for KBAG decryption (decrypt each 16-byte block independently)
	// This is common for key/IV decryption in cryptographic systems
	for i := 0; i < len(decrypted); i += aes.BlockSize {
		block.Decrypt(decrypted[i:i+aes.BlockSize], decrypted[i:i+aes.BlockSize])
	}

	return decrypted, nil
}

func (i Img3) String() string {
	iStr := fmt.Sprintf(
		"[Img3 Info]\n"+
			"===========\n"+
			"Magic        = %s\n"+
			"Identifier   = %s\n\n"+
			"TAGS\n"+
			"----\n",
		reverseBytes(i.Magic[:]),
		reverseBytes(i.Ident[:]),
	)
	for _, tag := range i.Tags {
		magic := string(reverseBytes(tag.Magic[:]))
		switch magic {
		case "TYPE":
			iStr += fmt.Sprintf("%s: %s\n", magic, reverseBytes(tag.Data[:]))
		case "DATA":
			iStr += fmt.Sprintf("%s: %v (length: %d)\n", magic, tag.Data[0:15], len(tag.Data))
		case "VERS":
			iStr += fmt.Sprintf("%s: %s\n", magic, tag.Data)
		case "SEPO":
			iStr += fmt.Sprintf("%s: %d\n", magic, binary.LittleEndian.Uint32(tag.Data))
		case "CHIP":
			iStr += fmt.Sprintf("%s: 0x%x\n", magic, binary.LittleEndian.Uint32(tag.Data))
		case "BORD":
			iStr += fmt.Sprintf("%s: 0x%x\n", magic, binary.LittleEndian.Uint32(tag.Data))
		case "KBAG":
			if kbag, err := ParseKBag(tag.Data); err == nil {
				iStr += fmt.Sprintf("%s: CryptState=%d, AESType=0x%x, IV=%x, Key=%x\n",
					magic, kbag.CryptState, kbag.AESType, kbag.IV, kbag.Key)
			} else {
				iStr += fmt.Sprintf("%s: %v (parse error: %v)\n", magic, tag.Data, err)
			}
		default:
			iStr += fmt.Sprintf("%s: %v\n", magic, tag.Data)
		}
	}
	return iStr
}

func reverseBytes(a []byte) []byte {
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
}
