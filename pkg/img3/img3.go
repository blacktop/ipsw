package img3

import (
	"encoding/binary"
	"fmt"

	"github.com/blacktop/ipsw/internal/utils"
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

func (i Img3) String() string {
	iStr := fmt.Sprintf(
		"[Img3 Info]\n"+
			"===========\n"+
			"Magic        = %s\n"+
			"Identifier   = %s\n\n"+
			"TAGS\n"+
			"----\n",
		utils.ReverseBytes(i.Magic[:]),
		utils.ReverseBytes(i.Ident[:]),
	)
	for _, tag := range i.Tags {
		magic := string(utils.ReverseBytes(tag.Magic[:]))
		switch magic {
		case "TYPE":
			iStr += fmt.Sprintf("%s: %s\n", magic, utils.ReverseBytes(tag.Data[:]))
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
		default:
			iStr += fmt.Sprintf("%s: %v\n", magic, tag.Data)
		}
	}
	return iStr
}
