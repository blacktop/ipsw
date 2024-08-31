package img4

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
)

// Img4 object
type Img4 struct {
	Name        string
	Description string
	Manifest    manifest
	RestoreInfo restoreInfo
}

type manifest struct {
	Properties   ManifestProperties
	ApImg4Ticket asn1.RawValue
	img4Manifest
}

type restoreInfo struct {
	Generator dataProp
	img4RestoreInfo
}

type img4 struct {
	Raw         asn1.RawContent
	Name        string // IMG4
	IM4P        im4p
	Manifest    asn1.RawValue   `asn1:"explicit,tag:0,optional"`
	RestoreInfo img4RestoreInfo `asn1:"explicit,tag:1,optional"`
}

type Im4p struct {
	im4p
	Kbags []Keybag
}

type im4p struct {
	Raw         asn1.RawContent
	Name        string `asn1:"ia5"` // IM4P
	Type        string `asn1:"ia5"`
	Description string
	Data        []byte
	KbagData    []byte `asn1:"optional"`
}

type kbagType int

const (
	PRODUCTION  kbagType = 1
	DEVELOPMENT kbagType = 2
	DECRYPTED   kbagType = 3
)

func (t kbagType) String() string {
	switch t {
	case PRODUCTION:
		return "PRODUCTION"
	case DEVELOPMENT:
		return "DEVELOPMENT"
	case DECRYPTED:
		return "DECRYPTED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
func (t kbagType) Short() string {
	switch t {
	case PRODUCTION:
		return "prod"
	case DEVELOPMENT:
		return "dev"
	case DECRYPTED:
		return "dec"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

type Keybag struct {
	Type kbagType
	IV   []byte
	Key  []byte
}

func (k Keybag) String() string {
	return fmt.Sprintf(
		"-\n"+
			"  type: %s\n"+
			"    iv: %x\n"+
			"   key: %x",
		k.Type.String(),
		k.IV,
		k.Key)
}
func (k Keybag) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Type string `json:"type,omitempty"`
		IV   string `json:"iv,omitempty"`
		Key  string `json:"key,omitempty"`
	}{
		Type: k.Type.Short(),
		IV:   hex.EncodeToString(k.IV),
		Key:  hex.EncodeToString(k.Key),
	})
}

const typeBNCN = "private,tag:1112425294"

type img4RestoreInfo struct {
	Raw       asn1.RawContent
	Name      string // IM4R
	Generator asn1.RawValue
}

type img4Manifest struct {
	Raw     asn1.RawContent
	Name    string // IM4M
	Version int
	Body    asn1.RawValue
	Data    []byte
}

const typeMANB = "private,tag:1296125506"

type manifestBody struct {
	Raw        asn1.RawContent
	Name       string // MANB
	Properties asn1.RawValue
}

const typeMANP = "private,tag:1296125520"

type manifestProperties struct {
	Raw        asn1.RawContent
	Name       string // MANP
	Properties asn1.RawValue
}

type idProp struct {
	Raw  asn1.RawContent
	Name string
	ID   int
}

type dataProp struct {
	Raw  asn1.RawContent
	Name string
	Data []byte
}

type boolProp struct {
	Raw  asn1.RawContent
	Name string
	Bool bool
}

type ManifestProperties map[string]interface{}

const typeBNCH = "private,tag:1112425288"

type BNCH struct {
	dataProp
}

const typeBORD = "private,tag:1112494660"

type BORD struct {
	idProp
}

const typeCEPO = "private,tag:1128616015"

type CEPO struct {
	idProp
}

const typeCHIP = "private,tag:1128810832"

type CHIP struct {
	idProp
}

const typeCPRO = "private,tag:1129337423"

type CPRO struct {
	boolProp
}

const typeCSEC = "private,tag:1129530691"

type CSEC struct {
	boolProp
}

const typeECID = "private,tag:1162037572"

type ECID struct {
	idProp
}

const typeSDOM = "private,tag:1396985677"

type SDOM struct {
	idProp
}

const typeSnon = "private,tag:1936617326"

type snon struct {
	dataProp
}

const typeSrvn = "private,tag:1936881262"

type srvn struct {
	dataProp
}

const ( // sepi private tags
	typeImpl = "private,tag:1768779884"
	typeArms = "private,tag:1634889075"
	typeTbmr = "private,tag:1952607602"
	typeTbms = "private,tag:1952607603"
	typeTz0s = "private,tag:1954164851"
)

type arms struct {
	idProp
}
type tbmr struct {
	dataProp
}
type tbms struct {
	dataProp
}
type tz0s struct {
	idProp
}

func parseDataProp(data []byte, pType string) (*dataProp, []byte, error) {
	var d []dataProp
	rest, err := asn1.UnmarshalWithParams(data, &d, pType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ASN.1 parse data property: %v", err)
	}
	return &d[0], rest, nil
}

func parseIDProp(data []byte, pType string) (*idProp, []byte, error) {
	var i []idProp
	rest, err := asn1.UnmarshalWithParams(data, &i, pType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ASN.1 parse id property: %v", err)
	}
	return &i[0], rest, nil
}

func parseBoolProp(data []byte, pType string) (*boolProp, []byte, error) {
	var b []boolProp
	rest, err := asn1.UnmarshalWithParams(data, &b, pType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ASN.1 parse bool property: %v", err)
	}
	return &b[0], rest, nil
}

func parseManifestProperties(data []byte) (*ManifestProperties, error) {
	mProps := make(ManifestProperties)
	// parse BNCH
	dProp, rest, err := parseDataProp(data, typeBNCH)
	if err != nil {
		return nil, err
	}
	mProps[dProp.Name] = dProp.Data
	// parse BORD
	iProp, rest, err := parseIDProp(rest, typeBORD)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse CEPO
	iProp, rest, err = parseIDProp(rest, typeCEPO)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse CHIP
	iProp, rest, err = parseIDProp(rest, typeCHIP)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse CPRO
	bProp, rest, err := parseBoolProp(rest, typeCPRO)
	if err != nil {
		return nil, err
	}
	mProps[bProp.Name] = bProp.Bool
	// parse CSEC
	bProp, rest, err = parseBoolProp(rest, typeCSEC)
	if err != nil {
		return nil, err
	}
	mProps[bProp.Name] = bProp.Bool
	// parse ECID
	iProp, rest, err = parseIDProp(rest, typeECID)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse SDOM
	iProp, rest, err = parseIDProp(rest, typeSDOM)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse snon
	dProp, rest, err = parseDataProp(rest, typeSnon)
	if err != nil {
		return nil, err
	}
	mProps[dProp.Name] = dProp.Data
	// parse srvn
	dProp, rest, err = parseDataProp(rest, typeSrvn)
	if err != nil {
		return nil, err
	}
	mProps[dProp.Name] = dProp.Data

	return &mProps, nil
}

// Parse parses a Img4
func Parse(r io.Reader) (*Img4, error) {
	utils.Indent(log.Info, 2)("Parsing IMG4")

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i img4

	_, err := asn1.Unmarshal(data.Bytes(), &i)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	var m img4Manifest
	_, err = asn1.Unmarshal(i.Manifest.Bytes, &m)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4 manifest: %v", err)
	}

	var mb []manifestBody
	_, err = asn1.UnmarshalWithParams(m.Body.Bytes, &mb, typeMANB)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4 manifest body: %v", err)
	}

	var mProps []manifestProperties
	_, err = asn1.UnmarshalWithParams(mb[0].Properties.Bytes, &mProps, typeMANP)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4 manifest properties: %v", err)
	}

	props, err := parseManifestProperties(mProps[0].Properties.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4 manifest property: %v", err)
	}

	gen, _, err := parseDataProp(i.RestoreInfo.Generator.Bytes, typeBNCN)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Generator: %v", err)
	}

	return &Img4{
		Name:        i.IM4P.Name,
		Description: i.IM4P.Description,
		Manifest: manifest{
			Properties:   *props,
			ApImg4Ticket: i.Manifest,
			img4Manifest: m,
		},
		RestoreInfo: restoreInfo{
			Generator:       *gen,
			img4RestoreInfo: i.RestoreInfo,
		},
	}, nil
}

func OpenIm4p(path string) (*Im4p, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseIm4p(f)
}

func ParseIm4p(r io.Reader) (*Im4p, error) {

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i Im4p

	_, err := asn1.Unmarshal(data.Bytes(), &i.im4p)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Im4p: %v", err)
	}

	if i.im4p.KbagData != nil {
		_, err = asn1.Unmarshal(i.im4p.KbagData, &i.Kbags)
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Im4p KBAG: %v", err)
		}
	}

	return &i, nil
}

func ParseImg4(r io.Reader) (*img4, error) {

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i img4

	if _, err := asn1.Unmarshal(data.Bytes(), &i); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	return &i, nil
}

type im4pKBag struct {
	Name    string   `json:"name,omitempty"`
	Keybags []Keybag `json:"kbags,omitempty"`
}

type KeyBags struct {
	Type    string
	Version string
	Build   string
	Devices []string
	Files   []im4pKBag
}

func (kbs KeyBags) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Type    string     `json:"type,omitempty"`
		Version string     `json:"version,omitempty"`
		Build   string     `json:"build,omitempty"`
		Devices []string   `json:"devices,omitempty"`
		Files   []im4pKBag `json:"files,omitempty"`
	}{
		Type:    kbs.Type,
		Version: kbs.Version,
		Build:   kbs.Build,
		Devices: kbs.Devices,
		Files:   kbs.Files,
	})
}

func ParseZipKeyBags(files []*zip.File, inf *info.Info, pattern string) (*KeyBags, error) {
	kbags := &KeyBags{
		Type:    inf.Plists.Type,
		Version: inf.Plists.BuildManifest.ProductVersion,
		Build:   inf.Plists.BuildManifest.ProductBuildVersion,
		Devices: inf.Plists.Restore.SupportedProductTypes,
	}

	rePattern := `.*im4p$`
	if len(pattern) > 0 {
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, fmt.Errorf("failed to compile --pattern regexp: %v", err)
		}
		rePattern = pattern
	}

	for _, f := range files {
		if regexp.MustCompile(rePattern).MatchString(f.Name) {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("error opening zipped file %s: %v", f.Name, err)
			}
			im4p, err := ParseIm4p(rc)
			if err != nil {
				log.Errorf("failed to parse im4p %s: %v", f.Name, err)
			}
			if im4p.Kbags == nil { // kbags are optional
				continue
			}
			kbags.Files = append(kbags.Files, im4pKBag{
				Name:    filepath.Base(f.Name),
				Keybags: im4p.Kbags,
			})
			rc.Close()
		}
	}

	return kbags, nil
}
