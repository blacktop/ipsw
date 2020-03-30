package img4

import (
	"bytes"
	"encoding/asn1"
	"io"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
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
	Manifest    asn1.RawValue   `asn1:"explicit,tag:0"`
	RestoreInfo img4RestoreInfo `asn1:"explicit,tag:1"`
}

type im4p struct {
	Raw         asn1.RawContent
	Name        string // IM4P
	Type        string
	Description string
	Data        []byte
	Kbag        []byte `asn1:"optional"`
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

func parseDataProp(data []byte, pType string) (*dataProp, []byte, error) {
	var d []dataProp
	rest, err := asn1.UnmarshalWithParams(data, &d, pType)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to ASN.1 parse data property")
	}
	return &d[0], rest, nil
}

func parseIDProp(data []byte, pType string) (*idProp, []byte, error) {
	var i []idProp
	rest, err := asn1.UnmarshalWithParams(data, &i, pType)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to ASN.1 parse id property")
	}
	return &i[0], rest, nil
}

func parseBoolProp(data []byte, pType string) (*boolProp, []byte, error) {
	var b []boolProp
	rest, err := asn1.UnmarshalWithParams(data, &b, pType)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to ASN.1 parse bool property")
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
		return nil, errors.Wrap(err, "failed to ASN.1 parse Img4")
	}

	var m img4Manifest
	_, err = asn1.Unmarshal(i.Manifest.Bytes, &m)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Img4 manifest")
	}

	var mb []manifestBody
	_, err = asn1.UnmarshalWithParams(m.Body.Bytes, &mb, typeMANB)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Img4 manifest body")
	}

	var mProps []manifestProperties
	_, err = asn1.UnmarshalWithParams(mb[0].Properties.Bytes, &mProps, typeMANP)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Img4 manifest properties")
	}

	props, err := parseManifestProperties(mProps[0].Properties.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Img4 manifest property")
	}

	gen, _, err := parseDataProp(i.RestoreInfo.Generator.Bytes, typeBNCN)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Generator")
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

func ParseIm4p(r io.Reader) (*im4p, error) {
	utils.Indent(log.Info, 1)("Parsing Im4p")

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i im4p

	_, err := asn1.Unmarshal(data.Bytes(), &i)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Im4p")
	}

	return &i, nil
}
