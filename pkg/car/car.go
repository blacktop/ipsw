package car

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-termimg"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/bom"
)

type Config struct {
	Output  string
	Export  bool
	Verbose bool
}

type Asset struct {
	Header
	Metadata  extendedMetadata
	KeyFormat []renditionAttributeType
	ImageDB   []Rendition
	ColorDB   map[string]color.RGBA
	// FontDB        map[string]Font
	// FontSizeDB    map[string]uint32
	// GlyphDB       map[string]Glyph
	// BezelDB       map[string]Bezel
	FacetKeyDB    map[string]renditionKeyToken
	BitmapKeyDB   map[any][]byte
	AppearanceDB  map[string]uint16
	Globals       []byte // bplist data
	Localizations map[string]uint32

	conf *Config
}

func (a *Asset) GetName(id uint16) (string, error) {
	for k, v := range a.FacetKeyDB {
		for _, attr := range v.Attributes {
			if attr.Name == 17 && attr.Value == id {
				return k, nil
			}
		}
	}
	return "", fmt.Errorf("could not find name for id: %d", id)
}

type Header struct {
	Tag                [4]byte // 'CTAR'
	CoreUiVersion      uint32
	StorageVersion     uint32
	StorageTimestamp   uint32
	RenditionCount     uint32
	MainVersionString  [128]byte
	VersionString      [256]byte
	UUID               types.UUID
	AssociatedChecksum uint32
	SchemaVersion      uint32
	ColorSpaceID       colorSpaceID
	KeySemantics       uint32
}

type extendedMetadata struct {
	Tag                       [4]byte // 'META'
	ThinningArguments         [256]byte
	DeploymentPlatformVersion [256]byte
	DeploymentPlatform        [256]byte
	AuthoringTool             [256]byte
}

type renditionAttributeType uint32

const (
	ThemeLook               renditionAttributeType = 0
	Element                 renditionAttributeType = 1
	Part                    renditionAttributeType = 2
	Size                    renditionAttributeType = 3
	Direction               renditionAttributeType = 4
	placeholder             renditionAttributeType = 5
	Value                   renditionAttributeType = 6
	ThemeAppearance         renditionAttributeType = 7
	Dimension1              renditionAttributeType = 8
	Dimension2              renditionAttributeType = 9
	State                   renditionAttributeType = 10
	Layer                   renditionAttributeType = 11
	Scale                   renditionAttributeType = 12
	PresentationState       renditionAttributeType = 14
	Idiom                   renditionAttributeType = 15
	Subtype                 renditionAttributeType = 16
	Identifier              renditionAttributeType = 17
	PreviousValue           renditionAttributeType = 18
	PreviousState           renditionAttributeType = 19
	HorizontalSizeClass     renditionAttributeType = 20
	VerticalSizeClass       renditionAttributeType = 21
	MemoryLevelClass        renditionAttributeType = 22
	GraphicsFeatureSetClass renditionAttributeType = 23
	DisplayGamut            renditionAttributeType = 24
	DeploymentTarget        renditionAttributeType = 25
)

type RenditionKeyformat struct {
	Tag                           [4]byte // 'kfmt'
	Version                       uint32
	MaximumRenditionKeyTokenCount uint32
	RenditionKeyTokens            []renditionAttributeType
}

type systemColor struct {
	Version uint32 // 1
	Unknown uint32 // 0
	Color   struct {
		Blue  uint8
		Green uint8
		Red   uint8
		Alpha uint8
	}
}

type renditionLayoutType uint16

const (
	OnePart             renditionLayoutType = 0
	ThreePartHorizontal renditionLayoutType = 1
	ThreePartVertical   renditionLayoutType = 2
	NinePart            renditionLayoutType = 3
	TwelvePart          renditionLayoutType = 4
	ManyPart            renditionLayoutType = 5
	Gradient            renditionLayoutType = 6
	Effect              renditionLayoutType = 7
	Animation           renditionLayoutType = 8
	Vector              renditionLayoutType = 9
	RawData             renditionLayoutType = 1000
	ExternalLink        renditionLayoutType = 1001
	LayerStack          renditionLayoutType = 1002
	InternalLink        renditionLayoutType = 1003
	Packed              renditionLayoutType = 1004
	NamedContents       renditionLayoutType = 1005
	ThinningPlaceholder renditionLayoutType = 1006
	Texture             renditionLayoutType = 1007
	TextureImage        renditionLayoutType = 1008
	Color               renditionLayoutType = 1009
	MultiSizeImageSet   renditionLayoutType = 1010
	ModelAsset          renditionLayoutType = 1011
	ModelMesh           renditionLayoutType = 1012
	RecognitionGroup    renditionLayoutType = 1013
	RecognitionObject   renditionLayoutType = 1014
)

type coreThemeIdiom uint32

const (
	Universal coreThemeIdiom = 0
	Phone     coreThemeIdiom = 1
	Tablet    coreThemeIdiom = 2
	Desktop   coreThemeIdiom = 3
	Tv        coreThemeIdiom = 4
	Car       coreThemeIdiom = 5
	Watch     coreThemeIdiom = 6
	Marketing coreThemeIdiom = 7
)

type renditionAttribute struct {
	Name  uint16
	Value uint16
}
type renditionKeyToken struct {
	CursorHotSpot struct {
		X uint16
		Y uint16
	}
	NumberOfAttributes uint16
	Attributes         []renditionAttribute
}

type Rendition struct {
	Name       string
	Type       string
	Colorspace string
	Size       int
	Attributes map[string]uint16
	Resources  []csiResource
	Asset      any
}

func Parse(name string, conf *Config) (*Asset, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", name, err)
	}
	defer f.Close()

	fi, err := os.Stat(name)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %s: %v", name, err)
	}
	modeTime := fi.ModTime().Local().Unix()

	bm, err := bom.New(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse BOM file: %v", err)
	}

	a := Asset{conf: conf}

	a.AppearanceDB = make(map[string]uint16)
	a.BitmapKeyDB = make(map[any][]byte)
	a.ColorDB = make(map[string]color.RGBA)
	a.Localizations = make(map[string]uint32)

	if a.conf.Verbose {
		log.WithField("name", name).Debug("Parsing BOM")
		utils.Indent(log.Debug, 2)("Blocks/Trees: " + strings.Join(bm.BlockNames(), ", "))
	}

	for _, v := range bm.Vars {
		switch v.Name {
		/**********
		 * BLOCKS *
		 **********/
		case "CARHEADER":
			br, err := bm.ReadBlock(v.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to read block %s: %v", v.Name, err)
			}
			if err := binary.Read(br, binary.LittleEndian, &a.Header); err != nil {
				return nil, fmt.Errorf("failed to read CAR header: %v", err)
			}
			if a.Header.StorageTimestamp == 0 {
				a.Header.StorageTimestamp = uint32(modeTime) // use file modification time
			}
			// TODO: read tree ? (I see a 'tree' following this data, but that might be some other object's sub-tree)
		case "EXTENDED_METADATA":
			br, err := bm.ReadBlock(v.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to read block %s: %v", v.Name, err)
			}
			if err := binary.Read(br, binary.BigEndian, &a.Metadata); err != nil {
				return nil, fmt.Errorf("failed to read extended metadata: %v", err)
			}
		case "KEYFORMAT":
			if err := a.parseKeyFormat(bm); err != nil {
				return nil, fmt.Errorf("failed to parse KEYFORMAT block: %v", err)
			}
		case "CARGLOBALS":
			br, err := bm.ReadBlock(v.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to read block %s: %v", v.Name, err)
			}
			a.Globals, err = io.ReadAll(br)
			if err != nil {
				return nil, fmt.Errorf("failed to read CARGLOBALS data: %v", err)
			}
		case "KEYFORMATWORKAROUND":
			log.Error("BOM block KEYFORMATWORKAROUND parsing not implemented yet - please open an issue on github.com/blacktop/ipsw/issues")
		case "EXTERNAL_KEYS":
			log.Error("BOM block EXTERNAL_KEYS parsing not implemented yet - please open an issue on github.com/blacktop/ipsw/issues")
		/*********
		 * TREES *
		 *********/
		case "APPEARANCEKEYS":
			tree, err := bm.ReadTree("APPEARANCEKEYS")
			if err != nil {
				return nil, fmt.Errorf("failed to read APPEARANCEKEYS tree: %v", err)
			}
			for _, item := range tree.Indices {
				key, err := io.ReadAll(item.KeyReader)
				if err != nil {
					return nil, fmt.Errorf("failed to read key for APPEARANCEKEYS: %v", err)
				}
				var value uint16
				if err := binary.Read(item.ValueReader, binary.LittleEndian, &value); err != nil {
					return nil, fmt.Errorf("failed to read value for key %s: %v", string(key), err)
				}
				a.AppearanceDB[string(key)] = value
			}
		case "BEZELS":
			log.Error("BOM tree BEZELS not implemented yet - please open an issue on github.com/blacktop/ipsw/issues")
		case "BITMAPKEYS":
			// NOTE: /System/Library/PrivateFrameworks/ChatKit.framework/Assets.car is SUPER weird (keys are many different types)
			tree, err := bm.ReadTree("BITMAPKEYS")
			if err != nil {
				return nil, fmt.Errorf("failed to read BITMAPKEYS tree: %v", err)
			}
			for _, item := range tree.Indices {
				if a.conf.Verbose {
					// if err := dumpTreeIndice("BITMAPKEYS", item); err != nil {
					// 	return nil, fmt.Errorf("failed to dump BITMAPKEYS tree indice: %v", err)
					// }
				} else {
					value, err := io.ReadAll(item.ValueReader)
					if err != nil {
						return nil, fmt.Errorf("failed to read BITMAPKEYS value: %v", err)
					}
					// TODO: I think if I understand the struct of the value data it might tell me what the key TYPE is
					keyData, err := io.ReadAll(item.KeyReader)
					if err != nil {
						return nil, fmt.Errorf("failed to read BITMAPKEYS key data: %v", err)
					}
					switch {
					case len(keyData) == 0:
						a.BitmapKeyDB[nil] = value
					case len(keyData) == 4:
						var key uint32
						if err := binary.Read(bytes.NewReader(keyData), binary.LittleEndian, &key); err != nil {
							return nil, fmt.Errorf("failed to read BITMAPKEYS key: %v", err)
						}
						a.BitmapKeyDB[key] = value
					case len(keyData) > 4:
						// a.BitmapKeyDB[keyData] = value FIXME: this is an array of bytes (what does it represent?)
					}
				}
			}
		case "COLORS":
			ctrees, err := bm.ReadTrees("COLORS")
			if err != nil {
				return nil, fmt.Errorf("failed to read COLORS tree: %v", err)
			}
			for _, tree := range ctrees {
				for _, item := range tree.Indices {
					var key uint32 // always 0
					if err := binary.Read(item.KeyReader, binary.LittleEndian, &key); err != nil {
						return nil, fmt.Errorf("failed to read COLORS key: %v", err)
					}
					name, err := readString(item.KeyReader)
					if err != nil {
						return nil, fmt.Errorf("failed to read COLORS name: %v", err)
					}
					var sc systemColor
					if err := binary.Read(item.ValueReader, binary.LittleEndian, &sc); err != nil {
						return nil, fmt.Errorf("failed to read COLORS system color: %v", err)
					}
					a.ColorDB[name] = color.RGBA{
						R: sc.Color.Red,
						G: sc.Color.Green,
						B: sc.Color.Blue,
						A: sc.Color.Alpha,
					}
				}
			}
		case "ELEMENT_INFO":
			log.Error("BOM tree ELEMENT_INFO parsing not implemented yet - please open an issue on github.com/blacktop/ipsw/issues")
		case "FACETKEYS":
			if err := a.parseFacetKeys(bm); err != nil {
				return nil, fmt.Errorf("failed to parse FACETKEYS trees: %v", err)
			}
		case "FONTS":
			log.Error("BOM tree FONTS parsing not implemented yet - please open an issue on github.com/blacktop/ipsw/issues")
		case "FONTSIZES":
			log.Error("BOM tree FONTSIZES parsing not implemented yet - please open an issue on github.com/blacktop/ipsw/issues")
		case "GLYPHS":
			log.Error("BOM tree GLYPHS parsing not implemented yet - please open an issue on github.com/blacktop/ipsw/issues")
		case "LOCALIZATIONKEYS":
			tree, err := bm.ReadTree("LOCALIZATIONKEYS")
			if err != nil {
				return nil, fmt.Errorf("failed to read LOCALIZATIONKEYS tree: %v", err)
			}
			for _, item := range tree.Indices {
				key, err := io.ReadAll(item.KeyReader)
				if err != nil {
					return nil, fmt.Errorf("failed to read LOCALIZATIONKEYS key: %v", err)
				}
				valueData, err := io.ReadAll(item.ValueReader)
				if err != nil {
					return nil, fmt.Errorf("failed to read LOCALIZATIONKEYS value data: %v", err)
				}
				var value uint32
				switch len(valueData) {
				case 2:
					value = uint32(binary.LittleEndian.Uint16(valueData))
				case 4:
					value = binary.LittleEndian.Uint32(valueData)
				default:
					return nil, fmt.Errorf("failed to read LOCALIZATIONKEYS value: %v; data=\n%s", err, hex.Dump(valueData))
				}
				a.Localizations[string(key)] = uint32(value)
			}
		case "PART_INFO":
			log.Error("BOM tree PART_INFO parsing not implemented yet - please open an issue on github.com/blacktop/ipsw/issues")
		case "RENDITIONS":
			if err := a.parseKeyFormat(bm); err != nil {
				return nil, fmt.Errorf("failed to parse asset KeyFormat %v", err)
			}
			rtrees, err := bm.ReadTrees("RENDITIONS")
			if err != nil {
				return nil, fmt.Errorf("failed to read 'RENDITIONS' trees: %v", err)
			}
			for _, tree := range rtrees {
				for _, item := range tree.Indices {
					rend := Rendition{
						Attributes: make(map[string]uint16),
					}
					// parse key data
					keyData, err := io.ReadAll(item.KeyReader)
					if err != nil {
						return nil, fmt.Errorf("failed to read 'RENDITIONS' key data: %v", err)
					}
					attrs := make([]uint16, len(keyData)/binary.Size(uint16(0)))
					if err := binary.Read(bytes.NewReader(keyData), binary.LittleEndian, &attrs); err != nil {
						return nil, fmt.Errorf("failed to read 'RENDITIONS' key attributes: %v", err)
					}
					for idx, k := range a.KeyFormat {
						rend.Attributes[k.String()] = attrs[idx]
					}
					// parse value data
					vdata, err := io.ReadAll(item.ValueReader) // TODO: this might be wasteful if we don't need to read the whole thing
					if err != nil {
						return nil, fmt.Errorf("failed to read 'RENDITIONS' value data: %v", err)
					}
					vr := bytes.NewReader(vdata)
					cheader, err := readCSIFileHeader(vr)
					if err != nil {
						return nil, fmt.Errorf("failed to read 'RENDITIONS' csiHeader: %v", err)
					}
					resourceData := make([]byte, cheader.ChainSize)
					if _, err := vr.Read(resourceData); err != nil {
						return nil, fmt.Errorf("failed to read 'RENDITIONS' resource data: %v", err)
					}
					rr := bytes.NewReader(resourceData)
					for rr.Len() > 0 {
						var rsc csiResource
						if err := binary.Read(rr, binary.LittleEndian, &rsc.ID); err != nil {
							return nil, fmt.Errorf("failed to read 'RENDITIONS' resource ID: %v", err)
						}
						if err := binary.Read(rr, binary.LittleEndian, &rsc.Length); err != nil {
							return nil, fmt.Errorf("failed to read 'RENDITIONS' resource length: %v", err)
						}
						rsc.Data = make([]byte, rsc.Length)
						if _, err := rr.Read(rsc.Data); err != nil {
							return nil, fmt.Errorf("failed to read 'RENDITIONS' resource data: %v", err)
						}
						rend.Resources = append(rend.Resources, rsc)
					}

					rend.Name = string(bytes.Trim(cheader.Metadata.Name[:], "\x00"))
					rend.Type = cheader.Metadata.Layout.String()
					rend.Size = int(cheader.ImageIndex.AccumLength[len(cheader.ImageIndex.AccumLength)-1])

					if vr.Len() > 0 {
						format := string(utils.ReverseBytes(cheader.PixelFormat[:]))
						switch format {
						case PixFmtARGB, PixFmtARGB16, PixFmtRGB555, PixFmtGray, PixFmtGray16:
							rend.Type = "Image"
							img, err := decodeImage(vr, *cheader)
							if err != nil {
								if a.conf.Verbose {
									log.Errorf("failed to decode image '%s': %v; data:\n%s", rend.Name, err, hex.Dump(vdata))
								} else {
									log.Errorf("failed to decode image '%s': %v", rend.Name, err)
								}
								// return nil, err
							}
							if img != nil {
								if a.conf.Export {
									// save image
									name := string(bytes.Trim(cheader.Metadata.Name[:], "\x00"))
									if !strings.HasSuffix(name, ".png") {
										name += ".png"
									}
									imgFile, err := os.Create(filepath.Join(a.conf.Output, name))
									if err != nil {
										return nil, err
									}
									if err := png.Encode(imgFile, img); err != nil {
										return nil, err
									}
									imgFile.Close()
								}
								if a.conf.Verbose {
									// display image in terminal
									log.Debug(rend.Name)
									var dat bytes.Buffer
									buf := bufio.NewWriter(&dat)
									if err := png.Encode(buf, img); err != nil {
										return nil, err
									}
									ti, err := termimg.From(bytes.NewReader(dat.Bytes()))
									if err != nil {
										return nil, fmt.Errorf("failed to create termimg from image: %v", err)
									}
									if err := ti.Print(); err != nil {
										return nil, fmt.Errorf("failed to print termimg: %v", err)
									}
								}
								rend.Asset = img
							}
						case PixFmtPDF:
							rend.Type = "PDF"
							if a.conf.Export {
								name := string(bytes.Trim(cheader.Metadata.Name[:], "\x00"))
								if !strings.HasSuffix(name, ".pdf") {
									name += ".pdf"
								}
								f, err := os.Create(filepath.Join(a.conf.Output, name))
								if err != nil {
									return nil, err
								}
								if _, err := io.Copy(f, vr); err != nil {
									return nil, err
								}
							}
						case PixFmtJPEG:
							rend.Type = "JPEG"
							if a.conf.Export {
								name := string(bytes.Trim(cheader.Metadata.Name[:], "\x00"))
								if !strings.HasSuffix(name, ".jpg") {
									name += ".jpg"
								}
								f, err := os.Create(filepath.Join(a.conf.Output, name))
								if err != nil {
									return nil, err
								}
								if _, err := io.Copy(f, vr); err != nil {
									return nil, err
								}
							}
						case PixFmtHEIF:
							rend.Type = "HEIF"
							if a.conf.Export {
								name := string(bytes.Trim(cheader.Metadata.Name[:], "\x00"))
								if !strings.HasSuffix(name, ".heic") {
									name += ".heic"
								}
								f, err := os.Create(filepath.Join(a.conf.Output, name))
								if err != nil {
									return nil, err
								}
								if _, err := io.Copy(f, vr); err != nil {
									return nil, err
								}
							}
						case PixFmtRawData:
							rend.Type = "Data"
							if a.conf.Export {
								name := string(bytes.Trim(cheader.Metadata.Name[:], "\x00"))
								f, err := os.Create(filepath.Join(a.conf.Output, name))
								if err != nil {
									return nil, err
								}
								if _, err := io.Copy(f, vr); err != nil {
									return nil, err
								}
							}
						case "\x00\x00\x00\x00":
							switch cheader.Metadata.Layout {
							case Effect:
								fallthrough
							case Vector:
								fallthrough
							case RawData:
								fallthrough
							case ExternalLink:
								fallthrough
							case LayerStack:
								log.Errorf("RENDITION layout %s not supported yet - please open an issue on github.com/blacktop/ipsw/issues", cheader.Metadata.Layout)
							case InternalLink:
								ilink, err := parseInternalLink(vr)
								if err != nil {
									return nil, fmt.Errorf("failed to parse rendition internal link: %v", err)
								}
								rend.Asset = ilink
							case Packed:
								fallthrough
							case NamedContents:
								fallthrough
							case ThinningPlaceholder:
								fallthrough
							case Texture:
								fallthrough
							case TextureImage:
								log.Errorf("RENDITION layout %s not supported yet - please open an issue on github.com/blacktop/ipsw/issues", cheader.Metadata.Layout)
							case Color:
								var c csiColor
								if err := binary.Read(vr, binary.LittleEndian, &c.Signature); err != nil {
									return nil, fmt.Errorf("failed to read rendition color signature: %v", err)
								}
								if err := binary.Read(vr, binary.LittleEndian, &c.Version); err != nil {
									return nil, fmt.Errorf("failed to read rendition color version: %v", err)
								}
								if err := binary.Read(vr, binary.LittleEndian, &c.Info); err != nil {
									return nil, fmt.Errorf("failed to read rendition color info: %v", err)
								}
								if err := binary.Read(vr, binary.LittleEndian, &c.NumberOfComponents); err != nil {
									return nil, fmt.Errorf("failed to read rendition color number of components: %v", err)
								}
								c.Components = make([]float64, c.NumberOfComponents)
								if err := binary.Read(vr, binary.LittleEndian, &c.Components); err != nil {
									return nil, fmt.Errorf("failed to read rendition color components: %v", err)
								}
								if c.Info.ColorType() == SystemColorFollows {
									var sysc csiSystemColorName
									if err := binary.Read(vr, binary.LittleEndian, &sysc.Signature); err != nil {
										return nil, fmt.Errorf("failed to read rendition system color signature: %v", err)
									}
									if err := binary.Read(vr, binary.LittleEndian, &sysc.Version); err != nil {
										return nil, fmt.Errorf("failed to read rendition system color version: %v", err)
									}
									if err := binary.Read(vr, binary.LittleEndian, &sysc.Length); err != nil {
										return nil, fmt.Errorf("failed to read rendition system color name length: %v", err)
									}
									sysc.Name = make([]byte, sysc.Length)
									if _, err := vr.Read(sysc.Name); err != nil {
										return nil, fmt.Errorf("failed to read rendition system color name: %v", err)
									}
									rend.Asset = sysc // FIXME: this will stomp the outer color?
								}
								rend.Asset = c
							case MultiSizeImageSet:
								var msi csiMultisizeImageSet
								if err := binary.Read(vr, binary.LittleEndian, &msi.Signature); err != nil {
									return nil, err
								}
								if err := binary.Read(vr, binary.LittleEndian, &msi.Version); err != nil {
									return nil, err
								}
								if err := binary.Read(vr, binary.LittleEndian, &msi.NImageSizes); err != nil {
									return nil, err
								}
								msi.ImageSizes = make([]csiMultiImgSetImageSize, msi.NImageSizes)
								if err := binary.Read(vr, binary.LittleEndian, &msi.ImageSizes); err != nil {
									return nil, err
								}
								rend.Asset = msi
							case ModelAsset:
								fallthrough
							case ModelMesh:
								fallthrough
							case RecognitionGroup:
								fallthrough
							case RecognitionObject:
								log.Errorf("RENDITION layout %s not supported yet - please open an issue on github.com/blacktop/ipsw/issues", cheader.Metadata.Layout)
							default:
								return nil, fmt.Errorf("unknown RENDITION layout: %d - please open an issue on github.com/blacktop/ipsw/issues", cheader.Metadata.Layout)
							}
						default:
							return nil, fmt.Errorf("unknown format: %s", format)
						}
					}
					a.ImageDB = append(a.ImageDB, rend)
				}
			}
		default:
			return nil, fmt.Errorf("unknown BOM block/tree: '%s' - please open an issue on github.com/blacktop/ipsw/issues", name)
		}
	}

	return &a, nil
}

func (a *Asset) parseFacetKeys(bm *bom.BOM) error {
	if a.FacetKeyDB != nil {
		return nil
	}

	a.FacetKeyDB = make(map[string]renditionKeyToken)

	ftree, err := bm.ReadTrees("FACETKEYS")
	if err != nil {
		return fmt.Errorf("failed to read 'FACETKEYS' tree: %v", err)
	}

	for _, tree := range ftree {
		for _, item := range tree.Indices {
			var token renditionKeyToken
			if err := binary.Read(item.ValueReader, binary.LittleEndian, &token.CursorHotSpot); err != nil {
				return fmt.Errorf("failed to read 'FACETKEYS' cursor hotspot: %v", err)
			}
			if err := binary.Read(item.ValueReader, binary.LittleEndian, &token.NumberOfAttributes); err != nil {
				return fmt.Errorf("failed to read 'FACETKEYS' number of attributes: %v", err)
			}
			token.Attributes = make([]renditionAttribute, token.NumberOfAttributes)
			if err := binary.Read(item.ValueReader, binary.LittleEndian, &token.Attributes); err != nil {
				return fmt.Errorf("failed to read 'FACETKEYS' attributes: %v", err)
			}
			name, err := io.ReadAll(item.KeyReader)
			if err != nil {
				return fmt.Errorf("failed to read 'FACETKEYS' name: %v", err)
			}
			a.FacetKeyDB[string(name)] = token
		}
	}

	return nil
}

func (a *Asset) parseKeyFormat(bm *bom.BOM) error {
	if a.KeyFormat != nil {
		return nil
	}
	br, err := bm.ReadBlock("KEYFORMAT")
	if err != nil {
		return fmt.Errorf("failed to read block 'KEYFORMAT': %v", err)
	}
	var keyfmt RenditionKeyformat
	if err := binary.Read(br, binary.LittleEndian, &keyfmt.Tag); err != nil {
		return fmt.Errorf("failed to read 'KEYFORMAT' tag: %v", err)
	}
	if err := binary.Read(br, binary.LittleEndian, &keyfmt.Version); err != nil {
		return fmt.Errorf("failed to read 'KEYFORMAT' version: %v", err)
	}
	if err := binary.Read(br, binary.LittleEndian, &keyfmt.MaximumRenditionKeyTokenCount); err != nil {
		return fmt.Errorf("failed to read 'KEYFORMAT' maximum rendition key token count: %v", err)
	}
	a.KeyFormat = make([]renditionAttributeType, keyfmt.MaximumRenditionKeyTokenCount)
	if err := binary.Read(br, binary.LittleEndian, &a.KeyFormat); err != nil {
		return fmt.Errorf("failed to read 'KEYFORMAT' rendition attribute types: %v", err)
	}
	return nil
}

func readCSIFileHeader(r io.Reader) (*csiHeader, error) { // TODO: this is gross
	var c csiHeader
	if err := binary.Read(r, binary.BigEndian, &c.Signature); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader signature: %v", err)
	}
	if binary.BigEndian.Uint32(c.Signature[:]) != CsiFileSignature {
		return nil, fmt.Errorf("invalid csiHeader signature: %v", c.Signature)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Version); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader version: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Flags); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader flags: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Width); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader width: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Height); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader height: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.PPI); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader ppi: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.PixelFormat); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader pixel format: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.ColorSpace); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader color space: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Metadata); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader metadata: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.ChainSize); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader chain size: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.ImageIndex.Count); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader image index count: %v", err)
	}
	c.ImageIndex.AccumLength = make([]uint32, c.ImageIndex.Count+1)
	if err := binary.Read(r, binary.LittleEndian, &c.ImageIndex.AccumLength); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader image index accum lengths: %v", err)
	}
	return &c, nil
}

func parseInternalLink(r io.Reader) (*csiInternalLinkData, error) {
	var ilink csiInternalLinkData
	if err := binary.Read(r, binary.LittleEndian, &ilink.Signature); err != nil {
		return nil, fmt.Errorf("failed to read rendition internal link signature: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &ilink.Flags); err != nil {
		return nil, fmt.Errorf("failed to read rendition internal link flags: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &ilink.Frame); err != nil {
		return nil, fmt.Errorf("failed to read rendition internal link frame: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &ilink.Layout); err != nil {
		return nil, fmt.Errorf("failed to read rendition internal link layout: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &ilink.Length); err != nil {
		return nil, fmt.Errorf("failed to read rendition internal link length: %v", err)
	}
	ilink.ReferenceData = make([]byte, ilink.Length)
	if err := binary.Read(r, binary.LittleEndian, &ilink.ReferenceData); err != nil {
		return nil, fmt.Errorf("failed to read rendition internal link reference data: %v", err)
	}
	refs := make([]renditionAttribute, len(ilink.ReferenceData)/binary.Size(renditionAttribute{}))
	if err := binary.Read(bytes.NewReader(ilink.ReferenceData), binary.LittleEndian, &refs); err != nil {
		return nil, fmt.Errorf("failed to read rendition internal link references: %v", err)
	}
	return &ilink, nil
}

func readString(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		return strings.Trim(scanner.Text(), "\x00"), nil
	}
	return "", scanner.Err()
}

func dumpTreeIndice(block string, item bom.TreeIndex) error {
	keyData, err := io.ReadAll(item.KeyReader)
	if err != nil {
		return fmt.Errorf("failed to read %s key: %v", block, err)
	}
	println(block + " KEY")
	println(hex.Dump(keyData))

	valueData, err := io.ReadAll(item.ValueReader)
	if err != nil {
		return fmt.Errorf("failed to read %s value: %v", block, err)
	}
	println(block + " VALUE")
	println(hex.Dump(valueData))

	return nil
}
