package download

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/table"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
)

// CREDIT: https://github.com/munki/macadmin-scripts

const (
	seedCatalogsPlist  = "/System/Library/PrivateFrameworks/Seeding.framework/Versions/Current/Resources/SeedCatalogs.plist"
	sucatalogs17       = "https://swscan.apple.com/content/catalogs/others/index-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog"
	sucatalogs18       = "https://swscan.apple.com/content/catalogs/others/index-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog"
	sucatalogs19       = "https://swscan.apple.com/content/catalogs/others/index-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog"
	sucatalogs20       = "https://swscan.apple.com/content/catalogs/others/index-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog"
	sucatalogs21       = "https://swscan.apple.com/content/catalogs/others/index-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog"
	sucatalogs22       = "https://swscan.apple.com/content/catalogs/others/index-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog"
	sucatalogs22Beta   = "https://swscan.apple.com/content/catalogs/others/index-13seed-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog"
	sucatalogs23       = "https://swscan.apple.com/content/catalogs/others/index-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"
	sucatalogs23Beta   = "https://swscan.apple.com/content/catalogs/others/index-14beta-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"
	sucatalogs23Seed   = "https://swscan.apple.com/content/catalogs/others/index-14seed-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"
	sucatalogs24       = "https://swscan.apple.com/content/catalogs/others/index-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"
	sucatalogs24Cust   = "https://swscan.apple.com/content/catalogs/others/index-15customerseed-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"
	sucatalogs24Dev    = "https://swscan.apple.com/content/catalogs/others/index-15seed-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"
	sucatalogs24Public = "https://swscan.apple.com/content/catalogs/others/index-15beta-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"
	sucatalogs26Seed   = "https://swscan.apple.com/content/catalogs/others/index-26seed-26-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"
	sucatalogsLatest   = sucatalogs26Seed
)

type seedCatalog struct {
	CustomerSeed  string
	DeveloperSeed string
	PublicSeed    string
}

type Package struct {
	URL               string `plist:"URL,omitempty"`
	Size              int    `plist:"Size,omitempty"`
	Digest            string `plist:"Digest,omitempty"`
	MetadataURL       string `plist:"MetadataURL,omitempty"`
	IntegrityDataURL  string `plist:"IntegrityDataURL,omitempty"`
	IntegrityDataSize int    `plist:"IntegrityDataSize,omitempty"`
}

type ExtendedMetaInfo struct {
	AutoUpdate                                     string `json:"AutoUpdate,omitempty"`
	ProductType                                    string `json:"ProductType,omitempty"`
	ProductVersion                                 string `json:"ProductVersion,omitempty"`
	BridgeOSPredicateProductOrdering               string `json:"BridgeOSPredicateProductOrdering,omitempty"`
	BridgeOSSoftwareUpdateEventRecordingServiceURL string `json:"BridgeOSSoftwareUpdateEventRecordingServiceURL,omitempty"`
	InstallAssistantPackageIdentifiers             map[string]string
}

type Product struct {
	DeferredSUEnablementDate time.Time `json:"DeferredSUEnablementDate"`
	Distributions            map[string]string
	Packages                 []Package
	PostDate                 time.Time
	ExtendedMetaInfo         ExtendedMetaInfo `plist:"ExtendedMetaInfo,omitempty"`
	ServerMetadataURL        string
}

type Catalog struct {
	ApplePostURL   string
	CatalogVersion int
	IndexDate      time.Time
	Products       map[string]Product
}

type localization struct {
	Description   []byte `plist:"description,omitempty"`
	ServerComment string `plist:"serverComment,omitempty"`
	Title         string `plist:"title,omitempty"`
}

type ServerMetadata struct {
	CFBundleShortVersionString string
	Localization               map[string]localization `plist:"localization,omitempty"`
	Platforms                  map[string][]string     `plist:"platforms,omitempty"`
}

type Options struct {
	VisibleOnlyForPredicate string `xml:"visibleOnlyForPredicate,attr"`
	Customize               string `xml:"customize,attr"`
	RootVolumeOnly          string `xml:"rootVolumeOnly,attr"`
	MajorOSUpdate           string `xml:"major-os-update,attr"`
	RequireScripts          string `xml:"require-scripts,attr"`
}

type auxInfo struct {
	XMLName xml.Name `xml:"auxinfo"`
	Keys    []string `xml:"dict>key"`
	Values  []string `xml:"dict>string"`
}

type PkgRef struct {
	ID                string `xml:"id,attr"`
	PackageIdentifier string `xml:"packageIdentifier,attr"`
	Auth              string `xml:"auth,attr,omitempty"`
	InstallKBytes     string `xml:"installKBytes,attr,omitempty"`
	Version           string `xml:"version,attr,omitempty"`
	Content           string `xml:",chardata"`
}

type Script struct {
	For  string `xml:"for,attr"`
	Data string `xml:",innerxml"`
}

type distribution struct {
	XMLName  xml.Name `xml:"installer-gui-script"`
	Version  string   `xml:"minSpecVersion,attr"`
	Title    string   `xml:"title"`
	Options  Options  `xml:"options"`
	AuxInfo  auxInfo  `xml:"auxinfo"`
	Tags     []string `xml:"tags>tag"`
	Packages []PkgRef `xml:"pkg-ref"`
	Scripts  []Script `xml:"script"`
}

type ProductInfo struct {
	ProductID    string
	Version      string
	Build        string
	PostDate     time.Time
	Title        string
	Product      Product
	Distribution distribution

	distributionData []byte
}

func (i ProductInfo) String() string {
	return fmt.Sprintf("Title: %s, Version: %s, Build: %s, PostDate: %s",
		i.Title,
		i.Version,
		i.Build,
		i.PostDate.Format("02Jan2006 15:04:05"))
}

type ProductInfos []ProductInfo

// FilterByVersion filters out installers that do not match the given version
func (infos ProductInfos) FilterByVersion(version string) ProductInfos {
	var out ProductInfos
	for _, i := range infos {
		if version == i.Version {
			out = append(out, i)
		}
	}
	return out
}

func (infos ProductInfos) FilterByBuild(build string) ProductInfos {
	var out ProductInfos
	for _, i := range infos {
		if build == i.Build {
			out = append(out, i)
		}
	}
	return out
}

func (infos ProductInfos) GetLatest() ProductInfos {
	var out ProductInfos
	lastDate := infos[len(infos)-1].PostDate
	for _, i := range infos {
		if i.PostDate.YearDay() == lastDate.YearDay() {
			out = append(out, i)
		}
	}
	return out
}

func (infos ProductInfos) String() string {
	tableString := &strings.Builder{}
	pdata := [][]string{}
	zone, _ := time.Now().Zone()
	location, err := time.LoadLocation(zone)
	if err != nil {
		for _, pinfo := range infos {
			pdata = append(pdata, []string{
				pinfo.Title,
				pinfo.Version,
				pinfo.Build,
				pinfo.PostDate.Format("02Jan2006 15:04:05 MST"),
			})
		}
	} else {
		for _, pinfo := range infos {
			pdata = append(pdata, []string{
				pinfo.Title,
				pinfo.Version,
				pinfo.Build,
				pinfo.PostDate.In(location).Format("02Jan2006 15:04:05"),
			})
		}
	}
	tbl := table.NewStringBuilderTableWriter(tableString)
	tbl.SetHeader([]string{"Title", "Version", "Build", "Post Date"})
	tbl.SetBorders(nil)
	tbl.SetCenterSeparator("|")
	tbl.AppendBulk(pdata)
	tbl.SetAlignment(1)
	tbl.Render()

	return tableString.String()
}

func zipArrays(arr1, arr2 []string) (map[string]string, error) {
	if len(arr1) != len(arr2) {
		return nil, fmt.Errorf("both arrays are NOT equal in length")
	}
	out := make(map[string]string)
	for i := range arr1 {
		out[strings.ToLower(arr1[i])] = arr2[i]
	}
	return out, nil
}

func getDestName(url string, removeCommas bool) string {
	var destName string
	if removeCommas {
		destName = strings.Replace(path.Base(url), ",", "_", -1)
	} else {
		destName = path.Base(url)
	}
	return destName
}

// GetProductInfo downloads and parses the macOS installer product infos
func GetProductInfo(latest bool) (ProductInfos, error) {

	var catData []byte
	var prods ProductInfos

	if runtime.GOOS == "darwin" && !latest {
		data, err := os.ReadFile(seedCatalogsPlist)
		if err != nil {
			return nil, err
		}

		seed := seedCatalog{}
		if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&seed); err != nil {
			return nil, fmt.Errorf("failed to decode sucatalogs plist: %v", err)
		}

		// resp, err := http.Get(seed.CustomerSeed)
		resp, err := http.Get(seed.DeveloperSeed)
		if err != nil {
			return nil, fmt.Errorf("failed to downoad the sucatalogs: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("failed to connect to URL: %s", resp.Status)
		}

		document, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read sucatalogs data: %v", err)
		}

		gzr, err := gzip.NewReader(bytes.NewReader(document))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer func() {
			if closeErr := gzr.Close(); closeErr != nil {
				log.WithError(closeErr).Warn("failed to close gzip reader")
			}
		}()

		var buff bytes.Buffer
		if _, err := buff.ReadFrom(gzr); err != nil {
			return nil, fmt.Errorf("failed to read gzip data: %v", err)
		}
		catData = buff.Bytes()

	} else {
		resp, err := http.Get(sucatalogsLatest)
		if err != nil {
			return nil, fmt.Errorf("failed to downoad the sucatalogs: %v", err)
		}

		document, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read sucatalogs data: %v", err)
		}

		gzr, err := gzip.NewReader(bytes.NewReader(document))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer func() {
			if closeErr := gzr.Close(); closeErr != nil {
				log.WithError(closeErr).Warn("failed to close gzip reader")
			}
		}()

		var buff bytes.Buffer
		if _, err := buff.ReadFrom(gzr); err != nil {
			return nil, fmt.Errorf("failed to read gzip data: %v", err)
		}
		catData = buff.Bytes()
	}

	cat := Catalog{}
	if err := plist.NewDecoder(bytes.NewReader(catData)).Decode(&cat); err != nil {
		return nil, fmt.Errorf("failed to decode sucatalogs plist: %v", err)
	}

	for key, prod := range cat.Products {

		// filter
		if len(prod.ExtendedMetaInfo.InstallAssistantPackageIdentifiers) == 0 {
			continue
		}

		pInfo := ProductInfo{ProductID: key, PostDate: prod.PostDate, Product: prod}

		if len(prod.ServerMetadataURL) > 0 {
			resp, err := http.Get(prod.ServerMetadataURL)
			if err != nil {
				return nil, fmt.Errorf("failed to download the server metadata %s: %v", prod.ServerMetadataURL, err)
			}

			serverMetadata, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read server metadata: %v", err)
			}

			smeta := ServerMetadata{}
			if err := plist.NewDecoder(bytes.NewReader(serverMetadata)).Decode(&smeta); err != nil {
				return nil, fmt.Errorf("failed to decode server metadata plist: %v", err)
			}

			for lang, loc := range smeta.Localization {
				if strings.HasPrefix(strings.ToLower(lang), "english") {
					pInfo.Title = loc.Title
					pInfo.Version = smeta.CFBundleShortVersionString
					break
				}
			}
		}

		var distURL string
		if dist, ok := prod.Distributions["English"]; ok {
			distURL = dist
		} else {
			if dist, ok := prod.Distributions["en"]; ok {
				distURL = dist
			} else {
				return nil, fmt.Errorf("failed to find English distribution for product: %s", key)
			}
		}

		resp, err := http.Get(distURL)
		if err != nil {
			return nil, fmt.Errorf("failed to download the distribution: %v", err)
		}

		pInfo.distributionData, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read distribution data: %v", err)
		}

		// os.WriteFile("dist.xml", pInfo.distributionData, 0660)

		if err := xml.Unmarshal(pInfo.distributionData, &pInfo.Distribution); err != nil {
			return nil, fmt.Errorf("failed to decode distribution XML data: %v", err)
		}

		if !strings.EqualFold(pInfo.Distribution.Title, "SU_TITLE") {
			pInfo.Title = pInfo.Distribution.Title
		}

		if len(pInfo.Distribution.AuxInfo.Keys) > 0 {
			info, err := zipArrays(pInfo.Distribution.AuxInfo.Keys, pInfo.Distribution.AuxInfo.Values)
			if err != nil {
				return nil, fmt.Errorf("failed to zip distribution auxinfo: %v", err)
			}
			pInfo.Build = info["build"]
			pInfo.Version = info["version"]
		}

		prods = append(prods, pInfo)
	}

	sort.Slice(prods[:], func(i, j int) bool {
		return prods[i].PostDate.Before(prods[j].PostDate)
	})

	return prods, nil
}

func (i *ProductInfo) DownloadInstaller(workDir, proxy string, insecure, skipAll, resumeAll, restartAll, assistantOnly bool) error {

	downloader := NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, true, true)

	folder := filepath.Join(workDir, fmt.Sprintf("%s_%s_%s", strings.ReplaceAll(i.Title, " ", "_"), i.Version, i.Build))

	if err := os.MkdirAll(folder, 0750); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", folder, err)
	}

	log.Info("Downloading packages")
	for _, pkg := range i.Product.Packages {
		if len(pkg.URL) > 0 {
			if assistantOnly && !strings.HasSuffix(pkg.URL, "InstallAssistant.pkg") {
				continue
			}
			destName := getDestName(pkg.URL, false)
			if _, err := os.Stat(filepath.Join(folder, destName)); os.IsNotExist(err) {
				log.WithFields(log.Fields{
					"size":     humanize.Bytes(uint64(pkg.Size)),
					"destName": destName,
				}).Info("Getting Package")
				// download file
				downloader.URL = pkg.URL
				downloader.DestName = filepath.Join(folder, destName)
				if err = downloader.Do(); err != nil {
					return errors.Wrap(err, "failed to download file")
				}
				if len(pkg.IntegrityDataURL) > 0 {
					utils.Indent(log.Info, 2)("Verifying Package")
					resp, err := http.Get(pkg.IntegrityDataURL)
					if err != nil {
						return fmt.Errorf("failed to download the integrity data %s: %v", pkg.IntegrityDataURL, err)
					}
					integrityData, err := io.ReadAll(resp.Body)
					if err != nil {
						return fmt.Errorf("failed to read integrity data: %v", err)
					}
					resp.Body.Close()
					r := bytes.NewReader(integrityData)
					var chklist Chunklist
					if err := binary.Read(r, binary.LittleEndian, &chklist); err != nil {
						return fmt.Errorf("failed to read integrity chunklist: %v", err)
					}
					if chklist.SignatureMethod == ChunkSignatureMethodSHA256 {
						chunks := make([]Chunk, chklist.ChunkCount)
						if err := binary.Read(r, binary.LittleEndian, chunks); err != nil {
							return fmt.Errorf("failed to read integrity chunks: %v", err)
						}
						signature := make([]byte, len(integrityData)-int(chklist.SignatureOffset))
						if err := binary.Read(r, binary.BigEndian, &signature); err != nil {
							return fmt.Errorf("failed to read signature: %v", err)
						}
						f, err := os.Open(filepath.Join(folder, destName))
						if err != nil {
							return fmt.Errorf("failed to open package: %v", err)
						}
						defer f.Close()
						// verify integrity
						for idx, chunk := range chunks {
							chunkData := make([]byte, chunk.Size)
							if _, err := f.Read(chunkData); err != nil {
								return fmt.Errorf("failed to read chunk data: %v", err)
							}
							// verify chunk
							sha256 := sha256.New()
							sha256.Write(chunkData)
							if !bytes.Equal(sha256.Sum(nil), chunk.Hash[:]) {
								return fmt.Errorf("failed to validate %s: chunk #%d integrity check failed", destName, idx)
							}
						}
					}
				}
			} else {
				log.Warnf("pkg already exists: %s", filepath.Join(folder, destName))
			}
		} else if len(pkg.MetadataURL) > 0 {
			if assistantOnly && !strings.HasSuffix(pkg.MetadataURL, "InstallAssistant.pkg") {
				continue
			}
			destName := getDestName(pkg.MetadataURL, false)
			if _, err := os.Stat(filepath.Join(folder, destName)); os.IsNotExist(err) {
				log.WithFields(log.Fields{
					"size":     humanize.Bytes(uint64(pkg.Size)),
					"destName": destName,
				}).Info("Getting Package")
				// download file
				downloader.URL = pkg.URL
				downloader.Sha1 = pkg.Digest
				downloader.DestName = filepath.Join(folder, destName)

				if err := downloader.Do(); err != nil {
					return errors.Wrap(err, "failed to download metadata file")
				}
			} else {
				log.Warnf("pkg already exists: %s", filepath.Join(folder, destName))
			}
		}
	}

	if assistantOnly {
		return nil
	}

	volumeName := fmt.Sprintf("Install_macOS_%s-%s", i.Version, i.Build)
	sparseDiskimagePath := filepath.Join(folder, volumeName+".sparseimage")

	if _, err := os.Stat(sparseDiskimagePath); os.IsNotExist(err) {
		log.Info("Creating empty sparseimage")
		sparseDiskimagePath, err = utils.CreateSparseDiskImage(volumeName, sparseDiskimagePath)
		if err != nil {
			return fmt.Errorf("failed to create sparse disk image: %v", err)
		}
		defer os.Remove(sparseDiskimagePath)
	}

	sparseDiskimageMount := fmt.Sprintf("/tmp/sparseimage_%s-%s", i.Version, i.Build)
	if _, err := os.Stat(sparseDiskimageMount); os.IsNotExist(err) {
		log.Infof("Mounting %s", sparseDiskimageMount)
		if err := utils.Mount(sparseDiskimagePath, sparseDiskimageMount); err != nil {
			return fmt.Errorf("failed to mount sparse disk image: %v", err)
		}
	}

	distPath := filepath.Join(folder, getDestName(i.Product.Distributions["English"], false))
	if _, err := os.Stat(distPath); os.IsNotExist(err) {
		if err := os.WriteFile(distPath, i.distributionData, 0660); err != nil {
			return fmt.Errorf("failed to write distribution data: %v", err)
		}
	}

	log.Infof("Creating installer from distribution %s", distPath)
	if err := utils.CreateInstaller(distPath, sparseDiskimageMount); err != nil {
		return fmt.Errorf("failed to create installer: %v", err)
	}

	var appPath string
	filepath.Walk(sparseDiskimageMount, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to walk sparse disk image mount: %v", err)
		}
		if filepath.Ext(info.Name()) == ".app" {
			appPath = path
		}
		return nil
	})
	if len(appPath) == 0 {
		return fmt.Errorf("app not found in sparse disk image mount")
	}

	// if err := xattr.Set(appPath, "SeedProgram", []byte(sucatalogs20)); err != nil {
	// 	return err
	// }

	dmgPath := filepath.Join(folder, volumeName+".dmg")
	if _, err := os.Stat(dmgPath); os.IsNotExist(err) {
		log.Infof("Creating compressed DMG %s", dmgPath)
		if err := utils.CreateCompressedDMG(appPath, dmgPath); err != nil {
			return err
		}
	}

	if _, err := os.Stat(sparseDiskimageMount); os.IsExist(err) {
		if err := utils.Unmount(sparseDiskimageMount, true); err != nil {
			return err
		}
	}

	return nil
}

const ChunklistMagic = 0x4C4B4E43 // 'CNKL'

type Chunk struct {
	Size uint32
	Hash [32]byte
}

type ChunkSignatureMethod uint8

const (
	ChunkSignatureMethodNone ChunkSignatureMethod = iota
	ChunkSignatureMethodSHA1
	ChunkSignatureMethodSHA256
)

type Chunklist struct {
	Magic           uint32
	HdrSize         uint32
	Version         uint8
	ChunkMethod     uint8
	SignatureMethod ChunkSignatureMethod
	Padding         uint8
	ChunkCount      uint64
	ChunkOffset     uint64
	SignatureOffset uint64
	// Chunks          []Chunk
	// Signature       []byte
}
