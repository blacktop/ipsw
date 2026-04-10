package download

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/download/pcc"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const bagURL = "https://init-kt-prod.ess.apple.com/init/getBag?ix=5&p=atresearch"

const pccLogLeavesBatchSize uint64 = 3000

type BagResponse struct {
	UUID                          string `plist:"uuid,omitempty"`
	AtResearcherConsistencyProof  string `plist:"at-researcher-consistency-proof,omitempty"`
	AtResearcherListTrees         string `plist:"at-researcher-list-trees,omitempty"`
	AtResearcherLogHead           string `plist:"at-researcher-log-head,omitempty"`
	AtResearcherLogInclusionProof string `plist:"at-researcher-log-inclusion-proof,omitempty"`
	AtResearcherLogLeaves         string `plist:"at-researcher-log-leaves,omitempty"`
	AtResearcherPublicKeys        string `plist:"at-researcher-public-keys,omitempty"`
	BagExpiryTimestamp            int    `plist:"bag-expiry-timestamp,omitempty"`
	BagType                       string `plist:"bag-type,omitempty"`
	BuildVersion                  string `plist:"build-version,omitempty"`
	Platform                      string `plist:"platform,omitempty"`
	TtrEnabled                    int    `plist:"ttr-enabled,omitempty"`
}

type pccInstance struct {
	HttpService struct {
		Enabled bool `plist:"enabled,omitempty"`
	} `plist:"httpService,omitempty"`
	Name          string `plist:"name,omitempty"`
	ReleaseAssets []struct {
		File    string `plist:"file,omitempty"`
		Type    string `plist:"type,omitempty"`
		Variant string `plist:"variant,omitempty"`
	} `plist:"releaseAssets,omitempty"`
	ReleaseID string `plist:"releaseID,omitempty"`
}

type TransparencyExtension struct {
	Type uint8
	Size uint16
	Data []byte
}

type ATLeaf struct {
	Version         uint8
	Type            uint8
	DescriptionSize uint8
	Description     []byte
	HashSize        uint8
	Hash            []byte
	ExpiryMS        uint64
	ExtensionsSize  uint16
	Extensions      []TransparencyExtension
}

type Ticket struct {
	Raw            asn1.RawContent
	Version        int
	ApTicket       asn1.RawValue
	CryptexTickets []asn1.RawValue `asn1:"set"`
}

var colorField = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorTypeField = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
var colorHash = color.New(color.Faint).SprintfFunc()
var colorName = color.New(color.Bold).SprintfFunc()
var colorCreateTime = color.New(color.Faint, color.FgGreen).SprintFunc()
var colorExpireTime = color.New(color.Faint, color.FgRed).SprintFunc()

func pccReleaseHash(release *PCCRelease) []byte {
	if release == nil {
		return nil
	}
	if hash := release.GetReleaseHash(); len(hash) > 0 {
		return hash
	}
	if release.ATLeaf != nil {
		return release.Hash
	}
	return nil
}

func pccReleaseHashString(release *PCCRelease) string {
	return hex.EncodeToString(pccReleaseHash(release))
}

type PCCRelease struct {
	Index uint64
	pcc.ReleaseMetadata
	Ticket
	*ATLeaf
}

// CloudOSInfo returns the com.apple.cloudos.cloudOSInfo preference values
// from DarwinInit. Build version is always populated; train and app appear
// only on newer releases.
func (r *PCCRelease) CloudOSInfo() (build, train, app string) {
	di := r.GetDarwinInit()
	if di == nil {
		return
	}
	prefs, _ := di.AsMap()["preferences"].([]any)
	for _, p := range prefs {
		m, _ := p.(map[string]any)
		if m["application_id"] != "com.apple.cloudos.cloudOSInfo" {
			continue
		}
		v, _ := m["value"].(string)
		switch m["key"] {
		case "cloudOSBuildVersion":
			build = v
		case "cloudOSBuildTrain":
			train = v
		case "cloudOSApplicationName":
			app = v
		}
	}
	return
}

// OSAssetURL returns the URL of the ASSET_TYPE_OS asset (the IPSW).
func (r *PCCRelease) OSAssetURL() string {
	for _, a := range r.GetAssets() {
		if a.GetType() == pcc.ReleaseMetadata_ASSET_TYPE_OS {
			return a.GetUrl()
		}
	}
	return ""
}

// PCCVersion is the ProductVersion/Build pair from an OS asset's BuildManifest.
type PCCVersion struct {
	Version string `json:"v"`
	Build   string `json:"b"`
}

// ResolvePCCVersions partial-zips each release's OS asset to read
// BuildManifest.plist's ProductVersion. Results are cached by asset digest
// (immutable URL path) so subsequent runs are instant. Failures (the newest
// releases sometimes 403 before CDN sync) are not cached and retry next run.
func ResolvePCCVersions(releases []*PCCRelease, fetch func(url string) (PCCVersion, error)) map[string]PCCVersion {
	cache := loadPCCVersionCache()

	type job struct{ digest, url string }
	var jobs []job
	out := make(map[string]PCCVersion, len(releases))
	queued := make(map[string]bool)
	for _, r := range releases {
		url := r.OSAssetURL()
		if url == "" {
			continue
		}
		digest := path.Base(url)
		if v, ok := cache[digest]; ok {
			out[digest] = v
			continue
		}
		// Many releases (TIE/TIE Proxy/PCC Agent variants) share one OS
		// asset digest — fetch each digest once, not once per release.
		if queued[digest] {
			continue
		}
		queued[digest] = true
		jobs = append(jobs, job{digest, url})
	}
	if len(jobs) == 0 {
		return out
	}

	log.Infof("Resolving %d uncached PCC OS versions...", len(jobs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, j := range jobs {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			v, err := fetch(j.url)
			if err != nil || v.Version == "" {
				log.Debugf("resolve %s: %v", j.digest, err)
				return
			}
			mu.Lock()
			out[j.digest] = v
			cache[j.digest] = v
			mu.Unlock()
		})
	}
	wg.Wait()

	savePCCVersionCache(cache)
	return out
}

func loadPCCVersionCache() map[string]PCCVersion {
	cache := make(map[string]PCCVersion)
	dir, err := getCacheDir()
	if err != nil {
		return cache
	}
	data, err := os.ReadFile(filepath.Join(dir, "pcc_versions.json"))
	if err != nil {
		return cache
	}
	json.Unmarshal(data, &cache)
	return cache
}

func savePCCVersionCache(cache map[string]PCCVersion) {
	dir, err := getCacheDir()
	if err != nil {
		return
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(dir, "pcc_versions.json"), data, 0o644)
}

func (r *PCCRelease) String() string {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%d) %s\n", r.Index, colorHash(pccReleaseHashString(r))))
	if build, train, app := r.CloudOSInfo(); build != "" {
		out.WriteString(fmt.Sprintf(colorField("Build")+":  %s", colorName(build)))
		if train != "" {
			out.WriteString(fmt.Sprintf(" (%s)", train))
		}
		if app != "" {
			out.WriteString(fmt.Sprintf("  %s", colorTypeField(app)))
		}
		out.WriteString("\n")
	}
	out.WriteString(fmt.Sprintf(colorField("Type")+":   %s\n", pcc.ATLogDataType(r.Type).String()))
	out.WriteString(fmt.Sprintf(colorField("Schema")+": %s\n", string(r.SchemaVersion.String())))
	out.WriteString(colorField("Assets\n"))
	for _, asset := range r.GetAssets() {
		out.WriteString(fmt.Sprintf("    [%s]\n", colorTypeField(strings.TrimPrefix(asset.GetType().String(), "ASSET_TYPE_"))))
		out.WriteString(fmt.Sprintf(colorField("        Variant")+": %s\n", colorName(asset.GetVariant())))
		out.WriteString(fmt.Sprintf(colorField("        Digest")+":  %s (%s)\n", colorHash(hex.EncodeToString(asset.Digest.GetValue())), strings.TrimPrefix(asset.Digest.GetDigestAlg().String(), "DIGEST_ALG_")))
		out.WriteString(fmt.Sprintf(colorField("        URL")+":     %s\n", asset.GetUrl()))
	}
	out.WriteString(colorField("Tickets\n"))
	hash := sha256.New()
	hash.Write(r.Ticket.ApTicket.Bytes)
	out.WriteString(fmt.Sprintf(colorField("    OS")+": %s\n", colorHash(hex.EncodeToString(hash.Sum(nil)))))
	out.WriteString(fmt.Sprintf("        [%s: %s]\n", colorCreateTime("created"), r.GetTimestamp().AsTime().Format("2006-01-02 15:04:05")))
	out.WriteString(fmt.Sprintf("        [%s: %s]\n", colorExpireTime("expires"), time.UnixMilli(int64(r.ExpiryMS)).Format("2006-01-02 15:04:05")))
	out.WriteString(colorField("    Cryptexes\n"))
	for i, ct := range r.Ticket.CryptexTickets {
		hash.Reset()
		hash.Write(ct.Bytes)
		out.WriteString(fmt.Sprintf("        %d) %s\n", i, colorHash(hex.EncodeToString(hash.Sum(nil)))))
	}
	out.WriteString(colorField("DarwinInit:\n"))
	dat, _ := json.MarshalIndent(r.DarwinInit.AsMap(), "", "  ")
	if color.NoColor {
		out.WriteString(string(dat))
	} else {
		var buf strings.Builder
		if err := quick.Highlight(&buf, string(dat)+"\n", "json", "terminal256", "nord"); err != nil {
			out.WriteString(string(dat))
		} else {
			out.WriteString(buf.String())
		}
	}
	return out.String()
}

func (r *PCCRelease) Download(output, proxy string, insecure bool) error {
	// Preflight: HEAD every asset before downloading anything. The newest
	// releases sometimes 403 on the OS IPSW before CDN sync — fail now
	// rather than after pulling several GB of other assets.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}
	for _, asset := range r.GetAssets() {
		req, err := http.NewRequest(http.MethodHead, asset.GetUrl(), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("preflight %s: %w", asset.GetType(), err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("asset %s unavailable (HTTP %d) — newest releases may not be on the CDN yet; try an older release or retry later",
				strings.TrimPrefix(asset.GetType().String(), "ASSET_TYPE_"), resp.StatusCode)
		}
	}

	if err := os.MkdirAll(output, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}
	releaseID := pccReleaseHashString(r)
	releaseName := releaseID
	if len(releaseName) > 7 {
		releaseName = releaseName[:7]
	}
	if releaseName == "" {
		releaseName = fmt.Sprintf("%d", r.Index)
	}
	pinst := pccInstance{
		HttpService: struct {
			Enabled bool `plist:"enabled,omitempty"`
		}{Enabled: true},
		Name:      releaseName,
		ReleaseID: releaseID,
	}
	for _, asset := range r.GetAssets() {
		assetURL := asset.GetUrl()
		filePath := filepath.Join(output, strings.TrimPrefix(asset.GetType().String(), "ASSET_TYPE_")+assetTypeExt(asset.GetType()))
		pinst.ReleaseAssets = append(pinst.ReleaseAssets, struct {
			File    string `plist:"file,omitempty"`
			Type    string `plist:"type,omitempty"`
			Variant string `plist:"variant,omitempty"`
		}{
			File:    filepath.Base(filePath),
			Type:    asset.GetType().String(),
			Variant: asset.GetVariant(),
		})
		log.WithFields(log.Fields{
			"digest":  hex.EncodeToString(asset.Digest.GetValue()),
			"variant": asset.GetVariant(),
		}).Info("Downloading Asset")
		downloader := NewDownload(proxy, insecure, false, false, false, false, false)
		downloader.URL = assetURL
		downloader.DestName = filePath
		if err := downloader.Do(); err != nil {
			return err
		}
	}
	dat, err := json.MarshalIndent(r.DarwinInit.AsMap(), "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal darwin-init.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(output, "darwin-init.json"), dat, 0644); err != nil {
		return fmt.Errorf("failed to write darwin-init.json: %v", err)
	}
	pdat, err := plist.MarshalIndent(pinst, plist.XMLFormat, "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal instance.plist: %v", err)
	}
	if err := os.WriteFile(filepath.Join(output, "instance.plist"), pdat, 0644); err != nil {
		return fmt.Errorf("failed to write instance.plist: %v", err)
	}
	return nil
}

func assetTypeExt(typ pcc.ReleaseMetadata_AssetType) string {
	switch typ {
	case pcc.ReleaseMetadata_ASSET_TYPE_OS:
		return ".ipsw"
	case pcc.ReleaseMetadata_ASSET_TYPE_PCS, pcc.ReleaseMetadata_ASSET_TYPE_MODEL, pcc.ReleaseMetadata_ASSET_TYPE_DEBUG_SHELL:
		return ".aar"
	case pcc.ReleaseMetadata_ASSET_TYPE_HOST_TOOLS:
		return ".dmg"
	default: // ReleaseMetadata_ASSET_TYPE_UNSPECIFIED
		return ""
	}
}

func parseAtLeaf(r *bytes.Reader) (*ATLeaf, error) {
	var leaf ATLeaf

	if err := binary.Read(r, binary.BigEndian, &leaf.Version); err != nil {
		return nil, fmt.Errorf("cannot read version: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.Type); err != nil {
		return nil, fmt.Errorf("cannot read type: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.DescriptionSize); err != nil {
		return nil, fmt.Errorf("cannot read description size: %v", err)
	}
	leaf.Description = make([]byte, leaf.DescriptionSize)
	if err := binary.Read(r, binary.BigEndian, &leaf.Description); err != nil {
		return nil, fmt.Errorf("cannot read description: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.HashSize); err != nil {
		return nil, fmt.Errorf("cannot read hash size: %v", err)
	}
	leaf.Hash = make([]byte, leaf.HashSize)
	if err := binary.Read(r, binary.BigEndian, &leaf.Hash); err != nil {
		return nil, fmt.Errorf("cannot read hash: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.ExpiryMS); err != nil {
		return nil, fmt.Errorf("cannot read expiry: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.ExtensionsSize); err != nil {
		return nil, fmt.Errorf("cannot read extensions size: %v", err)
	}
	extensionData := make([]byte, leaf.ExtensionsSize)
	if err := binary.Read(r, binary.BigEndian, &extensionData); err != nil {
		return nil, fmt.Errorf("cannot read extensions: %v", err)
	}
	er := bytes.NewReader(extensionData)
	for er.Len() > 0 {
		var ext TransparencyExtension
		if err := binary.Read(er, binary.BigEndian, &ext.Type); err != nil {
			return nil, fmt.Errorf("cannot read extension type: %v", err)
		}
		if err := binary.Read(er, binary.BigEndian, &ext.Size); err != nil {
			return nil, fmt.Errorf("cannot read extension size: %v", err)
		}
		ext.Data = make([]byte, ext.Size)
		if err := binary.Read(er, binary.BigEndian, &ext.Data); err != nil {
			return nil, fmt.Errorf("cannot read extension data: %v", err)
		}
		leaf.Extensions = append(leaf.Extensions, ext)
	}
	return &leaf, nil
}

func hintedATLeafType(mutation []byte) (pcc.ATLogDataType, bool) {
	if len(mutation) < 2 {
		return 0, false
	}
	return pcc.ATLogDataType(mutation[1]), true
}

func parsePCCReleaseLeaf(leaf *pcc.LogLeavesResponse_Leaf) (*PCCRelease, error) {
	if leaf.GetNodeType() != pcc.NodeType_ATL_NODE {
		return nil, nil
	}

	var clnode pcc.ChangeLogNodeV2
	if err := proto.Unmarshal(leaf.GetNodeBytes(), &clnode); err != nil {
		if typ, ok := hintedATLeafType(clnode.GetMutation()); ok && typ != pcc.ATLogDataType_RELEASE {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot unmarshal ChangeLogNodeV2: %v", err)
	}

	atLeaf, err := parseAtLeaf(bytes.NewReader(clnode.GetMutation()))
	if err != nil {
		if typ, ok := hintedATLeafType(clnode.GetMutation()); ok && typ != pcc.ATLogDataType_RELEASE {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot parse ATLeaf: %v", err)
	}
	if pcc.ATLogDataType(atLeaf.Type) != pcc.ATLogDataType_RELEASE {
		return nil, nil
	}

	if len(leaf.GetMetadata()) == 0 {
		return nil, fmt.Errorf("release leaf missing metadata")
	}
	if len(leaf.GetRawData()) == 0 {
		return nil, fmt.Errorf("release leaf missing raw ticket data")
	}

	release := &PCCRelease{
		Index:  leaf.GetIndex(),
		ATLeaf: atLeaf,
	}

	if err := proto.Unmarshal(leaf.GetMetadata(), &release.ReleaseMetadata); err != nil {
		return nil, fmt.Errorf("cannot unmarshal ReleaseMetadata: %v", err)
	}
	if _, err := asn1.Unmarshal(leaf.GetRawData(), &release.Ticket); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	return release, nil
}

func collectPCCReleases(logSize, batchSize uint64, progress func(done, total uint64), fetchLeaves func(startIndex, endIndex uint64) ([]*pcc.LogLeavesResponse_Leaf, error)) ([]*PCCRelease, error) {
	if logSize == 0 {
		return nil, nil
	}
	if batchSize == 0 {
		batchSize = pccLogLeavesBatchSize
	}

	var releases []*PCCRelease

	for startIndex := uint64(0); startIndex < logSize; startIndex += batchSize {
		endIndex := min(startIndex+batchSize, logSize)
		leaves, err := fetchLeaves(startIndex, endIndex)
		if err != nil {
			return nil, err
		}
		for _, leaf := range leaves {
			release, err := parsePCCReleaseLeaf(leaf)
			if err != nil {
				return nil, fmt.Errorf("failed to parse pcc log leaf %d: %w", leaf.GetIndex(), err)
			}
			if release != nil {
				releases = append(releases, release)
			}
		}
		if progress != nil {
			progress(endIndex, logSize)
		}
	}

	return releases, nil
}

func UniquePCCReleases(releases []*PCCRelease) []*PCCRelease {
	if len(releases) < 2 {
		return releases
	}

	unique := make([]*PCCRelease, 0, len(releases))
	seen := make(map[string]int, len(releases))

	for _, release := range releases {
		hash := pccReleaseHashString(release)
		if hash == "" {
			unique = append(unique, release)
			continue
		}
		if idx, ok := seen[hash]; ok {
			if release.Index > unique[idx].Index {
				unique[idx] = release
			}
			continue
		}
		seen[hash] = len(unique)
		unique = append(unique, release)
	}

	return unique
}

func GetPCCReleases(proxy string, insecure bool, progress func(done, total uint64)) ([]*PCCRelease, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	req, err := http.NewRequest("GET", bagURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http POST request: %v", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to GET pcc atresearch bag: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pcc atresearch bag GET returned status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	var bag BagResponse
	if _, err := plist.Unmarshal(body, &bag); err != nil {
		return nil, fmt.Errorf("cannot unmarshal plist: %v", err)
	}

	uuid := uuid.NewString()

	data, err := proto.Marshal(&pcc.ListTreesRequest{
		Version:     pcc.ProtocolVersion_V3,
		RequestUuid: uuid,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot marshal ListTreesRequest: %v", err)
	}

	req, err = http.NewRequest("POST", bag.AtResearcherListTrees, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("cannot create http POST request: %v", err)
	}
	req.Header.Set("X-Apple-Request-UUID", uuid)
	req.Header.Set("Content-Type", "application/protobuf")
	req.Header.Add("User-Agent", utils.RandomAgent())

	res, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status: %s", res.Status)
	}

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	var lt pcc.ListTreesResponse
	if err := proto.Unmarshal(body, &lt); err != nil {
		return nil, fmt.Errorf("cannot unmarshal ListTreesResponse: %v", err)
	}
	if lt.GetStatus() != pcc.Status_OK {
		return nil, fmt.Errorf("pcc list trees returned status: %s", lt.GetStatus())
	}

	var tree *pcc.ListTreesResponse_Tree
	for _, t := range lt.GetTrees() {
		if t.GetLogType() == pcc.LogType_AT_LOG &&
			t.GetApplication() == pcc.Application_PRIVATE_CLOUD_COMPUTE {
			tree = t
		}
	}
	if tree == nil {
		return nil, fmt.Errorf("failed to find private cloud compute tree in list trees response")
	}

	data, err = proto.Marshal(&pcc.LogHeadRequest{
		Version:     pcc.ProtocolVersion_V3,
		TreeId:      tree.GetTreeId(),
		Revision:    -1,
		RequestUuid: uuid,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot marshal ListTreesRequest: %v", err)
	}

	req, err = http.NewRequest("POST", bag.AtResearcherLogHead, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("cannot create http POST request: %v", err)
	}
	req.Header.Set("X-Apple-Request-UUID", uuid)
	req.Header.Set("Content-Type", "application/protobuf")
	req.Header.Add("User-Agent", utils.RandomAgent())

	res, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status: %s", res.Status)
	}

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	var lh pcc.LogHeadResponse
	if err := proto.Unmarshal(body, &lh); err != nil {
		return nil, fmt.Errorf("cannot unmarshal ListTreesResponse: %v", err)
	}
	if lh.GetStatus() != pcc.Status_OK {
		return nil, fmt.Errorf("pcc log head returned status: %s", lh.GetStatus())
	}
	if lh.GetLogHead() == nil {
		return nil, fmt.Errorf("pcc log head response missing log head object")
	}
	var logHead pcc.LogHead
	if err := proto.Unmarshal(lh.GetLogHead().GetObject(), &logHead); err != nil {
		return nil, fmt.Errorf("cannot unmarshal LogHead: %v", err)
	}

	return collectPCCReleases(logHead.GetLogSize(), pccLogLeavesBatchSize, progress, func(startIndex, endIndex uint64) ([]*pcc.LogLeavesResponse_Leaf, error) {
		data, err := proto.Marshal(&pcc.LogLeavesRequest{
			Version:         pcc.ProtocolVersion_V3,
			TreeId:          tree.GetTreeId(),
			StartIndex:      startIndex,
			EndIndex:        endIndex,
			RequestUuid:     uuid,
			StartMergeGroup: 0,
			EndMergeGroup:   uint32(tree.GetMergeGroups()),
		})
		if err != nil {
			return nil, fmt.Errorf("cannot marshal LogLeavesRequest: %v", err)
		}

		req, err = http.NewRequest("POST", bag.AtResearcherLogLeaves, bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("cannot create http POST request: %v", err)
		}
		req.Header.Set("X-Apple-Request-UUID", uuid)
		req.Header.Set("Content-Type", "application/protobuf")
		req.Header.Add("User-Agent", utils.RandomAgent())

		res, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("pcc log leaves [%d,%d) returned http status: %s", startIndex, endIndex, res.Status)
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		var lls pcc.LogLeavesResponse
		if err := proto.Unmarshal(body, &lls); err != nil {
			return nil, fmt.Errorf("cannot unmarshal LogLeavesResponse: %v", err)
		}
		if lls.GetStatus() != pcc.Status_OK {
			return nil, fmt.Errorf("pcc log leaves [%d,%d) returned status: %s", startIndex, endIndex, lls.GetStatus())
		}

		return lls.GetLeaves(), nil
	})
}
