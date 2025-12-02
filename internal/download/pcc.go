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
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/download/pcc"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const bagURL = "https://init-kt-prod.ess.apple.com/init/getBag?ix=5&p=atresearch"

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
	Type uint32
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
	ExpiryMS        int64
	ExtensionsSize  uint16
	Extensions      []TransparencyExtension
}

type Ticket struct {
	Raw            asn1.RawContent
	Version        int
	ApTicket       asn1.RawValue
	CryptexTickets []asn1.RawValue `asn1:"set"`
}

var colorField = colors.BoldHiBlue().SprintFunc()
var colorTypeField = colors.BoldHiMagenta().SprintFunc()
var colorHash = colors.Faint().SprintfFunc()
var colorName = colors.Bold().SprintfFunc()
var colorCreateTime = colors.FaintGreen().SprintFunc()
var colorExpireTime = colors.FaintRed().SprintFunc()

type PCCRelease struct {
	Index uint64
	pcc.ReleaseMetadata
	Ticket
	*ATLeaf
}

type ByPccIndex []PCCRelease

func (a ByPccIndex) Len() int           { return len(a) }
func (a ByPccIndex) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByPccIndex) Less(i, j int) bool { return a[i].Index > a[j].Index }

func (r PCCRelease) String() string {
	var out string
	out += fmt.Sprintf("%d) %s\n", r.Index, colorHash(hex.EncodeToString(r.GetReleaseHash())))
	out += fmt.Sprintf(colorField("Type")+":   %s\n", pcc.ATLogDataType(r.Type).String())
	out += fmt.Sprintf(colorField("Schema")+": %s\n", string(r.SchemaVersion.String()))
	out += colorField("Assets\n")
	for _, asset := range r.GetAssets() {
		out += fmt.Sprintf("    [%s]\n", colorTypeField(strings.TrimPrefix(asset.GetType().String(), "ASSET_TYPE_")))
		out += fmt.Sprintf(colorField("        Variant")+": %s\n", colorName(asset.GetVariant()))
		out += fmt.Sprintf(colorField("        Digest")+":  %s (%s)\n", colorHash(hex.EncodeToString(asset.Digest.GetValue())), strings.TrimPrefix(asset.Digest.GetDigestAlg().String(), "DIGEST_ALG_"))
		out += fmt.Sprintf(colorField("        URL")+":     %s\n", asset.GetUrl())
	}
	out += colorField("Tickets\n")
	hash := sha256.New()
	hash.Write(r.Ticket.ApTicket.Bytes)
	out += fmt.Sprintf(colorField("    OS")+": %s\n", colorHash(hex.EncodeToString(hash.Sum(nil))))
	out += fmt.Sprintf("        [%s: %s]\n", colorCreateTime("created"), r.GetTimestamp().AsTime().Format("2006-01-02 15:04:05"))
	out += fmt.Sprintf("        [%s: %s]\n", colorExpireTime("expires"), time.UnixMilli(r.ExpiryMS).Format("2006-01-02 15:04:05"))
	out += colorField("    Cryptexes\n")
	for i, ct := range r.Ticket.CryptexTickets {
		hash.Reset()
		hash.Write(ct.Bytes)
		out += fmt.Sprintf("        %d) %s\n", i, colorHash(hex.EncodeToString(hash.Sum(nil))))
	}
	out += colorField("DarwinInit:\n")
	dat, _ := json.MarshalIndent(r.DarwinInit.AsMap(), "", "  ")
	if !colors.Active() {
		out += string(dat)
	} else {
		var buf strings.Builder
		if err := quick.Highlight(&buf, string(dat)+"\n", "json", "terminal256", "nord"); err != nil {
			out += string(dat)
		} else {
			out += buf.String()
		}
	}
	return out
}

func (r PCCRelease) Download(output, proxy string, insecure bool) error {
	if err := os.MkdirAll(output, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}
	pinst := pccInstance{
		HttpService: struct {
			Enabled bool `plist:"enabled,omitempty"`
		}{Enabled: true},
		Name:      hex.EncodeToString(r.GetReleaseHash())[:7],
		ReleaseID: hex.EncodeToString(r.GetReleaseHash()),
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
	for range int(leaf.ExtensionsSize) {
		var ext TransparencyExtension
		if err := binary.Read(r, binary.BigEndian, &ext.Type); err != nil {
			return nil, fmt.Errorf("cannot read extension type: %v", err)
		}
		if err := binary.Read(r, binary.BigEndian, &ext.Size); err != nil {
			return nil, fmt.Errorf("cannot read extension size: %v", err)
		}
		ext.Data = make([]byte, ext.Size)
		if err := binary.Read(r, binary.BigEndian, &ext.Data); err != nil {
			return nil, fmt.Errorf("cannot read extension data: %v", err)
		}
		leaf.Extensions = append(leaf.Extensions, ext)
	}
	return &leaf, nil
}

func GetPCCReleases(proxy string, insecure bool) ([]PCCRelease, error) {
	var releases []PCCRelease

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

	var tree *pcc.ListTreesResponse_Tree
	for _, t := range lt.GetTrees() {
		if t.GetLogType() == pcc.LogType_AT_LOG &&
			t.GetApplication() == pcc.Application_PRIVATE_CLOUD_COMPUTE {
			tree = t
		}
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
	var logHead pcc.LogHead
	if err := proto.Unmarshal(lh.GetLogHead().GetObject(), &logHead); err != nil {
		return nil, fmt.Errorf("cannot unmarshal LogHead: %v", err)
	}

	data, err = proto.Marshal(&pcc.LogLeavesRequest{
		Version:         pcc.ProtocolVersion_V3,
		TreeId:          tree.GetTreeId(),
		StartIndex:      0,
		EndIndex:        logHead.GetLogSize(),
		RequestUuid:     uuid,
		StartMergeGroup: 0,
		EndMergeGroup:   uint32(tree.GetMergeGroups()),
	})
	if err != nil {
		return nil, fmt.Errorf("cannot marshal ListTreesRequest: %v", err)
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
		return nil, fmt.Errorf("returned status: %s", res.Status)
	}

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	var lls pcc.LogLeavesResponse
	if err := proto.Unmarshal(body, &lls); err != nil {
		return nil, fmt.Errorf("cannot unmarshal ListTreesResponse: %v", err)
	}

	for _, leave := range lls.GetLeaves() {
		if leave.GetNodeType() == pcc.NodeType_ATL_NODE {
			var clnode pcc.ChangeLogNodeV2
			if err := proto.Unmarshal(leave.GetNodeBytes(), &clnode); err != nil {
				return nil, fmt.Errorf("cannot unmarshal ChangeLogNodeV2: %v", err)
			}
			// peak at the first 2 bytes to see if it's a release
			blob := make([]byte, 2)
			if err := binary.Read(bytes.NewReader(clnode.GetMutation()), binary.BigEndian, &blob); err != nil {
				return nil, fmt.Errorf("cannot read type: %v", err)
			}
			if pcc.ATLogDataType(blob[1]) != pcc.ATLogDataType_RELEASE {
				continue
			}
			release := PCCRelease{Index: leave.GetIndex()}
			release.ATLeaf, err = parseAtLeaf(bytes.NewReader(clnode.GetMutation()))
			if err != nil {
				return nil, fmt.Errorf("cannot parse ATLeaf: %v", err)
			}
			if err := proto.Unmarshal(leave.GetMetadata(), &release.ReleaseMetadata); err != nil {
				return nil, fmt.Errorf("cannot unmarshal ReleaseMetadata: %v", err)
			}
			if _, err := asn1.Unmarshal(leave.RawData, &release.Ticket); err != nil {
				return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
			}
			releases = append(releases, release)
		}
	}

	return releases, nil
}
