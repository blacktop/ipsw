package pcc

import (
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ReleaseMetadata_SchemaVersion int32

const (
	ReleaseMetadata_SCHEMA_VERSION_UNSPECIFIED ReleaseMetadata_SchemaVersion = 0
	ReleaseMetadata_SCHEMA_VERSION_V1          ReleaseMetadata_SchemaVersion = 1
)

// Enum value maps for ReleaseMetadata_SchemaVersion.
var (
	ReleaseMetadata_SchemaVersion_name = map[int32]string{
		0: "SCHEMA_VERSION_UNSPECIFIED",
		1: "SCHEMA_VERSION_V1",
	}
	ReleaseMetadata_SchemaVersion_value = map[string]int32{
		"SCHEMA_VERSION_UNSPECIFIED": 0,
		"SCHEMA_VERSION_V1":          1,
	}
)

func (x ReleaseMetadata_SchemaVersion) Enum() *ReleaseMetadata_SchemaVersion {
	p := new(ReleaseMetadata_SchemaVersion)
	*p = x
	return p
}

func (x ReleaseMetadata_SchemaVersion) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ReleaseMetadata_SchemaVersion) Descriptor() protoreflect.EnumDescriptor {
	return file_ReleaseMetadata_proto_enumTypes[0].Descriptor()
}

func (ReleaseMetadata_SchemaVersion) Type() protoreflect.EnumType {
	return &file_ReleaseMetadata_proto_enumTypes[0]
}

func (x ReleaseMetadata_SchemaVersion) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ReleaseMetadata_SchemaVersion.Descriptor instead.
func (ReleaseMetadata_SchemaVersion) EnumDescriptor() ([]byte, []int) {
	return file_ReleaseMetadata_proto_rawDescGZIP(), []int{0, 0}
}

type ReleaseMetadata_AssetType int32

const (
	ReleaseMetadata_ASSET_TYPE_UNSPECIFIED ReleaseMetadata_AssetType = 0
	ReleaseMetadata_ASSET_TYPE_OS          ReleaseMetadata_AssetType = 1 // (VRE) restore image
	ReleaseMetadata_ASSET_TYPE_PCS         ReleaseMetadata_AssetType = 2 // (VRE) PrivateCloudSupport (Private cloud extensions)
	ReleaseMetadata_ASSET_TYPE_MODEL       ReleaseMetadata_AssetType = 3 // (VRE) research model + adapter
	ReleaseMetadata_ASSET_TYPE_HOST_TOOLS  ReleaseMetadata_AssetType = 4 // (Host) PrivateCloudTools
	ReleaseMetadata_ASSET_TYPE_DEBUG_SHELL ReleaseMetadata_AssetType = 5 // (VRE) ssh server, etc
)

// Enum value maps for ReleaseMetadata_AssetType.
var (
	ReleaseMetadata_AssetType_name = map[int32]string{
		0: "ASSET_TYPE_UNSPECIFIED",
		1: "ASSET_TYPE_OS",
		2: "ASSET_TYPE_PCS",
		3: "ASSET_TYPE_MODEL",
		4: "ASSET_TYPE_HOST_TOOLS",
		5: "ASSET_TYPE_DEBUG_SHELL",
	}
	ReleaseMetadata_AssetType_value = map[string]int32{
		"ASSET_TYPE_UNSPECIFIED": 0,
		"ASSET_TYPE_OS":          1,
		"ASSET_TYPE_PCS":         2,
		"ASSET_TYPE_MODEL":       3,
		"ASSET_TYPE_HOST_TOOLS":  4,
		"ASSET_TYPE_DEBUG_SHELL": 5,
	}
)

func (x ReleaseMetadata_AssetType) Enum() *ReleaseMetadata_AssetType {
	p := new(ReleaseMetadata_AssetType)
	*p = x
	return p
}

func (x ReleaseMetadata_AssetType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ReleaseMetadata_AssetType) Descriptor() protoreflect.EnumDescriptor {
	return file_ReleaseMetadata_proto_enumTypes[1].Descriptor()
}

func (ReleaseMetadata_AssetType) Type() protoreflect.EnumType {
	return &file_ReleaseMetadata_proto_enumTypes[1]
}

func (x ReleaseMetadata_AssetType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ReleaseMetadata_AssetType.Descriptor instead.
func (ReleaseMetadata_AssetType) EnumDescriptor() ([]byte, []int) {
	return file_ReleaseMetadata_proto_rawDescGZIP(), []int{0, 1}
}

type ReleaseMetadata_FileType int32

const (
	ReleaseMetadata_FILE_TYPE_UNSPECIFIED  ReleaseMetadata_FileType = 0
	ReleaseMetadata_FILE_TYPE_IPSW         ReleaseMetadata_FileType = 1
	ReleaseMetadata_FILE_TYPE_DISKIMAGE    ReleaseMetadata_FileType = 2
	ReleaseMetadata_FILE_TYPE_APPLEARCHIVE ReleaseMetadata_FileType = 3
)

// Enum value maps for ReleaseMetadata_FileType.
var (
	ReleaseMetadata_FileType_name = map[int32]string{
		0: "FILE_TYPE_UNSPECIFIED",
		1: "FILE_TYPE_IPSW",
		2: "FILE_TYPE_DISKIMAGE",
		3: "FILE_TYPE_APPLEARCHIVE",
	}
	ReleaseMetadata_FileType_value = map[string]int32{
		"FILE_TYPE_UNSPECIFIED":  0,
		"FILE_TYPE_IPSW":         1,
		"FILE_TYPE_DISKIMAGE":    2,
		"FILE_TYPE_APPLEARCHIVE": 3,
	}
)

func (x ReleaseMetadata_FileType) Enum() *ReleaseMetadata_FileType {
	p := new(ReleaseMetadata_FileType)
	*p = x
	return p
}

func (x ReleaseMetadata_FileType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ReleaseMetadata_FileType) Descriptor() protoreflect.EnumDescriptor {
	return file_ReleaseMetadata_proto_enumTypes[2].Descriptor()
}

func (ReleaseMetadata_FileType) Type() protoreflect.EnumType {
	return &file_ReleaseMetadata_proto_enumTypes[2]
}

func (x ReleaseMetadata_FileType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ReleaseMetadata_FileType.Descriptor instead.
func (ReleaseMetadata_FileType) EnumDescriptor() ([]byte, []int) {
	return file_ReleaseMetadata_proto_rawDescGZIP(), []int{0, 2}
}

type ReleaseMetadata_DigestAlg int32

const (
	ReleaseMetadata_DIGEST_ALG_UNSPECIFIED ReleaseMetadata_DigestAlg = 0
	ReleaseMetadata_DIGEST_ALG_SHA256      ReleaseMetadata_DigestAlg = 1
	ReleaseMetadata_DIGEST_ALG_SHA384      ReleaseMetadata_DigestAlg = 2
)

// Enum value maps for ReleaseMetadata_DigestAlg.
var (
	ReleaseMetadata_DigestAlg_name = map[int32]string{
		0: "DIGEST_ALG_UNSPECIFIED",
		1: "DIGEST_ALG_SHA256",
		2: "DIGEST_ALG_SHA384",
	}
	ReleaseMetadata_DigestAlg_value = map[string]int32{
		"DIGEST_ALG_UNSPECIFIED": 0,
		"DIGEST_ALG_SHA256":      1,
		"DIGEST_ALG_SHA384":      2,
	}
)

func (x ReleaseMetadata_DigestAlg) Enum() *ReleaseMetadata_DigestAlg {
	p := new(ReleaseMetadata_DigestAlg)
	*p = x
	return p
}

func (x ReleaseMetadata_DigestAlg) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ReleaseMetadata_DigestAlg) Descriptor() protoreflect.EnumDescriptor {
	return file_ReleaseMetadata_proto_enumTypes[3].Descriptor()
}

func (ReleaseMetadata_DigestAlg) Type() protoreflect.EnumType {
	return &file_ReleaseMetadata_proto_enumTypes[3]
}

func (x ReleaseMetadata_DigestAlg) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ReleaseMetadata_DigestAlg.Descriptor instead.
func (ReleaseMetadata_DigestAlg) EnumDescriptor() ([]byte, []int) {
	return file_ReleaseMetadata_proto_rawDescGZIP(), []int{0, 3}
}

type ReleaseMetadata struct {
	state           protoimpl.MessageState        `protogen:"open.v1"`
	SchemaVersion   ReleaseMetadata_SchemaVersion `protobuf:"varint,1,opt,name=schema_version,json=schemaVersion,proto3,enum=ReleaseMetadata_SchemaVersion" json:"schema_version,omitempty"`
	ReleaseCreation *timestamppb.Timestamp        `protobuf:"bytes,2,opt,name=release_creation,json=releaseCreation,proto3" json:"release_creation,omitempty"`
	ReleaseDigest   []byte                        `protobuf:"bytes,3,opt,name=release_digest,json=releaseDigest,proto3" json:"release_digest,omitempty"`
	Assets          []*ReleaseMetadata_Asset      `protobuf:"bytes,4,rep,name=assets,proto3" json:"assets,omitempty"`
	// darwin_init is (json mapped) configuration of guest VM once booted;
	//
	//	dictates cryptex image attachments, service configs, other settings
	DarwinInit    *structpb.Struct                   `protobuf:"bytes,5,opt,name=darwin_init,json=darwinInit,proto3" json:"darwin_init,omitempty"`
	Requirements  []*ReleaseMetadata_ToolRequirement `protobuf:"bytes,6,rep,name=requirements,proto3" json:"requirements,omitempty"`
	Application   *ReleaseMetadata_Application       `protobuf:"bytes,7,opt,name=application,proto3" json:"application,omitempty"`
	BuildVersion  string                             `protobuf:"bytes,8,opt,name=build_version,json=buildVersion,proto3" json:"build_version,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ReleaseMetadata) Reset() {
	*x = ReleaseMetadata{}
	mi := &file_ReleaseMetadata_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ReleaseMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReleaseMetadata) ProtoMessage() {}

func (x *ReleaseMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_ReleaseMetadata_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReleaseMetadata.ProtoReflect.Descriptor instead.
func (*ReleaseMetadata) Descriptor() ([]byte, []int) {
	return file_ReleaseMetadata_proto_rawDescGZIP(), []int{0}
}

func (x *ReleaseMetadata) GetSchemaVersion() ReleaseMetadata_SchemaVersion {
	if x != nil {
		return x.SchemaVersion
	}
	return ReleaseMetadata_SCHEMA_VERSION_UNSPECIFIED
}

func (x *ReleaseMetadata) GetReleaseCreation() *timestamppb.Timestamp {
	if x != nil {
		return x.ReleaseCreation
	}
	return nil
}

func (x *ReleaseMetadata) GetReleaseDigest() []byte {
	if x != nil {
		return x.ReleaseDigest
	}
	return nil
}

func (x *ReleaseMetadata) GetAssets() []*ReleaseMetadata_Asset {
	if x != nil {
		return x.Assets
	}
	return nil
}

func (x *ReleaseMetadata) GetDarwinInit() *structpb.Struct {
	if x != nil {
		return x.DarwinInit
	}
	return nil
}

func (x *ReleaseMetadata) GetRequirements() []*ReleaseMetadata_ToolRequirement {
	if x != nil {
		return x.Requirements
	}
	return nil
}

func (x *ReleaseMetadata) GetApplication() *ReleaseMetadata_Application {
	if x != nil {
		return x.Application
	}
	return nil
}

func (x *ReleaseMetadata) GetBuildVersion() string {
	if x != nil {
		return x.BuildVersion
	}
	return ""
}

type ReleaseMetadata_Digest struct {
	state         protoimpl.MessageState    `protogen:"open.v1"`
	DigestAlg     ReleaseMetadata_DigestAlg `protobuf:"varint,1,opt,name=digest_alg,json=digestAlg,proto3,enum=ReleaseMetadata_DigestAlg" json:"digest_alg,omitempty"`
	Value         []byte                    `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ReleaseMetadata_Digest) Reset() {
	*x = ReleaseMetadata_Digest{}
	mi := &file_ReleaseMetadata_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ReleaseMetadata_Digest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReleaseMetadata_Digest) ProtoMessage() {}

func (x *ReleaseMetadata_Digest) ProtoReflect() protoreflect.Message {
	mi := &file_ReleaseMetadata_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReleaseMetadata_Digest.ProtoReflect.Descriptor instead.
func (*ReleaseMetadata_Digest) Descriptor() ([]byte, []int) {
	return file_ReleaseMetadata_proto_rawDescGZIP(), []int{0, 0}
}

func (x *ReleaseMetadata_Digest) GetDigestAlg() ReleaseMetadata_DigestAlg {
	if x != nil {
		return x.DigestAlg
	}
	return ReleaseMetadata_DIGEST_ALG_UNSPECIFIED
}

func (x *ReleaseMetadata_Digest) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

type ReleaseMetadata_Asset struct {
	state         protoimpl.MessageState    `protogen:"open.v1"`
	Type          ReleaseMetadata_AssetType `protobuf:"varint,1,opt,name=type,proto3,enum=ReleaseMetadata_AssetType" json:"type,omitempty"`
	Url           string                    `protobuf:"bytes,2,opt,name=url,proto3" json:"url,omitempty"`       // CDN path
	Digest        *ReleaseMetadata_Digest   `protobuf:"bytes,3,opt,name=digest,proto3" json:"digest,omitempty"` // over raw artifact (in url)
	Variant       string                    `protobuf:"bytes,4,opt,name=variant,proto3" json:"variant,omitempty"`
	Ticket        []byte                    `protobuf:"bytes,5,opt,name=ticket,proto3,oneof" json:"ticket,omitempty"` // matches ticket in leaf node release info
	FileType      ReleaseMetadata_FileType  `protobuf:"varint,6,opt,name=file_type,json=fileType,proto3,enum=ReleaseMetadata_FileType" json:"file_type,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ReleaseMetadata_Asset) Reset() {
	*x = ReleaseMetadata_Asset{}
	mi := &file_ReleaseMetadata_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ReleaseMetadata_Asset) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReleaseMetadata_Asset) ProtoMessage() {}

func (x *ReleaseMetadata_Asset) ProtoReflect() protoreflect.Message {
	mi := &file_ReleaseMetadata_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReleaseMetadata_Asset.ProtoReflect.Descriptor instead.
func (*ReleaseMetadata_Asset) Descriptor() ([]byte, []int) {
	return file_ReleaseMetadata_proto_rawDescGZIP(), []int{0, 1}
}

func (x *ReleaseMetadata_Asset) GetType() ReleaseMetadata_AssetType {
	if x != nil {
		return x.Type
	}
	return ReleaseMetadata_ASSET_TYPE_UNSPECIFIED
}

func (x *ReleaseMetadata_Asset) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *ReleaseMetadata_Asset) GetDigest() *ReleaseMetadata_Digest {
	if x != nil {
		return x.Digest
	}
	return nil
}

func (x *ReleaseMetadata_Asset) GetVariant() string {
	if x != nil {
		return x.Variant
	}
	return ""
}

func (x *ReleaseMetadata_Asset) GetTicket() []byte {
	if x != nil {
		return x.Ticket
	}
	return nil
}

func (x *ReleaseMetadata_Asset) GetFileType() ReleaseMetadata_FileType {
	if x != nil {
		return x.FileType
	}
	return ReleaseMetadata_FILE_TYPE_UNSPECIFIED
}

type ReleaseMetadata_ToolRequirement struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Feature       string                 `protobuf:"bytes,1,opt,name=feature,proto3" json:"feature,omitempty"`
	Availability  string                 `protobuf:"bytes,2,opt,name=availability,proto3" json:"availability,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ReleaseMetadata_ToolRequirement) Reset() {
	*x = ReleaseMetadata_ToolRequirement{}
	mi := &file_ReleaseMetadata_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ReleaseMetadata_ToolRequirement) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReleaseMetadata_ToolRequirement) ProtoMessage() {}

func (x *ReleaseMetadata_ToolRequirement) ProtoReflect() protoreflect.Message {
	mi := &file_ReleaseMetadata_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReleaseMetadata_ToolRequirement.ProtoReflect.Descriptor instead.
func (*ReleaseMetadata_ToolRequirement) Descriptor() ([]byte, []int) {
	return file_ReleaseMetadata_proto_rawDescGZIP(), []int{0, 2}
}

func (x *ReleaseMetadata_ToolRequirement) GetFeature() string {
	if x != nil {
		return x.Feature
	}
	return ""
}

func (x *ReleaseMetadata_ToolRequirement) GetAvailability() string {
	if x != nil {
		return x.Availability
	}
	return ""
}

type ReleaseMetadata_Application struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ReleaseMetadata_Application) Reset() {
	*x = ReleaseMetadata_Application{}
	mi := &file_ReleaseMetadata_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ReleaseMetadata_Application) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReleaseMetadata_Application) ProtoMessage() {}

func (x *ReleaseMetadata_Application) ProtoReflect() protoreflect.Message {
	mi := &file_ReleaseMetadata_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReleaseMetadata_Application.ProtoReflect.Descriptor instead.
func (*ReleaseMetadata_Application) Descriptor() ([]byte, []int) {
	return file_ReleaseMetadata_proto_rawDescGZIP(), []int{0, 3}
}

func (x *ReleaseMetadata_Application) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_ReleaseMetadata_proto protoreflect.FileDescriptor

const file_ReleaseMetadata_proto_rawDesc = "" +
	"\n" +
	"\x15ReleaseMetadata.proto\x1a\x1cgoogle/protobuf/struct.proto\x1a\x1fgoogle/protobuf/timestamp.proto\"\xce\n" +
	"\n" +
	"\x0fReleaseMetadata\x12E\n" +
	"\x0eschema_version\x18\x01 \x01(\x0e2\x1e.ReleaseMetadata.SchemaVersionR\rschemaVersion\x12E\n" +
	"\x10release_creation\x18\x02 \x01(\v2\x1a.google.protobuf.TimestampR\x0freleaseCreation\x12%\n" +
	"\x0erelease_digest\x18\x03 \x01(\fR\rreleaseDigest\x12.\n" +
	"\x06assets\x18\x04 \x03(\v2\x16.ReleaseMetadata.AssetR\x06assets\x128\n" +
	"\vdarwin_init\x18\x05 \x01(\v2\x17.google.protobuf.StructR\n" +
	"darwinInit\x12D\n" +
	"\frequirements\x18\x06 \x03(\v2 .ReleaseMetadata.ToolRequirementR\frequirements\x12>\n" +
	"\vapplication\x18\a \x01(\v2\x1c.ReleaseMetadata.ApplicationR\vapplication\x12#\n" +
	"\rbuild_version\x18\b \x01(\tR\fbuildVersion\x1aY\n" +
	"\x06Digest\x129\n" +
	"\n" +
	"digest_alg\x18\x01 \x01(\x0e2\x1a.ReleaseMetadata.DigestAlgR\tdigestAlg\x12\x14\n" +
	"\x05value\x18\x02 \x01(\fR\x05value\x1a\xf4\x01\n" +
	"\x05Asset\x12.\n" +
	"\x04type\x18\x01 \x01(\x0e2\x1a.ReleaseMetadata.AssetTypeR\x04type\x12\x10\n" +
	"\x03url\x18\x02 \x01(\tR\x03url\x12/\n" +
	"\x06digest\x18\x03 \x01(\v2\x17.ReleaseMetadata.DigestR\x06digest\x12\x18\n" +
	"\avariant\x18\x04 \x01(\tR\avariant\x12\x1b\n" +
	"\x06ticket\x18\x05 \x01(\fH\x00R\x06ticket\x88\x01\x01\x126\n" +
	"\tfile_type\x18\x06 \x01(\x0e2\x19.ReleaseMetadata.FileTypeR\bfileTypeB\t\n" +
	"\a_ticket\x1aO\n" +
	"\x0fToolRequirement\x12\x18\n" +
	"\afeature\x18\x01 \x01(\tR\afeature\x12\"\n" +
	"\favailability\x18\x02 \x01(\tR\favailability\x1a!\n" +
	"\vApplication\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\"F\n" +
	"\rSchemaVersion\x12\x1e\n" +
	"\x1aSCHEMA_VERSION_UNSPECIFIED\x10\x00\x12\x15\n" +
	"\x11SCHEMA_VERSION_V1\x10\x01\"\x9b\x01\n" +
	"\tAssetType\x12\x1a\n" +
	"\x16ASSET_TYPE_UNSPECIFIED\x10\x00\x12\x11\n" +
	"\rASSET_TYPE_OS\x10\x01\x12\x12\n" +
	"\x0eASSET_TYPE_PCS\x10\x02\x12\x14\n" +
	"\x10ASSET_TYPE_MODEL\x10\x03\x12\x19\n" +
	"\x15ASSET_TYPE_HOST_TOOLS\x10\x04\x12\x1a\n" +
	"\x16ASSET_TYPE_DEBUG_SHELL\x10\x05\"n\n" +
	"\bFileType\x12\x19\n" +
	"\x15FILE_TYPE_UNSPECIFIED\x10\x00\x12\x12\n" +
	"\x0eFILE_TYPE_IPSW\x10\x01\x12\x17\n" +
	"\x13FILE_TYPE_DISKIMAGE\x10\x02\x12\x1a\n" +
	"\x16FILE_TYPE_APPLEARCHIVE\x10\x03\"U\n" +
	"\tDigestAlg\x12\x1a\n" +
	"\x16DIGEST_ALG_UNSPECIFIED\x10\x00\x12\x15\n" +
	"\x11DIGEST_ALG_SHA256\x10\x01\x12\x15\n" +
	"\x11DIGEST_ALG_SHA384\x10\x02B8Z.github.com/blacktop/ipsw/internal/download/pcc\xba\x02\x05TxPB_b\x06proto3"

var (
	file_ReleaseMetadata_proto_rawDescOnce sync.Once
	file_ReleaseMetadata_proto_rawDescData []byte
)

func file_ReleaseMetadata_proto_rawDescGZIP() []byte {
	file_ReleaseMetadata_proto_rawDescOnce.Do(func() {
		file_ReleaseMetadata_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_ReleaseMetadata_proto_rawDesc), len(file_ReleaseMetadata_proto_rawDesc)))
	})
	return file_ReleaseMetadata_proto_rawDescData
}

var file_ReleaseMetadata_proto_enumTypes = make([]protoimpl.EnumInfo, 4)
var file_ReleaseMetadata_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_ReleaseMetadata_proto_goTypes = []any{
	(ReleaseMetadata_SchemaVersion)(0),      // 0: ReleaseMetadata.SchemaVersion
	(ReleaseMetadata_AssetType)(0),          // 1: ReleaseMetadata.AssetType
	(ReleaseMetadata_FileType)(0),           // 2: ReleaseMetadata.FileType
	(ReleaseMetadata_DigestAlg)(0),          // 3: ReleaseMetadata.DigestAlg
	(*ReleaseMetadata)(nil),                 // 4: ReleaseMetadata
	(*ReleaseMetadata_Digest)(nil),          // 5: ReleaseMetadata.Digest
	(*ReleaseMetadata_Asset)(nil),           // 6: ReleaseMetadata.Asset
	(*ReleaseMetadata_ToolRequirement)(nil), // 7: ReleaseMetadata.ToolRequirement
	(*ReleaseMetadata_Application)(nil),     // 8: ReleaseMetadata.Application
	(*timestamppb.Timestamp)(nil),           // 9: google.protobuf.Timestamp
	(*structpb.Struct)(nil),                 // 10: google.protobuf.Struct
}
var file_ReleaseMetadata_proto_depIdxs = []int32{
	0,  // 0: ReleaseMetadata.schema_version:type_name -> ReleaseMetadata.SchemaVersion
	9,  // 1: ReleaseMetadata.release_creation:type_name -> google.protobuf.Timestamp
	6,  // 2: ReleaseMetadata.assets:type_name -> ReleaseMetadata.Asset
	10, // 3: ReleaseMetadata.darwin_init:type_name -> google.protobuf.Struct
	7,  // 4: ReleaseMetadata.requirements:type_name -> ReleaseMetadata.ToolRequirement
	8,  // 5: ReleaseMetadata.application:type_name -> ReleaseMetadata.Application
	3,  // 6: ReleaseMetadata.Digest.digest_alg:type_name -> ReleaseMetadata.DigestAlg
	1,  // 7: ReleaseMetadata.Asset.type:type_name -> ReleaseMetadata.AssetType
	5,  // 8: ReleaseMetadata.Asset.digest:type_name -> ReleaseMetadata.Digest
	2,  // 9: ReleaseMetadata.Asset.file_type:type_name -> ReleaseMetadata.FileType
	10, // [10:10] is the sub-list for method output_type
	10, // [10:10] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_ReleaseMetadata_proto_init() }
func file_ReleaseMetadata_proto_init() {
	if File_ReleaseMetadata_proto != nil {
		return
	}
	file_ReleaseMetadata_proto_msgTypes[2].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeFor[x]().PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_ReleaseMetadata_proto_rawDesc), len(file_ReleaseMetadata_proto_rawDesc)),
			NumEnums:      4,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ReleaseMetadata_proto_goTypes,
		DependencyIndexes: file_ReleaseMetadata_proto_depIdxs,
		EnumInfos:         file_ReleaseMetadata_proto_enumTypes,
		MessageInfos:      file_ReleaseMetadata_proto_msgTypes,
	}.Build()
	File_ReleaseMetadata_proto = out.File
	file_ReleaseMetadata_proto_goTypes = nil
	file_ReleaseMetadata_proto_depIdxs = nil
}
