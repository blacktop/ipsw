package pcc

import (
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Protobuf protocol protocol version.
// Later versions must have larger ordinal numbers.  Device clients require number in enum name to match ordinal number.
type ProtocolVersion int32

const (
	ProtocolVersion_UNKNOWN_VERSION ProtocolVersion = 0
	// V1 used in early builds, deprecated
	ProtocolVersion_V1 ProtocolVersion = 1
	// V2 introduced in 1530 (iOS 15.2). Adds account key, converts map leaves to TLS presentation language, changes some VRFs to SHA256 hashes
	ProtocolVersion_V2 ProtocolVersion = 2
	// V3 (was 2_1) introduced in 1540 (iOS 15.3). Same as V2 but clients can handle opt-in SMTs in query responses
	ProtocolVersion_V3 ProtocolVersion = 3
	// Future version used for testing
	ProtocolVersion_FUTURE ProtocolVersion = 999999999
)

// Enum value maps for ProtocolVersion.
var (
	ProtocolVersion_name = map[int32]string{
		0:         "UNKNOWN_VERSION",
		1:         "V1",
		2:         "V2",
		3:         "V3",
		999999999: "FUTURE",
	}
	ProtocolVersion_value = map[string]int32{
		"UNKNOWN_VERSION": 0,
		"V1":              1,
		"V2":              2,
		"V3":              3,
		"FUTURE":          999999999,
	}
)

func (x ProtocolVersion) Enum() *ProtocolVersion {
	p := new(ProtocolVersion)
	*p = x
	return p
}

func (x ProtocolVersion) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProtocolVersion) Descriptor() protoreflect.EnumDescriptor {
	return file_Transparency_proto_enumTypes[0].Descriptor()
}

func (ProtocolVersion) Type() protoreflect.EnumType {
	return &file_Transparency_proto_enumTypes[0]
}

func (x ProtocolVersion) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ProtocolVersion.Descriptor instead.
func (ProtocolVersion) EnumDescriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{0}
}

// Application is the smallest grouping that can not be divided across multiple sets of PACL,
// PAM, and PAT. It defines a map-index namespace and is associated with a personality.
type Application int32

const (
	Application_UNKNOWN_APPLICATION            Application = 0
	Application_IDS_MESSAGING                  Application = 1
	Application_PRIVATE_CLOUD_COMPUTE          Application = 5
	Application_PRIVATE_CLOUD_COMPUTE_INTERNAL Application = 6
)

// Enum value maps for Application.
var (
	Application_name = map[int32]string{
		0: "UNKNOWN_APPLICATION",
		1: "IDS_MESSAGING",
		5: "PRIVATE_CLOUD_COMPUTE",
		6: "PRIVATE_CLOUD_COMPUTE_INTERNAL",
	}
	Application_value = map[string]int32{
		"UNKNOWN_APPLICATION":            0,
		"IDS_MESSAGING":                  1,
		"PRIVATE_CLOUD_COMPUTE":          5,
		"PRIVATE_CLOUD_COMPUTE_INTERNAL": 6,
	}
)

func (x Application) Enum() *Application {
	p := new(Application)
	*p = x
	return p
}

func (x Application) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Application) Descriptor() protoreflect.EnumDescriptor {
	return file_Transparency_proto_enumTypes[1].Descriptor()
}

func (Application) Type() protoreflect.EnumType {
	return &file_Transparency_proto_enumTypes[1]
}

func (x Application) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Application.Descriptor instead.
func (Application) EnumDescriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{1}
}

// API response status.
type Status int32

const (
	Status_UNKNOWN_STATUS Status = 0
	Status_OK             Status = 1
	// 2 - can reuse
	Status_MUTATION_PENDING Status = 3
	Status_ALREADY_EXISTS   Status = 4
	Status_INTERNAL_ERROR   Status = 5
	Status_INVALID_REQUEST  Status = 6
	Status_NOT_FOUND        Status = 7 // V2: removed TOO_MANY_VRF_REQUESTS = 8; because queries no longer need to request VRF witnesses for deviceId and clientData
)

// Enum value maps for Status.
var (
	Status_name = map[int32]string{
		0: "UNKNOWN_STATUS",
		1: "OK",
		3: "MUTATION_PENDING",
		4: "ALREADY_EXISTS",
		5: "INTERNAL_ERROR",
		6: "INVALID_REQUEST",
		7: "NOT_FOUND",
	}
	Status_value = map[string]int32{
		"UNKNOWN_STATUS":   0,
		"OK":               1,
		"MUTATION_PENDING": 3,
		"ALREADY_EXISTS":   4,
		"INTERNAL_ERROR":   5,
		"INVALID_REQUEST":  6,
		"NOT_FOUND":        7,
	}
)

func (x Status) Enum() *Status {
	p := new(Status)
	*p = x
	return p
}

func (x Status) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Status) Descriptor() protoreflect.EnumDescriptor {
	return file_Transparency_proto_enumTypes[2].Descriptor()
}

func (Status) Type() protoreflect.EnumType {
	return &file_Transparency_proto_enumTypes[2]
}

func (x Status) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Status.Descriptor instead.
func (Status) EnumDescriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{2}
}

type VRFType int32

const (
	VRFType_UNKNOWN_VRF VRFType = 0
	// 1, 2 - can reuse
	VRFType_ECVRF_ED25519_SHA512_Elligator2 VRFType = 3
)

// Enum value maps for VRFType.
var (
	VRFType_name = map[int32]string{
		0: "UNKNOWN_VRF",
		3: "ECVRF_ED25519_SHA512_Elligator2",
	}
	VRFType_value = map[string]int32{
		"UNKNOWN_VRF":                     0,
		"ECVRF_ED25519_SHA512_Elligator2": 3,
	}
)

func (x VRFType) Enum() *VRFType {
	p := new(VRFType)
	*p = x
	return p
}

func (x VRFType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (VRFType) Descriptor() protoreflect.EnumDescriptor {
	return file_Transparency_proto_enumTypes[3].Descriptor()
}

func (VRFType) Type() protoreflect.EnumType {
	return &file_Transparency_proto_enumTypes[3]
}

func (x VRFType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use VRFType.Descriptor instead.
func (VRFType) EnumDescriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{3}
}

type LogType int32

const (
	LogType_UNKNOWN_LOG                LogType = 0
	LogType_PER_APPLICATION_CHANGE_LOG LogType = 1
	LogType_PER_APPLICATION_TREE       LogType = 2
	LogType_TOP_LEVEL_TREE             LogType = 3
	LogType_CT_LOG                     LogType = 4
	LogType_AT_LOG                     LogType = 5
)

// Enum value maps for LogType.
var (
	LogType_name = map[int32]string{
		0: "UNKNOWN_LOG",
		1: "PER_APPLICATION_CHANGE_LOG",
		2: "PER_APPLICATION_TREE",
		3: "TOP_LEVEL_TREE",
		4: "CT_LOG",
		5: "AT_LOG",
	}
	LogType_value = map[string]int32{
		"UNKNOWN_LOG":                0,
		"PER_APPLICATION_CHANGE_LOG": 1,
		"PER_APPLICATION_TREE":       2,
		"TOP_LEVEL_TREE":             3,
		"CT_LOG":                     4,
		"AT_LOG":                     5,
	}
)

func (x LogType) Enum() *LogType {
	p := new(LogType)
	*p = x
	return p
}

func (x LogType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LogType) Descriptor() protoreflect.EnumDescriptor {
	return file_Transparency_proto_enumTypes[4].Descriptor()
}

func (LogType) Type() protoreflect.EnumType {
	return &file_Transparency_proto_enumTypes[4]
}

func (x LogType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LogType.Descriptor instead.
func (LogType) EnumDescriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{4}
}

type MapType int32

const (
	MapType_UNKNOWN_MAP        MapType = 0
	MapType_PER_APP_OBJECT_MAP MapType = 1
)

// Enum value maps for MapType.
var (
	MapType_name = map[int32]string{
		0: "UNKNOWN_MAP",
		1: "PER_APP_OBJECT_MAP",
	}
	MapType_value = map[string]int32{
		"UNKNOWN_MAP":        0,
		"PER_APP_OBJECT_MAP": 1,
	}
)

func (x MapType) Enum() *MapType {
	p := new(MapType)
	*p = x
	return p
}

func (x MapType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MapType) Descriptor() protoreflect.EnumDescriptor {
	return file_Transparency_proto_enumTypes[5].Descriptor()
}

func (MapType) Type() protoreflect.EnumType {
	return &file_Transparency_proto_enumTypes[5]
}

func (x MapType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MapType.Descriptor instead.
func (MapType) EnumDescriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{5}
}

type NodeType int32

const (
	NodeType_PACL_NODE       NodeType = 0 // Dependent on personality. for IDS this is a ChangeLogNode
	NodeType_PAT_NODE        NodeType = 1 // PerApplicationTreeNode
	NodeType_PAT_CONFIG_NODE NodeType = 2 // Only valid for node index 0. PerApplicationTreeConfigNode
	NodeType_TLT_NODE        NodeType = 3 // TopLevelTreeNode
	NodeType_TLT_CONFIG_NODE NodeType = 4 // Only valid for node index 0. TopLevelTreeConfigNode
	NodeType_LOG_CLOSED_NODE NodeType = 5 // Valid for PAT or TLT. LogClosedNode
	NodeType_CT_NODE         NodeType = 6 // Certificate transparency log node.
	NodeType_ATL_NODE        NodeType = 7 // Private Cloud Compute log node. Can be an attestation node or certificate node (ChangeLogNodeV2 with an ATLeafData struct).
)

// Enum value maps for NodeType.
var (
	NodeType_name = map[int32]string{
		0: "PACL_NODE",
		1: "PAT_NODE",
		2: "PAT_CONFIG_NODE",
		3: "TLT_NODE",
		4: "TLT_CONFIG_NODE",
		5: "LOG_CLOSED_NODE",
		6: "CT_NODE",
		7: "ATL_NODE",
	}
	NodeType_value = map[string]int32{
		"PACL_NODE":       0,
		"PAT_NODE":        1,
		"PAT_CONFIG_NODE": 2,
		"TLT_NODE":        3,
		"TLT_CONFIG_NODE": 4,
		"LOG_CLOSED_NODE": 5,
		"CT_NODE":         6,
		"ATL_NODE":        7,
	}
)

func (x NodeType) Enum() *NodeType {
	p := new(NodeType)
	*p = x
	return p
}

func (x NodeType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (NodeType) Descriptor() protoreflect.EnumDescriptor {
	return file_Transparency_proto_enumTypes[6].Descriptor()
}

func (NodeType) Type() protoreflect.EnumType {
	return &file_Transparency_proto_enumTypes[6]
}

func (x NodeType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use NodeType.Descriptor instead.
func (NodeType) EnumDescriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{6}
}

type Signature_SignatureAlgorithm int32

const (
	Signature_UNKNOWN      Signature_SignatureAlgorithm = 0
	Signature_ECDSA_SHA256 Signature_SignatureAlgorithm = 1
)

// Enum value maps for Signature_SignatureAlgorithm.
var (
	Signature_SignatureAlgorithm_name = map[int32]string{
		0: "UNKNOWN",
		1: "ECDSA_SHA256",
	}
	Signature_SignatureAlgorithm_value = map[string]int32{
		"UNKNOWN":      0,
		"ECDSA_SHA256": 1,
	}
)

func (x Signature_SignatureAlgorithm) Enum() *Signature_SignatureAlgorithm {
	p := new(Signature_SignatureAlgorithm)
	*p = x
	return p
}

func (x Signature_SignatureAlgorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Signature_SignatureAlgorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_Transparency_proto_enumTypes[7].Descriptor()
}

func (Signature_SignatureAlgorithm) Type() protoreflect.EnumType {
	return &file_Transparency_proto_enumTypes[7]
}

func (x Signature_SignatureAlgorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Signature_SignatureAlgorithm.Descriptor instead.
func (Signature_SignatureAlgorithm) EnumDescriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{2, 0}
}

type VRFWitness struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Type          VRFType                `protobuf:"varint,1,opt,name=type,proto3,enum=VRFType" json:"type,omitempty"`
	Output        []byte                 `protobuf:"bytes,2,opt,name=output,proto3" json:"output,omitempty"`
	Proof         []byte                 `protobuf:"bytes,3,opt,name=proof,proto3" json:"proof,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *VRFWitness) Reset() {
	*x = VRFWitness{}
	mi := &file_Transparency_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VRFWitness) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VRFWitness) ProtoMessage() {}

func (x *VRFWitness) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VRFWitness.ProtoReflect.Descriptor instead.
func (*VRFWitness) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{0}
}

func (x *VRFWitness) GetType() VRFType {
	if x != nil {
		return x.Type
	}
	return VRFType_UNKNOWN_VRF
}

func (x *VRFWitness) GetOutput() []byte {
	if x != nil {
		return x.Output
	}
	return nil
}

func (x *VRFWitness) GetProof() []byte {
	if x != nil {
		return x.Proof
	}
	return nil
}

type VRFPublicKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	VrfKey        []byte                 `protobuf:"bytes,1,opt,name=vrfKey,proto3" json:"vrfKey,omitempty"`
	Type          VRFType                `protobuf:"varint,2,opt,name=type,proto3,enum=VRFType" json:"type,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *VRFPublicKey) Reset() {
	*x = VRFPublicKey{}
	mi := &file_Transparency_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VRFPublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VRFPublicKey) ProtoMessage() {}

func (x *VRFPublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VRFPublicKey.ProtoReflect.Descriptor instead.
func (*VRFPublicKey) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{1}
}

func (x *VRFPublicKey) GetVrfKey() []byte {
	if x != nil {
		return x.VrfKey
	}
	return nil
}

func (x *VRFPublicKey) GetType() VRFType {
	if x != nil {
		return x.Type
	}
	return VRFType_UNKNOWN_VRF
}

type Signature struct {
	state     protoimpl.MessageState `protogen:"open.v1"`
	Signature []byte                 `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	// This is a hash of the DER encoded public key used to verify the signature.
	// It is used to identify the correct key from multiple signing keys.
	SigningKeySPKIHash []byte                       `protobuf:"bytes,2,opt,name=signingKeySPKIHash,proto3" json:"signingKeySPKIHash,omitempty"`
	Algorithm          Signature_SignatureAlgorithm `protobuf:"varint,3,opt,name=algorithm,proto3,enum=Signature_SignatureAlgorithm" json:"algorithm,omitempty"`
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *Signature) Reset() {
	*x = Signature{}
	mi := &file_Transparency_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Signature) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Signature) ProtoMessage() {}

func (x *Signature) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Signature.ProtoReflect.Descriptor instead.
func (*Signature) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{2}
}

func (x *Signature) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *Signature) GetSigningKeySPKIHash() []byte {
	if x != nil {
		return x.SigningKeySPKIHash
	}
	return nil
}

func (x *Signature) GetAlgorithm() Signature_SignatureAlgorithm {
	if x != nil {
		return x.Algorithm
	}
	return Signature_UNKNOWN
}

type SignedObject struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// parse as a LogHead, MapHead, Mutation, or whatever is appropriate given context
	Object        []byte     `protobuf:"bytes,1,opt,name=object,proto3" json:"object,omitempty"`
	Signature     *Signature `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SignedObject) Reset() {
	*x = SignedObject{}
	mi := &file_Transparency_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SignedObject) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignedObject) ProtoMessage() {}

func (x *SignedObject) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignedObject.ProtoReflect.Descriptor instead.
func (*SignedObject) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{3}
}

func (x *SignedObject) GetObject() []byte {
	if x != nil {
		return x.Object
	}
	return nil
}

func (x *SignedObject) GetSignature() *Signature {
	if x != nil {
		return x.Signature
	}
	return nil
}

type LogHead struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	LogBeginningMs uint64                 `protobuf:"varint,1,opt,name=logBeginningMs,proto3" json:"logBeginningMs,omitempty"` // Used to identify the new tree when the tree has been reset
	LogSize        uint64                 `protobuf:"varint,2,opt,name=logSize,proto3" json:"logSize,omitempty"`
	LogHeadHash    []byte                 `protobuf:"bytes,3,opt,name=logHeadHash,proto3" json:"logHeadHash,omitempty"`
	Revision       uint64                 `protobuf:"varint,4,opt,name=revision,proto3" json:"revision,omitempty"`
	LogType        LogType                `protobuf:"varint,5,opt,name=logType,proto3,enum=LogType" json:"logType,omitempty"`
	Application    Application            `protobuf:"varint,6,opt,name=application,proto3,enum=Application" json:"application,omitempty"` // omitted for TLT
	TreeId         uint64                 `protobuf:"varint,7,opt,name=treeId,proto3" json:"treeId,omitempty"`
	TimestampMs    uint64                 `protobuf:"varint,8,opt,name=timestampMs,proto3" json:"timestampMs,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *LogHead) Reset() {
	*x = LogHead{}
	mi := &file_Transparency_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogHead) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogHead) ProtoMessage() {}

func (x *LogHead) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogHead.ProtoReflect.Descriptor instead.
func (*LogHead) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{4}
}

func (x *LogHead) GetLogBeginningMs() uint64 {
	if x != nil {
		return x.LogBeginningMs
	}
	return 0
}

func (x *LogHead) GetLogSize() uint64 {
	if x != nil {
		return x.LogSize
	}
	return 0
}

func (x *LogHead) GetLogHeadHash() []byte {
	if x != nil {
		return x.LogHeadHash
	}
	return nil
}

func (x *LogHead) GetRevision() uint64 {
	if x != nil {
		return x.Revision
	}
	return 0
}

func (x *LogHead) GetLogType() LogType {
	if x != nil {
		return x.LogType
	}
	return LogType_UNKNOWN_LOG
}

func (x *LogHead) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *LogHead) GetTreeId() uint64 {
	if x != nil {
		return x.TreeId
	}
	return 0
}

func (x *LogHead) GetTimestampMs() uint64 {
	if x != nil {
		return x.TimestampMs
	}
	return 0
}

// The value and inclusion proof of a log leaf.
type LogEntry struct {
	state                     protoimpl.MessageState `protogen:"open.v1"`
	LogType                   LogType                `protobuf:"varint,1,opt,name=logType,proto3,enum=LogType" json:"logType,omitempty"`
	Slh                       *SignedObject          `protobuf:"bytes,2,opt,name=slh,proto3" json:"slh,omitempty"`
	HashesOfPeersInPathToRoot [][]byte               `protobuf:"bytes,3,rep,name=hashesOfPeersInPathToRoot,proto3" json:"hashesOfPeersInPathToRoot,omitempty"` // ordered with leaf at position 0, root-1 at end
	// Parse based on nodeType
	NodeBytes     []byte   `protobuf:"bytes,4,opt,name=nodeBytes,proto3" json:"nodeBytes,omitempty"`
	NodePosition  uint64   `protobuf:"varint,5,opt,name=nodePosition,proto3" json:"nodePosition,omitempty"` // in range [0, slh.logSize)
	NodeType      NodeType `protobuf:"varint,6,opt,name=nodeType,proto3,enum=NodeType" json:"nodeType,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogEntry) Reset() {
	*x = LogEntry{}
	mi := &file_Transparency_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogEntry) ProtoMessage() {}

func (x *LogEntry) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogEntry.ProtoReflect.Descriptor instead.
func (*LogEntry) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{5}
}

func (x *LogEntry) GetLogType() LogType {
	if x != nil {
		return x.LogType
	}
	return LogType_UNKNOWN_LOG
}

func (x *LogEntry) GetSlh() *SignedObject {
	if x != nil {
		return x.Slh
	}
	return nil
}

func (x *LogEntry) GetHashesOfPeersInPathToRoot() [][]byte {
	if x != nil {
		return x.HashesOfPeersInPathToRoot
	}
	return nil
}

func (x *LogEntry) GetNodeBytes() []byte {
	if x != nil {
		return x.NodeBytes
	}
	return nil
}

func (x *LogEntry) GetNodePosition() uint64 {
	if x != nil {
		return x.NodePosition
	}
	return 0
}

func (x *LogEntry) GetNodeType() NodeType {
	if x != nil {
		return x.NodeType
	}
	return NodeType_PACL_NODE
}

type MapHead struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	LogBeginningMs uint64                 `protobuf:"varint,1,opt,name=logBeginningMs,proto3" json:"logBeginningMs,omitempty"`
	MapHeadHash    []byte                 `protobuf:"bytes,2,opt,name=mapHeadHash,proto3" json:"mapHeadHash,omitempty"`
	Application    Application            `protobuf:"varint,3,opt,name=application,proto3,enum=Application" json:"application,omitempty"`
	ChangeLogHead  *LogHead               `protobuf:"bytes,4,opt,name=changeLogHead,proto3" json:"changeLogHead,omitempty"`
	Revision       uint64                 `protobuf:"varint,5,opt,name=revision,proto3" json:"revision,omitempty"`
	MapType        MapType                `protobuf:"varint,6,opt,name=mapType,proto3,enum=MapType" json:"mapType,omitempty"`
	TreeId         uint64                 `protobuf:"varint,7,opt,name=treeId,proto3" json:"treeId,omitempty"`
	TimestampMs    uint64                 `protobuf:"varint,8,opt,name=timestampMs,proto3" json:"timestampMs,omitempty"`
	Populating     bool                   `protobuf:"varint,9,opt,name=populating,proto3" json:"populating,omitempty"` // if true, indicates this map may not yet contain a full set of data
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *MapHead) Reset() {
	*x = MapHead{}
	mi := &file_Transparency_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MapHead) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MapHead) ProtoMessage() {}

func (x *MapHead) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MapHead.ProtoReflect.Descriptor instead.
func (*MapHead) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{6}
}

func (x *MapHead) GetLogBeginningMs() uint64 {
	if x != nil {
		return x.LogBeginningMs
	}
	return 0
}

func (x *MapHead) GetMapHeadHash() []byte {
	if x != nil {
		return x.MapHeadHash
	}
	return nil
}

func (x *MapHead) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *MapHead) GetChangeLogHead() *LogHead {
	if x != nil {
		return x.ChangeLogHead
	}
	return nil
}

func (x *MapHead) GetRevision() uint64 {
	if x != nil {
		return x.Revision
	}
	return 0
}

func (x *MapHead) GetMapType() MapType {
	if x != nil {
		return x.MapType
	}
	return MapType_UNKNOWN_MAP
}

func (x *MapHead) GetTreeId() uint64 {
	if x != nil {
		return x.TreeId
	}
	return 0
}

func (x *MapHead) GetTimestampMs() uint64 {
	if x != nil {
		return x.TimestampMs
	}
	return 0
}

func (x *MapHead) GetPopulating() bool {
	if x != nil {
		return x.Populating
	}
	return false
}

// Value and inclusion proof of a map leaf.
type MapEntry struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	Smh   *SignedObject          `protobuf:"bytes,1,opt,name=smh,proto3" json:"smh,omitempty"`
	// When computing the hash chain, prepend each non-leaf hash with 0x01
	// Empty peers may be omitted since they can be calculated by the client
	HashesOfPeersInPathToRoot [][]byte `protobuf:"bytes,2,rep,name=hashesOfPeersInPathToRoot,proto3" json:"hashesOfPeersInPathToRoot,omitempty"` // ordered with leaf at position 0, root-1 at end
	// When computing the hash chain, Prepend the hash of these bytes with 0x00
	MapLeaf       []byte `protobuf:"bytes,3,opt,name=mapLeaf,proto3" json:"mapLeaf,omitempty"` // For IDS, Parse as MapLeaf
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MapEntry) Reset() {
	*x = MapEntry{}
	mi := &file_Transparency_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MapEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MapEntry) ProtoMessage() {}

func (x *MapEntry) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MapEntry.ProtoReflect.Descriptor instead.
func (*MapEntry) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{7}
}

func (x *MapEntry) GetSmh() *SignedObject {
	if x != nil {
		return x.Smh
	}
	return nil
}

func (x *MapEntry) GetHashesOfPeersInPathToRoot() [][]byte {
	if x != nil {
		return x.HashesOfPeersInPathToRoot
	}
	return nil
}

func (x *MapEntry) GetMapLeaf() []byte {
	if x != nil {
		return x.MapLeaf
	}
	return nil
}

type InclusionProof struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// V2: removed uriVRFOutput = 1
	MapEntry                *MapEntry `protobuf:"bytes,2,opt,name=mapEntry,proto3" json:"mapEntry,omitempty"`
	Index                   []byte    `protobuf:"bytes,3,opt,name=index,proto3" json:"index,omitempty"`                                     // Added for V2, equals SHA256(uriVrfOutput)
	PerApplicationTreeEntry *LogEntry `protobuf:"bytes,4,opt,name=perApplicationTreeEntry,proto3" json:"perApplicationTreeEntry,omitempty"` // optional
	TopLevelTreeEntry       *LogEntry `protobuf:"bytes,5,opt,name=topLevelTreeEntry,proto3" json:"topLevelTreeEntry,omitempty"`             // optional
	unknownFields           protoimpl.UnknownFields
	sizeCache               protoimpl.SizeCache
}

func (x *InclusionProof) Reset() {
	*x = InclusionProof{}
	mi := &file_Transparency_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InclusionProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InclusionProof) ProtoMessage() {}

func (x *InclusionProof) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InclusionProof.ProtoReflect.Descriptor instead.
func (*InclusionProof) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{8}
}

func (x *InclusionProof) GetMapEntry() *MapEntry {
	if x != nil {
		return x.MapEntry
	}
	return nil
}

func (x *InclusionProof) GetIndex() []byte {
	if x != nil {
		return x.Index
	}
	return nil
}

func (x *InclusionProof) GetPerApplicationTreeEntry() *LogEntry {
	if x != nil {
		return x.PerApplicationTreeEntry
	}
	return nil
}

func (x *InclusionProof) GetTopLevelTreeEntry() *LogEntry {
	if x != nil {
		return x.TopLevelTreeEntry
	}
	return nil
}

// Inclusion proof of a PAT node
type PatInclusionProof struct {
	state                   protoimpl.MessageState `protogen:"open.v1"`
	PerApplicationTreeEntry *LogEntry              `protobuf:"bytes,1,opt,name=perApplicationTreeEntry,proto3" json:"perApplicationTreeEntry,omitempty"`
	TopLevelTreeEntry       *LogEntry              `protobuf:"bytes,2,opt,name=topLevelTreeEntry,proto3" json:"topLevelTreeEntry,omitempty"`
	unknownFields           protoimpl.UnknownFields
	sizeCache               protoimpl.SizeCache
}

func (x *PatInclusionProof) Reset() {
	*x = PatInclusionProof{}
	mi := &file_Transparency_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PatInclusionProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PatInclusionProof) ProtoMessage() {}

func (x *PatInclusionProof) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PatInclusionProof.ProtoReflect.Descriptor instead.
func (*PatInclusionProof) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{9}
}

func (x *PatInclusionProof) GetPerApplicationTreeEntry() *LogEntry {
	if x != nil {
		return x.PerApplicationTreeEntry
	}
	return nil
}

func (x *PatInclusionProof) GetTopLevelTreeEntry() *LogEntry {
	if x != nil {
		return x.TopLevelTreeEntry
	}
	return nil
}

type ChangeLogNodeV2 struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Parse as appropriate for app, for IDS this is a TLS-encoded IdsMutation
	Mutation      []byte `protobuf:"bytes,1,opt,name=mutation,proto3" json:"mutation,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ChangeLogNodeV2) Reset() {
	*x = ChangeLogNodeV2{}
	mi := &file_Transparency_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ChangeLogNodeV2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChangeLogNodeV2) ProtoMessage() {}

func (x *ChangeLogNodeV2) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChangeLogNodeV2.ProtoReflect.Descriptor instead.
func (*ChangeLogNodeV2) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{10}
}

func (x *ChangeLogNodeV2) GetMutation() []byte {
	if x != nil {
		return x.Mutation
	}
	return nil
}

// node ID = SHA256( PAM tree ID || PAM revision )
type PerApplicationTreeNode struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// 1 - can reuse
	// predecessorHead contains either MapHead or LogHead depending on the application
	PredecessorHead *SignedObject `protobuf:"bytes,2,opt,name=predecessorHead,proto3" json:"predecessorHead,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *PerApplicationTreeNode) Reset() {
	*x = PerApplicationTreeNode{}
	mi := &file_Transparency_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PerApplicationTreeNode) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PerApplicationTreeNode) ProtoMessage() {}

func (x *PerApplicationTreeNode) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PerApplicationTreeNode.ProtoReflect.Descriptor instead.
func (*PerApplicationTreeNode) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{11}
}

func (x *PerApplicationTreeNode) GetPredecessorHead() *SignedObject {
	if x != nil {
		return x.PredecessorHead
	}
	return nil
}

type TopLevelTreeNode struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PatHead       *SignedObject          `protobuf:"bytes,1,opt,name=patHead,proto3" json:"patHead,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TopLevelTreeNode) Reset() {
	*x = TopLevelTreeNode{}
	mi := &file_Transparency_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TopLevelTreeNode) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TopLevelTreeNode) ProtoMessage() {}

func (x *TopLevelTreeNode) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TopLevelTreeNode.ProtoReflect.Descriptor instead.
func (*TopLevelTreeNode) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{12}
}

func (x *TopLevelTreeNode) GetPatHead() *SignedObject {
	if x != nil {
		return x.PatHead
	}
	return nil
}

// The first node (nodePosition 0) in a Per-Application Tree will have this value.
// V1: node ID = SHA256(VRF Public Key)
// V2: node ID = SHA256("Config node")
// Private cloud compute PAT config nodes will not include the VRF public key
type PerApplicationTreeConfigNode struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	VrfPublicKey   *VRFPublicKey          `protobuf:"bytes,1,opt,name=vrfPublicKey,proto3" json:"vrfPublicKey,omitempty"`
	PublicKeyBytes []byte                 `protobuf:"bytes,2,opt,name=publicKeyBytes,proto3" json:"publicKeyBytes,omitempty"` // public key for signing roots of all trees for this app, encoded in DER SPKI
	// first supported version for this tree, interpret not set as V1
	EarliestVersion ProtocolVersion `protobuf:"varint,3,opt,name=earliestVersion,proto3,enum=ProtocolVersion" json:"earliestVersion,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *PerApplicationTreeConfigNode) Reset() {
	*x = PerApplicationTreeConfigNode{}
	mi := &file_Transparency_proto_msgTypes[13]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PerApplicationTreeConfigNode) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PerApplicationTreeConfigNode) ProtoMessage() {}

func (x *PerApplicationTreeConfigNode) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[13]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PerApplicationTreeConfigNode.ProtoReflect.Descriptor instead.
func (*PerApplicationTreeConfigNode) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{13}
}

func (x *PerApplicationTreeConfigNode) GetVrfPublicKey() *VRFPublicKey {
	if x != nil {
		return x.VrfPublicKey
	}
	return nil
}

func (x *PerApplicationTreeConfigNode) GetPublicKeyBytes() []byte {
	if x != nil {
		return x.PublicKeyBytes
	}
	return nil
}

func (x *PerApplicationTreeConfigNode) GetEarliestVersion() ProtocolVersion {
	if x != nil {
		return x.EarliestVersion
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

// The first node (nodePosition 0) in a Top-level Tree will have this value.
// V1: node ID = SHA256(signing public key)
// V2: node ID = SHA256("Config node")
type TopLevelTreeConfigNode struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	PublicKeyBytes []byte                 `protobuf:"bytes,1,opt,name=publicKeyBytes,proto3" json:"publicKeyBytes,omitempty"` // public key for signing roots of the top-level tree, encoded in DER SPKI
	// first supported version for this tree, interpret not set as V1
	EarliestVersion ProtocolVersion `protobuf:"varint,3,opt,name=earliestVersion,proto3,enum=ProtocolVersion" json:"earliestVersion,omitempty"`
	TreeCounter     uint32          `protobuf:"varint,4,opt,name=treeCounter,proto3" json:"treeCounter,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *TopLevelTreeConfigNode) Reset() {
	*x = TopLevelTreeConfigNode{}
	mi := &file_Transparency_proto_msgTypes[14]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TopLevelTreeConfigNode) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TopLevelTreeConfigNode) ProtoMessage() {}

func (x *TopLevelTreeConfigNode) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[14]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TopLevelTreeConfigNode.ProtoReflect.Descriptor instead.
func (*TopLevelTreeConfigNode) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{14}
}

func (x *TopLevelTreeConfigNode) GetPublicKeyBytes() []byte {
	if x != nil {
		return x.PublicKeyBytes
	}
	return nil
}

func (x *TopLevelTreeConfigNode) GetEarliestVersion() ProtocolVersion {
	if x != nil {
		return x.EarliestVersion
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *TopLevelTreeConfigNode) GetTreeCounter() uint32 {
	if x != nil {
		return x.TreeCounter
	}
	return 0
}

// Indicates that this PAT or TLT is shut down (for PAT, the PACL and PAM that feed it are also shut down).
// Not necessarily the last PAT node. (PAT should contain no other nodes newer than this + MMD?)
// node ID = SHA256("Closed node")
type LogClosedNode struct {
	state       protoimpl.MessageState `protogen:"open.v1"`
	TimestampMs uint64                 `protobuf:"varint,1,opt,name=timestampMs,proto3" json:"timestampMs,omitempty"` // Any SMTs less than MMD before this may never merge
	// Earliest version that is supported by the new tree.
	EarliestVersionForNextTree ProtocolVersion `protobuf:"varint,3,opt,name=earliestVersionForNextTree,proto3,enum=ProtocolVersion" json:"earliestVersionForNextTree,omitempty"`
	unknownFields              protoimpl.UnknownFields
	sizeCache                  protoimpl.SizeCache
}

func (x *LogClosedNode) Reset() {
	*x = LogClosedNode{}
	mi := &file_Transparency_proto_msgTypes[15]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogClosedNode) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogClosedNode) ProtoMessage() {}

func (x *LogClosedNode) ProtoReflect() protoreflect.Message {
	mi := &file_Transparency_proto_msgTypes[15]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogClosedNode.ProtoReflect.Descriptor instead.
func (*LogClosedNode) Descriptor() ([]byte, []int) {
	return file_Transparency_proto_rawDescGZIP(), []int{15}
}

func (x *LogClosedNode) GetTimestampMs() uint64 {
	if x != nil {
		return x.TimestampMs
	}
	return 0
}

func (x *LogClosedNode) GetEarliestVersionForNextTree() ProtocolVersion {
	if x != nil {
		return x.EarliestVersionForNextTree
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

var File_Transparency_proto protoreflect.FileDescriptor

const file_Transparency_proto_rawDesc = "" +
	"\n" +
	"\x12Transparency.proto\"X\n" +
	"\n" +
	"VRFWitness\x12\x1c\n" +
	"\x04type\x18\x01 \x01(\x0e2\b.VRFTypeR\x04type\x12\x16\n" +
	"\x06output\x18\x02 \x01(\fR\x06output\x12\x14\n" +
	"\x05proof\x18\x03 \x01(\fR\x05proof\"D\n" +
	"\fVRFPublicKey\x12\x16\n" +
	"\x06vrfKey\x18\x01 \x01(\fR\x06vrfKey\x12\x1c\n" +
	"\x04type\x18\x02 \x01(\x0e2\b.VRFTypeR\x04type\"\xcb\x01\n" +
	"\tSignature\x12\x1c\n" +
	"\tsignature\x18\x01 \x01(\fR\tsignature\x12.\n" +
	"\x12signingKeySPKIHash\x18\x02 \x01(\fR\x12signingKeySPKIHash\x12;\n" +
	"\talgorithm\x18\x03 \x01(\x0e2\x1d.Signature.SignatureAlgorithmR\talgorithm\"3\n" +
	"\x12SignatureAlgorithm\x12\v\n" +
	"\aUNKNOWN\x10\x00\x12\x10\n" +
	"\fECDSA_SHA256\x10\x01\"P\n" +
	"\fSignedObject\x12\x16\n" +
	"\x06object\x18\x01 \x01(\fR\x06object\x12(\n" +
	"\tsignature\x18\x02 \x01(\v2\n" +
	".SignatureR\tsignature\"\x97\x02\n" +
	"\aLogHead\x12&\n" +
	"\x0elogBeginningMs\x18\x01 \x01(\x04R\x0elogBeginningMs\x12\x18\n" +
	"\alogSize\x18\x02 \x01(\x04R\alogSize\x12 \n" +
	"\vlogHeadHash\x18\x03 \x01(\fR\vlogHeadHash\x12\x1a\n" +
	"\brevision\x18\x04 \x01(\x04R\brevision\x12\"\n" +
	"\alogType\x18\x05 \x01(\x0e2\b.LogTypeR\alogType\x12.\n" +
	"\vapplication\x18\x06 \x01(\x0e2\f.ApplicationR\vapplication\x12\x16\n" +
	"\x06treeId\x18\a \x01(\x04R\x06treeId\x12 \n" +
	"\vtimestampMs\x18\b \x01(\x04R\vtimestampMs\"\xf6\x01\n" +
	"\bLogEntry\x12\"\n" +
	"\alogType\x18\x01 \x01(\x0e2\b.LogTypeR\alogType\x12\x1f\n" +
	"\x03slh\x18\x02 \x01(\v2\r.SignedObjectR\x03slh\x12<\n" +
	"\x19hashesOfPeersInPathToRoot\x18\x03 \x03(\fR\x19hashesOfPeersInPathToRoot\x12\x1c\n" +
	"\tnodeBytes\x18\x04 \x01(\fR\tnodeBytes\x12\"\n" +
	"\fnodePosition\x18\x05 \x01(\x04R\fnodePosition\x12%\n" +
	"\bnodeType\x18\x06 \x01(\x0e2\t.NodeTypeR\bnodeType\"\xcd\x02\n" +
	"\aMapHead\x12&\n" +
	"\x0elogBeginningMs\x18\x01 \x01(\x04R\x0elogBeginningMs\x12 \n" +
	"\vmapHeadHash\x18\x02 \x01(\fR\vmapHeadHash\x12.\n" +
	"\vapplication\x18\x03 \x01(\x0e2\f.ApplicationR\vapplication\x12.\n" +
	"\rchangeLogHead\x18\x04 \x01(\v2\b.LogHeadR\rchangeLogHead\x12\x1a\n" +
	"\brevision\x18\x05 \x01(\x04R\brevision\x12\"\n" +
	"\amapType\x18\x06 \x01(\x0e2\b.MapTypeR\amapType\x12\x16\n" +
	"\x06treeId\x18\a \x01(\x04R\x06treeId\x12 \n" +
	"\vtimestampMs\x18\b \x01(\x04R\vtimestampMs\x12\x1e\n" +
	"\n" +
	"populating\x18\t \x01(\bR\n" +
	"populating\"\x83\x01\n" +
	"\bMapEntry\x12\x1f\n" +
	"\x03smh\x18\x01 \x01(\v2\r.SignedObjectR\x03smh\x12<\n" +
	"\x19hashesOfPeersInPathToRoot\x18\x02 \x03(\fR\x19hashesOfPeersInPathToRoot\x12\x18\n" +
	"\amapLeaf\x18\x03 \x01(\fR\amapLeaf\"\xcb\x01\n" +
	"\x0eInclusionProof\x12%\n" +
	"\bmapEntry\x18\x02 \x01(\v2\t.MapEntryR\bmapEntry\x12\x14\n" +
	"\x05index\x18\x03 \x01(\fR\x05index\x12C\n" +
	"\x17perApplicationTreeEntry\x18\x04 \x01(\v2\t.LogEntryR\x17perApplicationTreeEntry\x127\n" +
	"\x11topLevelTreeEntry\x18\x05 \x01(\v2\t.LogEntryR\x11topLevelTreeEntry\"\x91\x01\n" +
	"\x11PatInclusionProof\x12C\n" +
	"\x17perApplicationTreeEntry\x18\x01 \x01(\v2\t.LogEntryR\x17perApplicationTreeEntry\x127\n" +
	"\x11topLevelTreeEntry\x18\x02 \x01(\v2\t.LogEntryR\x11topLevelTreeEntry\"-\n" +
	"\x0fChangeLogNodeV2\x12\x1a\n" +
	"\bmutation\x18\x01 \x01(\fR\bmutation\"Q\n" +
	"\x16PerApplicationTreeNode\x127\n" +
	"\x0fpredecessorHead\x18\x02 \x01(\v2\r.SignedObjectR\x0fpredecessorHead\";\n" +
	"\x10TopLevelTreeNode\x12'\n" +
	"\apatHead\x18\x01 \x01(\v2\r.SignedObjectR\apatHead\"\xb5\x01\n" +
	"\x1cPerApplicationTreeConfigNode\x121\n" +
	"\fvrfPublicKey\x18\x01 \x01(\v2\r.VRFPublicKeyR\fvrfPublicKey\x12&\n" +
	"\x0epublicKeyBytes\x18\x02 \x01(\fR\x0epublicKeyBytes\x12:\n" +
	"\x0fearliestVersion\x18\x03 \x01(\x0e2\x10.ProtocolVersionR\x0fearliestVersion\"\x9e\x01\n" +
	"\x16TopLevelTreeConfigNode\x12&\n" +
	"\x0epublicKeyBytes\x18\x01 \x01(\fR\x0epublicKeyBytes\x12:\n" +
	"\x0fearliestVersion\x18\x03 \x01(\x0e2\x10.ProtocolVersionR\x0fearliestVersion\x12 \n" +
	"\vtreeCounter\x18\x04 \x01(\rR\vtreeCounter\"\x83\x01\n" +
	"\rLogClosedNode\x12 \n" +
	"\vtimestampMs\x18\x01 \x01(\x04R\vtimestampMs\x12P\n" +
	"\x1aearliestVersionForNextTree\x18\x03 \x01(\x0e2\x10.ProtocolVersionR\x1aearliestVersionForNextTree*N\n" +
	"\x0fProtocolVersion\x12\x13\n" +
	"\x0fUNKNOWN_VERSION\x10\x00\x12\x06\n" +
	"\x02V1\x10\x01\x12\x06\n" +
	"\x02V2\x10\x02\x12\x06\n" +
	"\x02V3\x10\x03\x12\x0e\n" +
	"\x06FUTURE\x10\xff\x93\xeb\xdc\x03*x\n" +
	"\vApplication\x12\x17\n" +
	"\x13UNKNOWN_APPLICATION\x10\x00\x12\x11\n" +
	"\rIDS_MESSAGING\x10\x01\x12\x19\n" +
	"\x15PRIVATE_CLOUD_COMPUTE\x10\x05\x12\"\n" +
	"\x1ePRIVATE_CLOUD_COMPUTE_INTERNAL\x10\x06*\x86\x01\n" +
	"\x06Status\x12\x12\n" +
	"\x0eUNKNOWN_STATUS\x10\x00\x12\x06\n" +
	"\x02OK\x10\x01\x12\x14\n" +
	"\x10MUTATION_PENDING\x10\x03\x12\x12\n" +
	"\x0eALREADY_EXISTS\x10\x04\x12\x12\n" +
	"\x0eINTERNAL_ERROR\x10\x05\x12\x13\n" +
	"\x0fINVALID_REQUEST\x10\x06\x12\r\n" +
	"\tNOT_FOUND\x10\a*?\n" +
	"\aVRFType\x12\x0f\n" +
	"\vUNKNOWN_VRF\x10\x00\x12#\n" +
	"\x1fECVRF_ED25519_SHA512_Elligator2\x10\x03*\x80\x01\n" +
	"\aLogType\x12\x0f\n" +
	"\vUNKNOWN_LOG\x10\x00\x12\x1e\n" +
	"\x1aPER_APPLICATION_CHANGE_LOG\x10\x01\x12\x18\n" +
	"\x14PER_APPLICATION_TREE\x10\x02\x12\x12\n" +
	"\x0eTOP_LEVEL_TREE\x10\x03\x12\n" +
	"\n" +
	"\x06CT_LOG\x10\x04\x12\n" +
	"\n" +
	"\x06AT_LOG\x10\x05*2\n" +
	"\aMapType\x12\x0f\n" +
	"\vUNKNOWN_MAP\x10\x00\x12\x16\n" +
	"\x12PER_APP_OBJECT_MAP\x10\x01*\x8f\x01\n" +
	"\bNodeType\x12\r\n" +
	"\tPACL_NODE\x10\x00\x12\f\n" +
	"\bPAT_NODE\x10\x01\x12\x13\n" +
	"\x0fPAT_CONFIG_NODE\x10\x02\x12\f\n" +
	"\bTLT_NODE\x10\x03\x12\x13\n" +
	"\x0fTLT_CONFIG_NODE\x10\x04\x12\x13\n" +
	"\x0fLOG_CLOSED_NODE\x10\x05\x12\v\n" +
	"\aCT_NODE\x10\x06\x12\f\n" +
	"\bATL_NODE\x10\aBa\n" +
	"\x12com.apple.keyt.apiB\x11TransparencyProtoP\x01Z.github.com/blacktop/ipsw/internal/download/pcc\xba\x02\x05TxPB_b\x06proto3"

var (
	file_Transparency_proto_rawDescOnce sync.Once
	file_Transparency_proto_rawDescData []byte
)

func file_Transparency_proto_rawDescGZIP() []byte {
	file_Transparency_proto_rawDescOnce.Do(func() {
		file_Transparency_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_Transparency_proto_rawDesc), len(file_Transparency_proto_rawDesc)))
	})
	return file_Transparency_proto_rawDescData
}

var file_Transparency_proto_enumTypes = make([]protoimpl.EnumInfo, 8)
var file_Transparency_proto_msgTypes = make([]protoimpl.MessageInfo, 16)
var file_Transparency_proto_goTypes = []any{
	(ProtocolVersion)(0),                 // 0: ProtocolVersion
	(Application)(0),                     // 1: Application
	(Status)(0),                          // 2: Status
	(VRFType)(0),                         // 3: VRFType
	(LogType)(0),                         // 4: LogType
	(MapType)(0),                         // 5: MapType
	(NodeType)(0),                        // 6: NodeType
	(Signature_SignatureAlgorithm)(0),    // 7: Signature.SignatureAlgorithm
	(*VRFWitness)(nil),                   // 8: VRFWitness
	(*VRFPublicKey)(nil),                 // 9: VRFPublicKey
	(*Signature)(nil),                    // 10: Signature
	(*SignedObject)(nil),                 // 11: SignedObject
	(*LogHead)(nil),                      // 12: LogHead
	(*LogEntry)(nil),                     // 13: LogEntry
	(*MapHead)(nil),                      // 14: MapHead
	(*MapEntry)(nil),                     // 15: MapEntry
	(*InclusionProof)(nil),               // 16: InclusionProof
	(*PatInclusionProof)(nil),            // 17: PatInclusionProof
	(*ChangeLogNodeV2)(nil),              // 18: ChangeLogNodeV2
	(*PerApplicationTreeNode)(nil),       // 19: PerApplicationTreeNode
	(*TopLevelTreeNode)(nil),             // 20: TopLevelTreeNode
	(*PerApplicationTreeConfigNode)(nil), // 21: PerApplicationTreeConfigNode
	(*TopLevelTreeConfigNode)(nil),       // 22: TopLevelTreeConfigNode
	(*LogClosedNode)(nil),                // 23: LogClosedNode
}
var file_Transparency_proto_depIdxs = []int32{
	3,  // 0: VRFWitness.type:type_name -> VRFType
	3,  // 1: VRFPublicKey.type:type_name -> VRFType
	7,  // 2: Signature.algorithm:type_name -> Signature.SignatureAlgorithm
	10, // 3: SignedObject.signature:type_name -> Signature
	4,  // 4: LogHead.logType:type_name -> LogType
	1,  // 5: LogHead.application:type_name -> Application
	4,  // 6: LogEntry.logType:type_name -> LogType
	11, // 7: LogEntry.slh:type_name -> SignedObject
	6,  // 8: LogEntry.nodeType:type_name -> NodeType
	1,  // 9: MapHead.application:type_name -> Application
	12, // 10: MapHead.changeLogHead:type_name -> LogHead
	5,  // 11: MapHead.mapType:type_name -> MapType
	11, // 12: MapEntry.smh:type_name -> SignedObject
	15, // 13: InclusionProof.mapEntry:type_name -> MapEntry
	13, // 14: InclusionProof.perApplicationTreeEntry:type_name -> LogEntry
	13, // 15: InclusionProof.topLevelTreeEntry:type_name -> LogEntry
	13, // 16: PatInclusionProof.perApplicationTreeEntry:type_name -> LogEntry
	13, // 17: PatInclusionProof.topLevelTreeEntry:type_name -> LogEntry
	11, // 18: PerApplicationTreeNode.predecessorHead:type_name -> SignedObject
	11, // 19: TopLevelTreeNode.patHead:type_name -> SignedObject
	9,  // 20: PerApplicationTreeConfigNode.vrfPublicKey:type_name -> VRFPublicKey
	0,  // 21: PerApplicationTreeConfigNode.earliestVersion:type_name -> ProtocolVersion
	0,  // 22: TopLevelTreeConfigNode.earliestVersion:type_name -> ProtocolVersion
	0,  // 23: LogClosedNode.earliestVersionForNextTree:type_name -> ProtocolVersion
	24, // [24:24] is the sub-list for method output_type
	24, // [24:24] is the sub-list for method input_type
	24, // [24:24] is the sub-list for extension type_name
	24, // [24:24] is the sub-list for extension extendee
	0,  // [0:24] is the sub-list for field type_name
}

func init() { file_Transparency_proto_init() }
func file_Transparency_proto_init() {
	if File_Transparency_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeFor[x]().PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_Transparency_proto_rawDesc), len(file_Transparency_proto_rawDesc)),
			NumEnums:      8,
			NumMessages:   16,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_Transparency_proto_goTypes,
		DependencyIndexes: file_Transparency_proto_depIdxs,
		EnumInfos:         file_Transparency_proto_enumTypes,
		MessageInfos:      file_Transparency_proto_msgTypes,
	}.Build()
	File_Transparency_proto = out.File
	file_Transparency_proto_goTypes = nil
	file_Transparency_proto_depIdxs = nil
}
