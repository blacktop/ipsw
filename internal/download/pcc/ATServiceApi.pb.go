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

type ATLogDataType int32

const (
	ATLogDataType_UNKNOWN ATLogDataType = 0
	ATLogDataType_RELEASE ATLogDataType = 1
	// MODEL = 2; not used
	ATLogDataType_KEYBUNDLE_TGT   ATLogDataType = 3
	ATLogDataType_KEYBUNDLE_OTT   ATLogDataType = 4
	ATLogDataType_KEYBUNDLE_OHTTP ATLogDataType = 5
	ATLogDataType_TEST_MARKER     ATLogDataType = 100
)

// Enum value maps for ATLogDataType.
var (
	ATLogDataType_name = map[int32]string{
		0:   "UNKNOWN",
		1:   "RELEASE",
		3:   "KEYBUNDLE_TGT",
		4:   "KEYBUNDLE_OTT",
		5:   "KEYBUNDLE_OHTTP",
		100: "TEST_MARKER",
	}
	ATLogDataType_value = map[string]int32{
		"UNKNOWN":         0,
		"RELEASE":         1,
		"KEYBUNDLE_TGT":   3,
		"KEYBUNDLE_OTT":   4,
		"KEYBUNDLE_OHTTP": 5,
		"TEST_MARKER":     100,
	}
)

func (x ATLogDataType) Enum() *ATLogDataType {
	p := new(ATLogDataType)
	*p = x
	return p
}

func (x ATLogDataType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ATLogDataType) Descriptor() protoreflect.EnumDescriptor {
	return file_ATServiceApi_proto_enumTypes[0].Descriptor()
}

func (ATLogDataType) Type() protoreflect.EnumType {
	return &file_ATServiceApi_proto_enumTypes[0]
}

func (x ATLogDataType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ATLogDataType.Descriptor instead.
func (ATLogDataType) EnumDescriptor() ([]byte, []int) {
	return file_ATServiceApi_proto_rawDescGZIP(), []int{0}
}

// Insert data can go in one of two sets of fields.
// For extra environment verification, populate the ATInsertData field and leave type, data, and
// unhashedMetadata fields empty (they will be ignored if insertData is set).
// For traditional requests, set type, data, and unhashedMetadata fields with data to insert and
// leave insertData empty.
// version, application, and expiryMs fields must be populated in either case.
type ATLogInsertRequest struct {
	state       protoimpl.MessageState `protogen:"open.v1"`
	Version     ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	Application Application            `protobuf:"varint,2,opt,name=application,proto3,enum=Application" json:"application,omitempty"`
	Type        ATLogDataType          `protobuf:"varint,3,opt,name=type,proto3,enum=ATLogDataType" json:"type,omitempty"`
	ExpiryMs    uint64                 `protobuf:"varint,4,opt,name=expiryMs,proto3" json:"expiryMs,omitempty"`
	Data        []byte                 `protobuf:"bytes,5,opt,name=data,proto3" json:"data,omitempty"`
	// additional data available to researchers that will not be hashed or signed by the server
	UnhashedMetadata []byte `protobuf:"bytes,6,opt,name=unhashedMetadata,proto3" json:"unhashedMetadata,omitempty"`
	InsertData       []byte `protobuf:"bytes,7,opt,name=insertData,proto3" json:"insertData,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *ATLogInsertRequest) Reset() {
	*x = ATLogInsertRequest{}
	mi := &file_ATServiceApi_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ATLogInsertRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ATLogInsertRequest) ProtoMessage() {}

func (x *ATLogInsertRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ATServiceApi_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ATLogInsertRequest.ProtoReflect.Descriptor instead.
func (*ATLogInsertRequest) Descriptor() ([]byte, []int) {
	return file_ATServiceApi_proto_rawDescGZIP(), []int{0}
}

func (x *ATLogInsertRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *ATLogInsertRequest) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *ATLogInsertRequest) GetType() ATLogDataType {
	if x != nil {
		return x.Type
	}
	return ATLogDataType_UNKNOWN
}

func (x *ATLogInsertRequest) GetExpiryMs() uint64 {
	if x != nil {
		return x.ExpiryMs
	}
	return 0
}

func (x *ATLogInsertRequest) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *ATLogInsertRequest) GetUnhashedMetadata() []byte {
	if x != nil {
		return x.UnhashedMetadata
	}
	return nil
}

func (x *ATLogInsertRequest) GetInsertData() []byte {
	if x != nil {
		return x.InsertData
	}
	return nil
}

type ATLogInsertResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Possible status values: MUTATION_PENDING (success), INTERNAL_ERROR, INVALID_REQUEST
	Status        Status `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ATLogInsertResponse) Reset() {
	*x = ATLogInsertResponse{}
	mi := &file_ATServiceApi_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ATLogInsertResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ATLogInsertResponse) ProtoMessage() {}

func (x *ATLogInsertResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ATServiceApi_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ATLogInsertResponse.ProtoReflect.Descriptor instead.
func (*ATLogInsertResponse) Descriptor() ([]byte, []int) {
	return file_ATServiceApi_proto_rawDescGZIP(), []int{1}
}

func (x *ATLogInsertResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

type ATLogProofRequest struct {
	state       protoimpl.MessageState `protogen:"open.v1"`
	Version     ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	Application Application            `protobuf:"varint,2,opt,name=application,proto3,enum=Application" json:"application,omitempty"`
	// This is the SHA256 hash of the logged data.
	// If the same data has been inserted multiple times, this will return the latest entry.
	Identifier    []byte `protobuf:"bytes,3,opt,name=identifier,proto3" json:"identifier,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ATLogProofRequest) Reset() {
	*x = ATLogProofRequest{}
	mi := &file_ATServiceApi_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ATLogProofRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ATLogProofRequest) ProtoMessage() {}

func (x *ATLogProofRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ATServiceApi_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ATLogProofRequest.ProtoReflect.Descriptor instead.
func (*ATLogProofRequest) Descriptor() ([]byte, []int) {
	return file_ATServiceApi_proto_rawDescGZIP(), []int{2}
}

func (x *ATLogProofRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *ATLogProofRequest) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *ATLogProofRequest) GetIdentifier() []byte {
	if x != nil {
		return x.Identifier
	}
	return nil
}

type ATLogProofResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Possible status values: OK, INTERNAL_ERROR, INVALID_REQUEST, NOT_FOUND, MUTATION_PENDING
	// Other values should be treated as INTERNAL_ERROR
	// NOT_FOUND indicates the value was never inserted
	// MUTATION_PENDING means it has been inserted but hasn't yet sequenced into the log, PAT, and TLT
	// OK will return a full response, other values will only include status and serverEventInfo
	Status Status       `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	Proofs *ATLogProofs `protobuf:"bytes,3,opt,name=proofs,proto3" json:"proofs,omitempty"`
	// Expiry time of the returned leaf. Matches the expiry set in the insert request for this leaf.
	// Also available in proofs.inclusionProof.nodsBytes -> parse as as proto ChangeLogNodeV2 -> value -> parse as TLS ATLeafData -> expiryMs
	// That one is hashed... signed... tree consistency protections..., but this is much easier to access.
	ExpiryMs      uint64 `protobuf:"varint,4,opt,name=expiryMs,proto3" json:"expiryMs,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ATLogProofResponse) Reset() {
	*x = ATLogProofResponse{}
	mi := &file_ATServiceApi_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ATLogProofResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ATLogProofResponse) ProtoMessage() {}

func (x *ATLogProofResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ATServiceApi_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ATLogProofResponse.ProtoReflect.Descriptor instead.
func (*ATLogProofResponse) Descriptor() ([]byte, []int) {
	return file_ATServiceApi_proto_rawDescGZIP(), []int{3}
}

func (x *ATLogProofResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *ATLogProofResponse) GetProofs() *ATLogProofs {
	if x != nil {
		return x.Proofs
	}
	return nil
}

func (x *ATLogProofResponse) GetExpiryMs() uint64 {
	if x != nil {
		return x.ExpiryMs
	}
	return 0
}

type ATLogProofs struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Inclusion proof for this data if it exists in the TL.
	InclusionProof *LogEntry `protobuf:"bytes,1,opt,name=inclusionProof,proto3" json:"inclusionProof,omitempty"`
	// If the inclusion proof isn't to a milestone root, this will be included to prove consistency with a recent milestone
	MilestoneConsistency *LogConsistency `protobuf:"bytes,2,opt,name=milestoneConsistency,proto3" json:"milestoneConsistency,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *ATLogProofs) Reset() {
	*x = ATLogProofs{}
	mi := &file_ATServiceApi_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ATLogProofs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ATLogProofs) ProtoMessage() {}

func (x *ATLogProofs) ProtoReflect() protoreflect.Message {
	mi := &file_ATServiceApi_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ATLogProofs.ProtoReflect.Descriptor instead.
func (*ATLogProofs) Descriptor() ([]byte, []int) {
	return file_ATServiceApi_proto_rawDescGZIP(), []int{4}
}

func (x *ATLogProofs) GetInclusionProof() *LogEntry {
	if x != nil {
		return x.InclusionProof
	}
	return nil
}

func (x *ATLogProofs) GetMilestoneConsistency() *LogConsistency {
	if x != nil {
		return x.MilestoneConsistency
	}
	return nil
}

type LogConsistency struct {
	state       protoimpl.MessageState `protogen:"open.v1"`
	StartSLH    *SignedObject          `protobuf:"bytes,3,opt,name=startSLH,proto3" json:"startSLH,omitempty"` // SLH of a milestone root
	EndSLH      *SignedObject          `protobuf:"bytes,4,opt,name=endSLH,proto3" json:"endSLH,omitempty"`     // redundant, matches SLH in inclusionProof
	ProofHashes [][]byte               `protobuf:"bytes,5,rep,name=proofHashes,proto3" json:"proofHashes,omitempty"`
	// inclusion proof of the endSLH in the PAT, and the PAT head in the TLT
	PatInclusionProof *LogEntry `protobuf:"bytes,8,opt,name=patInclusionProof,proto3" json:"patInclusionProof,omitempty"`
	TltInclusionProof *LogEntry `protobuf:"bytes,9,opt,name=tltInclusionProof,proto3" json:"tltInclusionProof,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *LogConsistency) Reset() {
	*x = LogConsistency{}
	mi := &file_ATServiceApi_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogConsistency) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogConsistency) ProtoMessage() {}

func (x *LogConsistency) ProtoReflect() protoreflect.Message {
	mi := &file_ATServiceApi_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogConsistency.ProtoReflect.Descriptor instead.
func (*LogConsistency) Descriptor() ([]byte, []int) {
	return file_ATServiceApi_proto_rawDescGZIP(), []int{5}
}

func (x *LogConsistency) GetStartSLH() *SignedObject {
	if x != nil {
		return x.StartSLH
	}
	return nil
}

func (x *LogConsistency) GetEndSLH() *SignedObject {
	if x != nil {
		return x.EndSLH
	}
	return nil
}

func (x *LogConsistency) GetProofHashes() [][]byte {
	if x != nil {
		return x.ProofHashes
	}
	return nil
}

func (x *LogConsistency) GetPatInclusionProof() *LogEntry {
	if x != nil {
		return x.PatInclusionProof
	}
	return nil
}

func (x *LogConsistency) GetTltInclusionProof() *LogEntry {
	if x != nil {
		return x.TltInclusionProof
	}
	return nil
}

var File_ATServiceApi_proto protoreflect.FileDescriptor

const file_ATServiceApi_proto_rawDesc = "" +
	"\n" +
	"\x12ATServiceApi.proto\x1a\x12Transparency.proto\"\x90\x02\n" +
	"\x12ATLogInsertRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12.\n" +
	"\vapplication\x18\x02 \x01(\x0e2\f.ApplicationR\vapplication\x12\"\n" +
	"\x04type\x18\x03 \x01(\x0e2\x0e.ATLogDataTypeR\x04type\x12\x1a\n" +
	"\bexpiryMs\x18\x04 \x01(\x04R\bexpiryMs\x12\x12\n" +
	"\x04data\x18\x05 \x01(\fR\x04data\x12*\n" +
	"\x10unhashedMetadata\x18\x06 \x01(\fR\x10unhashedMetadata\x12\x1e\n" +
	"\n" +
	"insertData\x18\a \x01(\fR\n" +
	"insertData\"6\n" +
	"\x13ATLogInsertResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\"\x8f\x01\n" +
	"\x11ATLogProofRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12.\n" +
	"\vapplication\x18\x02 \x01(\x0e2\f.ApplicationR\vapplication\x12\x1e\n" +
	"\n" +
	"identifier\x18\x03 \x01(\fR\n" +
	"identifier\"w\n" +
	"\x12ATLogProofResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12$\n" +
	"\x06proofs\x18\x03 \x01(\v2\f.ATLogProofsR\x06proofs\x12\x1a\n" +
	"\bexpiryMs\x18\x04 \x01(\x04R\bexpiryMs\"\x85\x01\n" +
	"\vATLogProofs\x121\n" +
	"\x0einclusionProof\x18\x01 \x01(\v2\t.LogEntryR\x0einclusionProof\x12C\n" +
	"\x14milestoneConsistency\x18\x02 \x01(\v2\x0f.LogConsistencyR\x14milestoneConsistency\"\xf6\x01\n" +
	"\x0eLogConsistency\x12)\n" +
	"\bstartSLH\x18\x03 \x01(\v2\r.SignedObjectR\bstartSLH\x12%\n" +
	"\x06endSLH\x18\x04 \x01(\v2\r.SignedObjectR\x06endSLH\x12 \n" +
	"\vproofHashes\x18\x05 \x03(\fR\vproofHashes\x127\n" +
	"\x11patInclusionProof\x18\b \x01(\v2\t.LogEntryR\x11patInclusionProof\x127\n" +
	"\x11tltInclusionProof\x18\t \x01(\v2\t.LogEntryR\x11tltInclusionProof*u\n" +
	"\rATLogDataType\x12\v\n" +
	"\aUNKNOWN\x10\x00\x12\v\n" +
	"\aRELEASE\x10\x01\x12\x11\n" +
	"\rKEYBUNDLE_TGT\x10\x03\x12\x11\n" +
	"\rKEYBUNDLE_OTT\x10\x04\x12\x13\n" +
	"\x0fKEYBUNDLE_OHTTP\x10\x05\x12\x0f\n" +
	"\vTEST_MARKER\x10dBa\n" +
	"\x15com.apple.keyt.api.atB\x0eATServiceProtoP\x01Z.github.com/blacktop/ipsw/internal/download/pcc\xba\x02\x05TxPB_b\x06proto3"

var (
	file_ATServiceApi_proto_rawDescOnce sync.Once
	file_ATServiceApi_proto_rawDescData []byte
)

func file_ATServiceApi_proto_rawDescGZIP() []byte {
	file_ATServiceApi_proto_rawDescOnce.Do(func() {
		file_ATServiceApi_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_ATServiceApi_proto_rawDesc), len(file_ATServiceApi_proto_rawDesc)))
	})
	return file_ATServiceApi_proto_rawDescData
}

var file_ATServiceApi_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_ATServiceApi_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_ATServiceApi_proto_goTypes = []any{
	(ATLogDataType)(0),          // 0: ATLogDataType
	(*ATLogInsertRequest)(nil),  // 1: ATLogInsertRequest
	(*ATLogInsertResponse)(nil), // 2: ATLogInsertResponse
	(*ATLogProofRequest)(nil),   // 3: ATLogProofRequest
	(*ATLogProofResponse)(nil),  // 4: ATLogProofResponse
	(*ATLogProofs)(nil),         // 5: ATLogProofs
	(*LogConsistency)(nil),      // 6: LogConsistency
	(ProtocolVersion)(0),        // 7: ProtocolVersion
	(Application)(0),            // 8: Application
	(Status)(0),                 // 9: Status
	(*LogEntry)(nil),            // 10: LogEntry
	(*SignedObject)(nil),        // 11: SignedObject
}
var file_ATServiceApi_proto_depIdxs = []int32{
	7,  // 0: ATLogInsertRequest.version:type_name -> ProtocolVersion
	8,  // 1: ATLogInsertRequest.application:type_name -> Application
	0,  // 2: ATLogInsertRequest.type:type_name -> ATLogDataType
	9,  // 3: ATLogInsertResponse.status:type_name -> Status
	7,  // 4: ATLogProofRequest.version:type_name -> ProtocolVersion
	8,  // 5: ATLogProofRequest.application:type_name -> Application
	9,  // 6: ATLogProofResponse.status:type_name -> Status
	5,  // 7: ATLogProofResponse.proofs:type_name -> ATLogProofs
	10, // 8: ATLogProofs.inclusionProof:type_name -> LogEntry
	6,  // 9: ATLogProofs.milestoneConsistency:type_name -> LogConsistency
	11, // 10: LogConsistency.startSLH:type_name -> SignedObject
	11, // 11: LogConsistency.endSLH:type_name -> SignedObject
	10, // 12: LogConsistency.patInclusionProof:type_name -> LogEntry
	10, // 13: LogConsistency.tltInclusionProof:type_name -> LogEntry
	14, // [14:14] is the sub-list for method output_type
	14, // [14:14] is the sub-list for method input_type
	14, // [14:14] is the sub-list for extension type_name
	14, // [14:14] is the sub-list for extension extendee
	0,  // [0:14] is the sub-list for field type_name
}

func init() { file_ATServiceApi_proto_init() }
func file_ATServiceApi_proto_init() {
	if File_ATServiceApi_proto != nil {
		return
	}
	file_Transparency_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_ATServiceApi_proto_rawDesc), len(file_ATServiceApi_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ATServiceApi_proto_goTypes,
		DependencyIndexes: file_ATServiceApi_proto_depIdxs,
		EnumInfos:         file_ATServiceApi_proto_enumTypes,
		MessageInfos:      file_ATServiceApi_proto_msgTypes,
	}.Build()
	File_ATServiceApi_proto = out.File
	file_ATServiceApi_proto_goTypes = nil
	file_ATServiceApi_proto_depIdxs = nil
}
