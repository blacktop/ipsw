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

type ConsistencyProofRequest struct {
	state         protoimpl.MessageState                           `protogen:"open.v1"`
	Version       ProtocolVersion                                  `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	Requests      []*ConsistencyProofRequest_LogConsistencyRequest `protobuf:"bytes,2,rep,name=requests,proto3" json:"requests,omitempty"`
	LogType       LogType                                          `protobuf:"varint,3,opt,name=logType,proto3,enum=LogType" json:"logType,omitempty"`
	Application   Application                                      `protobuf:"varint,4,opt,name=application,proto3,enum=Application" json:"application,omitempty"` // If logType is not TopLevelTree, provide an application
	RequestUuid   string                                           `protobuf:"bytes,5,opt,name=requestUuid,proto3" json:"requestUuid,omitempty"`                   // Used for logging, not expected when uuid is passed in headers
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ConsistencyProofRequest) Reset() {
	*x = ConsistencyProofRequest{}
	mi := &file_KtClientApi_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConsistencyProofRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConsistencyProofRequest) ProtoMessage() {}

func (x *ConsistencyProofRequest) ProtoReflect() protoreflect.Message {
	mi := &file_KtClientApi_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConsistencyProofRequest.ProtoReflect.Descriptor instead.
func (*ConsistencyProofRequest) Descriptor() ([]byte, []int) {
	return file_KtClientApi_proto_rawDescGZIP(), []int{0}
}

func (x *ConsistencyProofRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *ConsistencyProofRequest) GetRequests() []*ConsistencyProofRequest_LogConsistencyRequest {
	if x != nil {
		return x.Requests
	}
	return nil
}

func (x *ConsistencyProofRequest) GetLogType() LogType {
	if x != nil {
		return x.LogType
	}
	return LogType_UNKNOWN_LOG
}

func (x *ConsistencyProofRequest) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *ConsistencyProofRequest) GetRequestUuid() string {
	if x != nil {
		return x.RequestUuid
	}
	return ""
}

// Note: the server may, at its discretion, return multiple LogConsistencyResponses for a single LogConsistencyRequest.
// For example, if a client requests a proof from revision 51 to 130, the server may return a consistency
// proof of [51,130], or multiple adjoining proofs, like [51, 100], [100, 120], [120, 130].
//
// The server may omit proofs (such as when too many are requested), the client should record the
// returned proofs and make a new request for the unfulfilled proofs.
type ConsistencyProofResponse struct {
	state  protoimpl.MessageState `protogen:"open.v1"`
	Status Status                 `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	// 2 - can reuse
	// these will be sorted by logId, start revision, end revision
	Responses     []*ConsistencyProofResponse_LogConsistencyResponse `protobuf:"bytes,3,rep,name=responses,proto3" json:"responses,omitempty"`
	LogType       LogType                                            `protobuf:"varint,4,opt,name=logType,proto3,enum=LogType" json:"logType,omitempty"`
	Application   Application                                        `protobuf:"varint,5,opt,name=application,proto3,enum=Application" json:"application,omitempty"` // If logType is not TopLevelTree, provide an application
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ConsistencyProofResponse) Reset() {
	*x = ConsistencyProofResponse{}
	mi := &file_KtClientApi_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConsistencyProofResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConsistencyProofResponse) ProtoMessage() {}

func (x *ConsistencyProofResponse) ProtoReflect() protoreflect.Message {
	mi := &file_KtClientApi_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConsistencyProofResponse.ProtoReflect.Descriptor instead.
func (*ConsistencyProofResponse) Descriptor() ([]byte, []int) {
	return file_KtClientApi_proto_rawDescGZIP(), []int{1}
}

func (x *ConsistencyProofResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *ConsistencyProofResponse) GetResponses() []*ConsistencyProofResponse_LogConsistencyResponse {
	if x != nil {
		return x.Responses
	}
	return nil
}

func (x *ConsistencyProofResponse) GetLogType() LogType {
	if x != nil {
		return x.LogType
	}
	return LogType_UNKNOWN_LOG
}

func (x *ConsistencyProofResponse) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

type RevisionLogInclusionProofRequest struct {
	state       protoimpl.MessageState `protogen:"open.v1"`
	Version     ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	Application Application            `protobuf:"varint,2,opt,name=application,proto3,enum=Application" json:"application,omitempty"`
	LogType     LogType                `protobuf:"varint,3,opt,name=logType,proto3,enum=LogType" json:"logType,omitempty"` // Type of log in which to lookup leaves, either PAT or TLT
	// If logType is PAT, revisions will be from PAM. If logType is TLT, revisions will be from PAT.
	Revision      []uint64 `protobuf:"varint,4,rep,packed,name=revision,proto3" json:"revision,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RevisionLogInclusionProofRequest) Reset() {
	*x = RevisionLogInclusionProofRequest{}
	mi := &file_KtClientApi_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RevisionLogInclusionProofRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RevisionLogInclusionProofRequest) ProtoMessage() {}

func (x *RevisionLogInclusionProofRequest) ProtoReflect() protoreflect.Message {
	mi := &file_KtClientApi_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RevisionLogInclusionProofRequest.ProtoReflect.Descriptor instead.
func (*RevisionLogInclusionProofRequest) Descriptor() ([]byte, []int) {
	return file_KtClientApi_proto_rawDescGZIP(), []int{2}
}

func (x *RevisionLogInclusionProofRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *RevisionLogInclusionProofRequest) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *RevisionLogInclusionProofRequest) GetLogType() LogType {
	if x != nil {
		return x.LogType
	}
	return LogType_UNKNOWN_LOG
}

func (x *RevisionLogInclusionProofRequest) GetRevision() []uint64 {
	if x != nil {
		return x.Revision
	}
	return nil
}

// The server may omit proofs (such as when too many are requested), the client should record the
// returned proofs and make a new request for the unfulfilled proofs.
type RevisionLogInclusionProofResponse struct {
	state  protoimpl.MessageState `protogen:"open.v1"`
	Status Status                 `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"` // OK, INVALID_REQUEST, or INTERNAL_ERROR
	// not guaranteed to have every requested proof
	// all these proofs will be under the same log head, sorted by leaf index
	LogEntry []*LogEntry `protobuf:"bytes,4,rep,name=logEntry,proto3" json:"logEntry,omitempty"`
	// if logEntries contains PAT proofs, this will be proof of the PAT head in the TLT, may be absent
	TopLevelTreeEntry *LogEntry `protobuf:"bytes,5,opt,name=topLevelTreeEntry,proto3" json:"topLevelTreeEntry,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *RevisionLogInclusionProofResponse) Reset() {
	*x = RevisionLogInclusionProofResponse{}
	mi := &file_KtClientApi_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RevisionLogInclusionProofResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RevisionLogInclusionProofResponse) ProtoMessage() {}

func (x *RevisionLogInclusionProofResponse) ProtoReflect() protoreflect.Message {
	mi := &file_KtClientApi_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RevisionLogInclusionProofResponse.ProtoReflect.Descriptor instead.
func (*RevisionLogInclusionProofResponse) Descriptor() ([]byte, []int) {
	return file_KtClientApi_proto_rawDescGZIP(), []int{3}
}

func (x *RevisionLogInclusionProofResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *RevisionLogInclusionProofResponse) GetLogEntry() []*LogEntry {
	if x != nil {
		return x.LogEntry
	}
	return nil
}

func (x *RevisionLogInclusionProofResponse) GetTopLevelTreeEntry() *LogEntry {
	if x != nil {
		return x.TopLevelTreeEntry
	}
	return nil
}

// When making requests over HTTP the body can be omitted.  Instead, the Application should
// be specified in the "x-apple-application" header using the numeric value, and the version
// specified in the "x-protocol-version" header using the enum value.
// Version 2, iMessage would be indicated with:
// x-apple-application: 1
// x-protocol-version: V2
type PublicKeysRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Version       ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	Application   Application            `protobuf:"varint,2,opt,name=application,proto3,enum=Application" json:"application,omitempty"`
	RequestUuid   string                 `protobuf:"bytes,3,opt,name=requestUuid,proto3" json:"requestUuid,omitempty"` // Used for logging, not expected when uuid is passed in headers
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PublicKeysRequest) Reset() {
	*x = PublicKeysRequest{}
	mi := &file_KtClientApi_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PublicKeysRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKeysRequest) ProtoMessage() {}

func (x *PublicKeysRequest) ProtoReflect() protoreflect.Message {
	mi := &file_KtClientApi_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKeysRequest.ProtoReflect.Descriptor instead.
func (*PublicKeysRequest) Descriptor() ([]byte, []int) {
	return file_KtClientApi_proto_rawDescGZIP(), []int{4}
}

func (x *PublicKeysRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *PublicKeysRequest) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *PublicKeysRequest) GetRequestUuid() string {
	if x != nil {
		return x.RequestUuid
	}
	return ""
}

type PublicKeysResponse struct {
	state  protoimpl.MessageState `protogen:"open.v1"`
	Status Status                 `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	// DER-encoded SMT and STH signing certificate(s) for the application's trees.
	AppLeafs [][]byte `protobuf:"bytes,2,rep,name=appLeafs,proto3" json:"appLeafs,omitempty"`
	// DER-encoded STH signing certificate(s) for the TLT.
	TltLeafs [][]byte `protobuf:"bytes,3,rep,name=tltLeafs,proto3" json:"tltLeafs,omitempty"`
	// DER-encoded intermediate certificate(s).
	Intermediates [][]byte `protobuf:"bytes,4,rep,name=intermediates,proto3" json:"intermediates,omitempty"` // V2 removed: vrfKey = 5, vrfSignature = 6, vrfPublicKey = 7, tltBeginningMs = 8
	// inclusion proof of the PerApplicationTreeConfigNode
	// Contains VRF public key, public key for signing roots of all trees for this app, and minimum version supported by these trees
	// For Private Cloud Compute PATs, the config node uses the same protocol messages but does not include the VRF public key
	PatConfigProof *PatInclusionProof `protobuf:"bytes,9,opt,name=patConfigProof,proto3" json:"patConfigProof,omitempty"`
	// inclusion proof of the TopLevelTreeConfigNode
	// Contains public key for signing roots of top-level tree and minimum version supported by the TLT
	TltConfigProof *LogEntry `protobuf:"bytes,10,opt,name=tltConfigProof,proto3" json:"tltConfigProof,omitempty"`
	// Inclusion proof of PatClosedNode of the last PAT that supported this ProtocolVersion.
	// Only present if this ProtocolVersion is no longer supported.
	// The patConfigProof will be from the same tree, tltConfigProof will be for the TLT with
	// this PAT's heads, and certificates will be for this set of trees
	PatClosedProof *PatInclusionProof `protobuf:"bytes,11,opt,name=patClosedProof,proto3" json:"patClosedProof,omitempty"`
	// Optional URL to information about tree roll or obsoletion.
	// Displayed by the client in the notification when the roll is detected.
	TreeRollInfoUrl string `protobuf:"bytes,12,opt,name=treeRollInfoUrl,proto3" json:"treeRollInfoUrl,omitempty"`
	// Proof of a recent PAM head in the PAT, used to check populating state
	// Optional unless the PAM is still populating
	// Uses the same PAT root as patConfigProof
	PamHeadInPatProof *LogEntry `protobuf:"bytes,13,opt,name=pamHeadInPatProof,proto3" json:"pamHeadInPatProof,omitempty"`
	// DER-encoded STH signing certificate(s) for old tree root signing certs. PCC only, optional.
	OldAppRootCerts [][]byte `protobuf:"bytes,14,rep,name=oldAppRootCerts,proto3" json:"oldAppRootCerts,omitempty"`
	OldTltRootCerts [][]byte `protobuf:"bytes,15,rep,name=oldTltRootCerts,proto3" json:"oldTltRootCerts,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *PublicKeysResponse) Reset() {
	*x = PublicKeysResponse{}
	mi := &file_KtClientApi_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PublicKeysResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKeysResponse) ProtoMessage() {}

func (x *PublicKeysResponse) ProtoReflect() protoreflect.Message {
	mi := &file_KtClientApi_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKeysResponse.ProtoReflect.Descriptor instead.
func (*PublicKeysResponse) Descriptor() ([]byte, []int) {
	return file_KtClientApi_proto_rawDescGZIP(), []int{5}
}

func (x *PublicKeysResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *PublicKeysResponse) GetAppLeafs() [][]byte {
	if x != nil {
		return x.AppLeafs
	}
	return nil
}

func (x *PublicKeysResponse) GetTltLeafs() [][]byte {
	if x != nil {
		return x.TltLeafs
	}
	return nil
}

func (x *PublicKeysResponse) GetIntermediates() [][]byte {
	if x != nil {
		return x.Intermediates
	}
	return nil
}

func (x *PublicKeysResponse) GetPatConfigProof() *PatInclusionProof {
	if x != nil {
		return x.PatConfigProof
	}
	return nil
}

func (x *PublicKeysResponse) GetTltConfigProof() *LogEntry {
	if x != nil {
		return x.TltConfigProof
	}
	return nil
}

func (x *PublicKeysResponse) GetPatClosedProof() *PatInclusionProof {
	if x != nil {
		return x.PatClosedProof
	}
	return nil
}

func (x *PublicKeysResponse) GetTreeRollInfoUrl() string {
	if x != nil {
		return x.TreeRollInfoUrl
	}
	return ""
}

func (x *PublicKeysResponse) GetPamHeadInPatProof() *LogEntry {
	if x != nil {
		return x.PamHeadInPatProof
	}
	return nil
}

func (x *PublicKeysResponse) GetOldAppRootCerts() [][]byte {
	if x != nil {
		return x.OldAppRootCerts
	}
	return nil
}

func (x *PublicKeysResponse) GetOldTltRootCerts() [][]byte {
	if x != nil {
		return x.OldTltRootCerts
	}
	return nil
}

type ConsistencyProofRequest_LogConsistencyRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// V2: moved logType = 1 and application = 2 out of LogConsistencyRequest
	StartRevision uint64 `protobuf:"varint,3,opt,name=startRevision,proto3" json:"startRevision,omitempty"` // Required, must be >= 0
	EndRevision   uint64 `protobuf:"varint,4,opt,name=endRevision,proto3" json:"endRevision,omitempty"`     // Required, must be > startRevision
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ConsistencyProofRequest_LogConsistencyRequest) Reset() {
	*x = ConsistencyProofRequest_LogConsistencyRequest{}
	mi := &file_KtClientApi_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConsistencyProofRequest_LogConsistencyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConsistencyProofRequest_LogConsistencyRequest) ProtoMessage() {}

func (x *ConsistencyProofRequest_LogConsistencyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_KtClientApi_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConsistencyProofRequest_LogConsistencyRequest.ProtoReflect.Descriptor instead.
func (*ConsistencyProofRequest_LogConsistencyRequest) Descriptor() ([]byte, []int) {
	return file_KtClientApi_proto_rawDescGZIP(), []int{0, 0}
}

func (x *ConsistencyProofRequest_LogConsistencyRequest) GetStartRevision() uint64 {
	if x != nil {
		return x.StartRevision
	}
	return 0
}

func (x *ConsistencyProofRequest_LogConsistencyRequest) GetEndRevision() uint64 {
	if x != nil {
		return x.EndRevision
	}
	return 0
}

// Individual consistency proofs, which can be linked to prove larger ranges
type ConsistencyProofResponse_LogConsistencyResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// V2: moved logType = 1 and application = 2 out of LogConsistencyResponse
	StartSLH      *SignedObject `protobuf:"bytes,3,opt,name=startSLH,proto3" json:"startSLH,omitempty"`
	EndSLH        *SignedObject `protobuf:"bytes,4,opt,name=endSLH,proto3" json:"endSLH,omitempty"`
	ProofHashes   [][]byte      `protobuf:"bytes,5,rep,name=proofHashes,proto3" json:"proofHashes,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ConsistencyProofResponse_LogConsistencyResponse) Reset() {
	*x = ConsistencyProofResponse_LogConsistencyResponse{}
	mi := &file_KtClientApi_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConsistencyProofResponse_LogConsistencyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConsistencyProofResponse_LogConsistencyResponse) ProtoMessage() {}

func (x *ConsistencyProofResponse_LogConsistencyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_KtClientApi_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConsistencyProofResponse_LogConsistencyResponse.ProtoReflect.Descriptor instead.
func (*ConsistencyProofResponse_LogConsistencyResponse) Descriptor() ([]byte, []int) {
	return file_KtClientApi_proto_rawDescGZIP(), []int{1, 0}
}

func (x *ConsistencyProofResponse_LogConsistencyResponse) GetStartSLH() *SignedObject {
	if x != nil {
		return x.StartSLH
	}
	return nil
}

func (x *ConsistencyProofResponse_LogConsistencyResponse) GetEndSLH() *SignedObject {
	if x != nil {
		return x.EndSLH
	}
	return nil
}

func (x *ConsistencyProofResponse_LogConsistencyResponse) GetProofHashes() [][]byte {
	if x != nil {
		return x.ProofHashes
	}
	return nil
}

var File_KtClientApi_proto protoreflect.FileDescriptor

const file_KtClientApi_proto_rawDesc = "" +
	"\n" +
	"\x11KtClientApi.proto\x1a\x12Transparency.proto\"\xe8\x02\n" +
	"\x17ConsistencyProofRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12J\n" +
	"\brequests\x18\x02 \x03(\v2..ConsistencyProofRequest.LogConsistencyRequestR\brequests\x12\"\n" +
	"\alogType\x18\x03 \x01(\x0e2\b.LogTypeR\alogType\x12.\n" +
	"\vapplication\x18\x04 \x01(\x0e2\f.ApplicationR\vapplication\x12 \n" +
	"\vrequestUuid\x18\x05 \x01(\tR\vrequestUuid\x1a_\n" +
	"\x15LogConsistencyRequest\x12$\n" +
	"\rstartRevision\x18\x03 \x01(\x04R\rstartRevision\x12 \n" +
	"\vendRevision\x18\x04 \x01(\x04R\vendRevision\"\xee\x02\n" +
	"\x18ConsistencyProofResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12N\n" +
	"\tresponses\x18\x03 \x03(\v20.ConsistencyProofResponse.LogConsistencyResponseR\tresponses\x12\"\n" +
	"\alogType\x18\x04 \x01(\x0e2\b.LogTypeR\alogType\x12.\n" +
	"\vapplication\x18\x05 \x01(\x0e2\f.ApplicationR\vapplication\x1a\x8c\x01\n" +
	"\x16LogConsistencyResponse\x12)\n" +
	"\bstartSLH\x18\x03 \x01(\v2\r.SignedObjectR\bstartSLH\x12%\n" +
	"\x06endSLH\x18\x04 \x01(\v2\r.SignedObjectR\x06endSLH\x12 \n" +
	"\vproofHashes\x18\x05 \x03(\fR\vproofHashes\"\xbe\x01\n" +
	" RevisionLogInclusionProofRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12.\n" +
	"\vapplication\x18\x02 \x01(\x0e2\f.ApplicationR\vapplication\x12\"\n" +
	"\alogType\x18\x03 \x01(\x0e2\b.LogTypeR\alogType\x12\x1a\n" +
	"\brevision\x18\x04 \x03(\x04R\brevision\"\xa4\x01\n" +
	"!RevisionLogInclusionProofResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12%\n" +
	"\blogEntry\x18\x04 \x03(\v2\t.LogEntryR\blogEntry\x127\n" +
	"\x11topLevelTreeEntry\x18\x05 \x01(\v2\t.LogEntryR\x11topLevelTreeEntry\"\x91\x01\n" +
	"\x11PublicKeysRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12.\n" +
	"\vapplication\x18\x02 \x01(\x0e2\f.ApplicationR\vapplication\x12 \n" +
	"\vrequestUuid\x18\x03 \x01(\tR\vrequestUuid\"\xf5\x03\n" +
	"\x12PublicKeysResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12\x1a\n" +
	"\bappLeafs\x18\x02 \x03(\fR\bappLeafs\x12\x1a\n" +
	"\btltLeafs\x18\x03 \x03(\fR\btltLeafs\x12$\n" +
	"\rintermediates\x18\x04 \x03(\fR\rintermediates\x12:\n" +
	"\x0epatConfigProof\x18\t \x01(\v2\x12.PatInclusionProofR\x0epatConfigProof\x121\n" +
	"\x0etltConfigProof\x18\n" +
	" \x01(\v2\t.LogEntryR\x0etltConfigProof\x12:\n" +
	"\x0epatClosedProof\x18\v \x01(\v2\x12.PatInclusionProofR\x0epatClosedProof\x12(\n" +
	"\x0ftreeRollInfoUrl\x18\f \x01(\tR\x0ftreeRollInfoUrl\x127\n" +
	"\x11pamHeadInPatProof\x18\r \x01(\v2\t.LogEntryR\x11pamHeadInPatProof\x12(\n" +
	"\x0foldAppRootCerts\x18\x0e \x03(\fR\x0foldAppRootCerts\x12(\n" +
	"\x0foldTltRootCerts\x18\x0f \x03(\fR\x0foldTltRootCertsB]\n" +
	"\x12com.apple.keyt.apiB\rKTClientProtoP\x01Z.github.com/blacktop/ipsw/internal/download/pcc\xba\x02\x05TxPB_b\x06proto3"

var (
	file_KtClientApi_proto_rawDescOnce sync.Once
	file_KtClientApi_proto_rawDescData []byte
)

func file_KtClientApi_proto_rawDescGZIP() []byte {
	file_KtClientApi_proto_rawDescOnce.Do(func() {
		file_KtClientApi_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_KtClientApi_proto_rawDesc), len(file_KtClientApi_proto_rawDesc)))
	})
	return file_KtClientApi_proto_rawDescData
}

var file_KtClientApi_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_KtClientApi_proto_goTypes = []any{
	(*ConsistencyProofRequest)(nil),                         // 0: ConsistencyProofRequest
	(*ConsistencyProofResponse)(nil),                        // 1: ConsistencyProofResponse
	(*RevisionLogInclusionProofRequest)(nil),                // 2: RevisionLogInclusionProofRequest
	(*RevisionLogInclusionProofResponse)(nil),               // 3: RevisionLogInclusionProofResponse
	(*PublicKeysRequest)(nil),                               // 4: PublicKeysRequest
	(*PublicKeysResponse)(nil),                              // 5: PublicKeysResponse
	(*ConsistencyProofRequest_LogConsistencyRequest)(nil),   // 6: ConsistencyProofRequest.LogConsistencyRequest
	(*ConsistencyProofResponse_LogConsistencyResponse)(nil), // 7: ConsistencyProofResponse.LogConsistencyResponse
	(ProtocolVersion)(0),                                    // 8: ProtocolVersion
	(LogType)(0),                                            // 9: LogType
	(Application)(0),                                        // 10: Application
	(Status)(0),                                             // 11: Status
	(*LogEntry)(nil),                                        // 12: LogEntry
	(*PatInclusionProof)(nil),                               // 13: PatInclusionProof
	(*SignedObject)(nil),                                    // 14: SignedObject
}
var file_KtClientApi_proto_depIdxs = []int32{
	8,  // 0: ConsistencyProofRequest.version:type_name -> ProtocolVersion
	6,  // 1: ConsistencyProofRequest.requests:type_name -> ConsistencyProofRequest.LogConsistencyRequest
	9,  // 2: ConsistencyProofRequest.logType:type_name -> LogType
	10, // 3: ConsistencyProofRequest.application:type_name -> Application
	11, // 4: ConsistencyProofResponse.status:type_name -> Status
	7,  // 5: ConsistencyProofResponse.responses:type_name -> ConsistencyProofResponse.LogConsistencyResponse
	9,  // 6: ConsistencyProofResponse.logType:type_name -> LogType
	10, // 7: ConsistencyProofResponse.application:type_name -> Application
	8,  // 8: RevisionLogInclusionProofRequest.version:type_name -> ProtocolVersion
	10, // 9: RevisionLogInclusionProofRequest.application:type_name -> Application
	9,  // 10: RevisionLogInclusionProofRequest.logType:type_name -> LogType
	11, // 11: RevisionLogInclusionProofResponse.status:type_name -> Status
	12, // 12: RevisionLogInclusionProofResponse.logEntry:type_name -> LogEntry
	12, // 13: RevisionLogInclusionProofResponse.topLevelTreeEntry:type_name -> LogEntry
	8,  // 14: PublicKeysRequest.version:type_name -> ProtocolVersion
	10, // 15: PublicKeysRequest.application:type_name -> Application
	11, // 16: PublicKeysResponse.status:type_name -> Status
	13, // 17: PublicKeysResponse.patConfigProof:type_name -> PatInclusionProof
	12, // 18: PublicKeysResponse.tltConfigProof:type_name -> LogEntry
	13, // 19: PublicKeysResponse.patClosedProof:type_name -> PatInclusionProof
	12, // 20: PublicKeysResponse.pamHeadInPatProof:type_name -> LogEntry
	14, // 21: ConsistencyProofResponse.LogConsistencyResponse.startSLH:type_name -> SignedObject
	14, // 22: ConsistencyProofResponse.LogConsistencyResponse.endSLH:type_name -> SignedObject
	23, // [23:23] is the sub-list for method output_type
	23, // [23:23] is the sub-list for method input_type
	23, // [23:23] is the sub-list for extension type_name
	23, // [23:23] is the sub-list for extension extendee
	0,  // [0:23] is the sub-list for field type_name
}

func init() { file_KtClientApi_proto_init() }
func file_KtClientApi_proto_init() {
	if File_KtClientApi_proto != nil {
		return
	}
	file_Transparency_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeFor[x]().PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_KtClientApi_proto_rawDesc), len(file_KtClientApi_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_KtClientApi_proto_goTypes,
		DependencyIndexes: file_KtClientApi_proto_depIdxs,
		MessageInfos:      file_KtClientApi_proto_msgTypes,
	}.Build()
	File_KtClientApi_proto = out.File
	file_KtClientApi_proto_goTypes = nil
	file_KtClientApi_proto_depIdxs = nil
}
