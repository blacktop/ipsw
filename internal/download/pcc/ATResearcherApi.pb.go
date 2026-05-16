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

type ATLogInclusionProofRequest struct {
	state       protoimpl.MessageState `protogen:"open.v1"`
	Version     ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	Application Application            `protobuf:"varint,2,opt,name=application,proto3,enum=Application" json:"application,omitempty"`
	// These are the SHA256 hash of the logged data.
	// If the same data has been inserted multiple times, this will return the latest entry.
	Identifier    [][]byte `protobuf:"bytes,3,rep,name=identifier,proto3" json:"identifier,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ATLogInclusionProofRequest) Reset() {
	*x = ATLogInclusionProofRequest{}
	mi := &file_ATResearcherApi_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ATLogInclusionProofRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ATLogInclusionProofRequest) ProtoMessage() {}

func (x *ATLogInclusionProofRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ATResearcherApi_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ATLogInclusionProofRequest.ProtoReflect.Descriptor instead.
func (*ATLogInclusionProofRequest) Descriptor() ([]byte, []int) {
	return file_ATResearcherApi_proto_rawDescGZIP(), []int{0}
}

func (x *ATLogInclusionProofRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *ATLogInclusionProofRequest) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *ATLogInclusionProofRequest) GetIdentifier() [][]byte {
	if x != nil {
		return x.Identifier
	}
	return nil
}

type ATLogInclusionProofResponse struct {
	state  protoimpl.MessageState `protogen:"open.v1"`
	Status Status                 `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"` // OK, INVALID_REQUEST, or INTERNAL_ERROR
	// root under which all leaves are proven
	Slh *SignedObject `protobuf:"bytes,2,opt,name=slh,proto3" json:"slh,omitempty"`
	// not guaranteed to have every requested proof
	// all these proofs will be under the same log head, sorted by leaf index
	Leaves        []*ATLogInclusionProofResponse_Leaf `protobuf:"bytes,3,rep,name=leaves,proto3" json:"leaves,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ATLogInclusionProofResponse) Reset() {
	*x = ATLogInclusionProofResponse{}
	mi := &file_ATResearcherApi_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ATLogInclusionProofResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ATLogInclusionProofResponse) ProtoMessage() {}

func (x *ATLogInclusionProofResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ATResearcherApi_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ATLogInclusionProofResponse.ProtoReflect.Descriptor instead.
func (*ATLogInclusionProofResponse) Descriptor() ([]byte, []int) {
	return file_ATResearcherApi_proto_rawDescGZIP(), []int{1}
}

func (x *ATLogInclusionProofResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *ATLogInclusionProofResponse) GetSlh() *SignedObject {
	if x != nil {
		return x.Slh
	}
	return nil
}

func (x *ATLogInclusionProofResponse) GetLeaves() []*ATLogInclusionProofResponse_Leaf {
	if x != nil {
		return x.Leaves
	}
	return nil
}

type ATLogInclusionProofResponse_Leaf struct {
	state                     protoimpl.MessageState `protogen:"open.v1"`
	NodeType                  NodeType               `protobuf:"varint,1,opt,name=nodeType,proto3,enum=NodeType" json:"nodeType,omitempty"` // always NodeType.ATL_NODE (ChangeLogNodeV2 with an ATLeafData struct)
	NodeBytes                 []byte                 `protobuf:"bytes,2,opt,name=nodeBytes,proto3" json:"nodeBytes,omitempty"`
	NodePosition              uint64                 `protobuf:"varint,3,opt,name=nodePosition,proto3" json:"nodePosition,omitempty"`                          // in range [0, slh.logSize)
	HashesOfPeersInPathToRoot [][]byte               `protobuf:"bytes,4,rep,name=hashesOfPeersInPathToRoot,proto3" json:"hashesOfPeersInPathToRoot,omitempty"` // Path to slh above. Ordered with leaf at 0, root-1 at end
	RawData                   []byte                 `protobuf:"bytes,5,opt,name=rawData,proto3" json:"rawData,omitempty"`
	Metadata                  []byte                 `protobuf:"bytes,6,opt,name=metadata,proto3" json:"metadata,omitempty"`
	unknownFields             protoimpl.UnknownFields
	sizeCache                 protoimpl.SizeCache
}

func (x *ATLogInclusionProofResponse_Leaf) Reset() {
	*x = ATLogInclusionProofResponse_Leaf{}
	mi := &file_ATResearcherApi_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ATLogInclusionProofResponse_Leaf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ATLogInclusionProofResponse_Leaf) ProtoMessage() {}

func (x *ATLogInclusionProofResponse_Leaf) ProtoReflect() protoreflect.Message {
	mi := &file_ATResearcherApi_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ATLogInclusionProofResponse_Leaf.ProtoReflect.Descriptor instead.
func (*ATLogInclusionProofResponse_Leaf) Descriptor() ([]byte, []int) {
	return file_ATResearcherApi_proto_rawDescGZIP(), []int{1, 0}
}

func (x *ATLogInclusionProofResponse_Leaf) GetNodeType() NodeType {
	if x != nil {
		return x.NodeType
	}
	return NodeType_PACL_NODE
}

func (x *ATLogInclusionProofResponse_Leaf) GetNodeBytes() []byte {
	if x != nil {
		return x.NodeBytes
	}
	return nil
}

func (x *ATLogInclusionProofResponse_Leaf) GetNodePosition() uint64 {
	if x != nil {
		return x.NodePosition
	}
	return 0
}

func (x *ATLogInclusionProofResponse_Leaf) GetHashesOfPeersInPathToRoot() [][]byte {
	if x != nil {
		return x.HashesOfPeersInPathToRoot
	}
	return nil
}

func (x *ATLogInclusionProofResponse_Leaf) GetRawData() []byte {
	if x != nil {
		return x.RawData
	}
	return nil
}

func (x *ATLogInclusionProofResponse_Leaf) GetMetadata() []byte {
	if x != nil {
		return x.Metadata
	}
	return nil
}

var File_ATResearcherApi_proto protoreflect.FileDescriptor

const file_ATResearcherApi_proto_rawDesc = "" +
	"\n" +
	"\x15ATResearcherApi.proto\x1a\x12Transparency.proto\x1a\x12ATServiceApi.proto\x1a\x11KtClientApi.proto\x1a\x10AuditorApi.proto\"\x98\x01\n" +
	"\x1aATLogInclusionProofRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12.\n" +
	"\vapplication\x18\x02 \x01(\x0e2\f.ApplicationR\vapplication\x12\x1e\n" +
	"\n" +
	"identifier\x18\x03 \x03(\fR\n" +
	"identifier\"\x80\x03\n" +
	"\x1bATLogInclusionProofResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12\x1f\n" +
	"\x03slh\x18\x02 \x01(\v2\r.SignedObjectR\x03slh\x129\n" +
	"\x06leaves\x18\x03 \x03(\v2!.ATLogInclusionProofResponse.LeafR\x06leaves\x1a\xe3\x01\n" +
	"\x04Leaf\x12%\n" +
	"\bnodeType\x18\x01 \x01(\x0e2\t.NodeTypeR\bnodeType\x12\x1c\n" +
	"\tnodeBytes\x18\x02 \x01(\fR\tnodeBytes\x12\"\n" +
	"\fnodePosition\x18\x03 \x01(\x04R\fnodePosition\x12<\n" +
	"\x19hashesOfPeersInPathToRoot\x18\x04 \x03(\fR\x19hashesOfPeersInPathToRoot\x12\x18\n" +
	"\arawData\x18\x05 \x01(\fR\arawData\x12\x1a\n" +
	"\bmetadata\x18\x06 \x01(\fR\bmetadataBb\n" +
	"\x15com.apple.keyt.api.atB\x0fATResearcherApiP\x01Z.github.com/blacktop/ipsw/internal/download/pcc\xba\x02\x05TxPB_b\x06proto3"

var (
	file_ATResearcherApi_proto_rawDescOnce sync.Once
	file_ATResearcherApi_proto_rawDescData []byte
)

func file_ATResearcherApi_proto_rawDescGZIP() []byte {
	file_ATResearcherApi_proto_rawDescOnce.Do(func() {
		file_ATResearcherApi_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_ATResearcherApi_proto_rawDesc), len(file_ATResearcherApi_proto_rawDesc)))
	})
	return file_ATResearcherApi_proto_rawDescData
}

var file_ATResearcherApi_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_ATResearcherApi_proto_goTypes = []any{
	(*ATLogInclusionProofRequest)(nil),       // 0: ATLogInclusionProofRequest
	(*ATLogInclusionProofResponse)(nil),      // 1: ATLogInclusionProofResponse
	(*ATLogInclusionProofResponse_Leaf)(nil), // 2: ATLogInclusionProofResponse.Leaf
	(ProtocolVersion)(0),                     // 3: ProtocolVersion
	(Application)(0),                         // 4: Application
	(Status)(0),                              // 5: Status
	(*SignedObject)(nil),                     // 6: SignedObject
	(NodeType)(0),                            // 7: NodeType
}
var file_ATResearcherApi_proto_depIdxs = []int32{
	3, // 0: ATLogInclusionProofRequest.version:type_name -> ProtocolVersion
	4, // 1: ATLogInclusionProofRequest.application:type_name -> Application
	5, // 2: ATLogInclusionProofResponse.status:type_name -> Status
	6, // 3: ATLogInclusionProofResponse.slh:type_name -> SignedObject
	2, // 4: ATLogInclusionProofResponse.leaves:type_name -> ATLogInclusionProofResponse.Leaf
	7, // 5: ATLogInclusionProofResponse.Leaf.nodeType:type_name -> NodeType
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_ATResearcherApi_proto_init() }
func file_ATResearcherApi_proto_init() {
	if File_ATResearcherApi_proto != nil {
		return
	}
	file_Transparency_proto_init()
	file_ATServiceApi_proto_init()
	file_KtClientApi_proto_init()
	file_AuditorApi_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_ATResearcherApi_proto_rawDesc), len(file_ATResearcherApi_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ATResearcherApi_proto_goTypes,
		DependencyIndexes: file_ATResearcherApi_proto_depIdxs,
		MessageInfos:      file_ATResearcherApi_proto_msgTypes,
	}.Build()
	File_ATResearcherApi_proto = out.File
	file_ATResearcherApi_proto_goTypes = nil
	file_ATResearcherApi_proto_depIdxs = nil
}
