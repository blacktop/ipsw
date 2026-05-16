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

type ListTreesResponse_Tree_State int32

const (
	ListTreesResponse_Tree_UNKNOWN ListTreesResponse_Tree_State = 0
	ListTreesResponse_Tree_STAGED  ListTreesResponse_Tree_State = 1
	ListTreesResponse_Tree_ACTIVE  ListTreesResponse_Tree_State = 2
	ListTreesResponse_Tree_RETIRED ListTreesResponse_Tree_State = 3
)

// Enum value maps for ListTreesResponse_Tree_State.
var (
	ListTreesResponse_Tree_State_name = map[int32]string{
		0: "UNKNOWN",
		1: "STAGED",
		2: "ACTIVE",
		3: "RETIRED",
	}
	ListTreesResponse_Tree_State_value = map[string]int32{
		"UNKNOWN": 0,
		"STAGED":  1,
		"ACTIVE":  2,
		"RETIRED": 3,
	}
)

func (x ListTreesResponse_Tree_State) Enum() *ListTreesResponse_Tree_State {
	p := new(ListTreesResponse_Tree_State)
	*p = x
	return p
}

func (x ListTreesResponse_Tree_State) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ListTreesResponse_Tree_State) Descriptor() protoreflect.EnumDescriptor {
	return file_AuditorApi_proto_enumTypes[0].Descriptor()
}

func (ListTreesResponse_Tree_State) Type() protoreflect.EnumType {
	return &file_AuditorApi_proto_enumTypes[0]
}

func (x ListTreesResponse_Tree_State) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ListTreesResponse_Tree_State.Descriptor instead.
func (ListTreesResponse_Tree_State) EnumDescriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{1, 0, 0}
}

type ListTreesRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Version       ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	RequestUuid   string                 `protobuf:"bytes,2,opt,name=requestUuid,proto3" json:"requestUuid,omitempty"` // Used for logging
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListTreesRequest) Reset() {
	*x = ListTreesRequest{}
	mi := &file_AuditorApi_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListTreesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListTreesRequest) ProtoMessage() {}

func (x *ListTreesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListTreesRequest.ProtoReflect.Descriptor instead.
func (*ListTreesRequest) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{0}
}

func (x *ListTreesRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *ListTreesRequest) GetRequestUuid() string {
	if x != nil {
		return x.RequestUuid
	}
	return ""
}

type ListTreesResponse struct {
	state         protoimpl.MessageState    `protogen:"open.v1"`
	Status        Status                    `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	Trees         []*ListTreesResponse_Tree `protobuf:"bytes,2,rep,name=trees,proto3" json:"trees,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListTreesResponse) Reset() {
	*x = ListTreesResponse{}
	mi := &file_AuditorApi_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListTreesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListTreesResponse) ProtoMessage() {}

func (x *ListTreesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListTreesResponse.ProtoReflect.Descriptor instead.
func (*ListTreesResponse) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{1}
}

func (x *ListTreesResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *ListTreesResponse) GetTrees() []*ListTreesResponse_Tree {
	if x != nil {
		return x.Trees
	}
	return nil
}

type LogLeavesRequest struct {
	state   protoimpl.MessageState `protogen:"open.v1"`
	Version ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	TreeId  uint64                 `protobuf:"varint,2,opt,name=treeId,proto3" json:"treeId,omitempty"`
	// 3 -- can reuse
	StartIndex      uint64 `protobuf:"varint,4,opt,name=startIndex,proto3" json:"startIndex,omitempty"`
	EndIndex        uint64 `protobuf:"varint,5,opt,name=endIndex,proto3" json:"endIndex,omitempty"`      // Exclusive
	RequestUuid     string `protobuf:"bytes,6,opt,name=requestUuid,proto3" json:"requestUuid,omitempty"` // Used for logging
	StartMergeGroup uint32 `protobuf:"varint,7,opt,name=startMergeGroup,proto3" json:"startMergeGroup,omitempty"`
	EndMergeGroup   uint32 `protobuf:"varint,8,opt,name=endMergeGroup,proto3" json:"endMergeGroup,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *LogLeavesRequest) Reset() {
	*x = LogLeavesRequest{}
	mi := &file_AuditorApi_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogLeavesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogLeavesRequest) ProtoMessage() {}

func (x *LogLeavesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogLeavesRequest.ProtoReflect.Descriptor instead.
func (*LogLeavesRequest) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{2}
}

func (x *LogLeavesRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *LogLeavesRequest) GetTreeId() uint64 {
	if x != nil {
		return x.TreeId
	}
	return 0
}

func (x *LogLeavesRequest) GetStartIndex() uint64 {
	if x != nil {
		return x.StartIndex
	}
	return 0
}

func (x *LogLeavesRequest) GetEndIndex() uint64 {
	if x != nil {
		return x.EndIndex
	}
	return 0
}

func (x *LogLeavesRequest) GetRequestUuid() string {
	if x != nil {
		return x.RequestUuid
	}
	return ""
}

func (x *LogLeavesRequest) GetStartMergeGroup() uint32 {
	if x != nil {
		return x.StartMergeGroup
	}
	return 0
}

func (x *LogLeavesRequest) GetEndMergeGroup() uint32 {
	if x != nil {
		return x.EndMergeGroup
	}
	return 0
}

type LogLeavesResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Return NOT_FOUND if any leaves in requested range do not exist.
	// Return INVALID_REQUEST if merge group range is invalid
	Status Status `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	// 2 - can reuse
	Leaves        []*LogLeavesResponse_Leaf `protobuf:"bytes,3,rep,name=leaves,proto3" json:"leaves,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogLeavesResponse) Reset() {
	*x = LogLeavesResponse{}
	mi := &file_AuditorApi_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogLeavesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogLeavesResponse) ProtoMessage() {}

func (x *LogLeavesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogLeavesResponse.ProtoReflect.Descriptor instead.
func (*LogLeavesResponse) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{3}
}

func (x *LogLeavesResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *LogLeavesResponse) GetLeaves() []*LogLeavesResponse_Leaf {
	if x != nil {
		return x.Leaves
	}
	return nil
}

type LogLeavesForRevisionRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Version       ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	LogType       LogType                `protobuf:"varint,2,opt,name=logType,proto3,enum=LogType" json:"logType,omitempty"` // must be PER_APPLICATION_TREE or TOP_LEVEL_TREE
	Application   Application            `protobuf:"varint,3,opt,name=application,proto3,enum=Application" json:"application,omitempty"`
	Revision      uint64                 `protobuf:"varint,4,opt,name=revision,proto3" json:"revision,omitempty"`      // Set to -1 to request latest revision
	RequestUuid   string                 `protobuf:"bytes,5,opt,name=requestUuid,proto3" json:"requestUuid,omitempty"` // Used for logging
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogLeavesForRevisionRequest) Reset() {
	*x = LogLeavesForRevisionRequest{}
	mi := &file_AuditorApi_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogLeavesForRevisionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogLeavesForRevisionRequest) ProtoMessage() {}

func (x *LogLeavesForRevisionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogLeavesForRevisionRequest.ProtoReflect.Descriptor instead.
func (*LogLeavesForRevisionRequest) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{4}
}

func (x *LogLeavesForRevisionRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *LogLeavesForRevisionRequest) GetLogType() LogType {
	if x != nil {
		return x.LogType
	}
	return LogType_UNKNOWN_LOG
}

func (x *LogLeavesForRevisionRequest) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *LogLeavesForRevisionRequest) GetRevision() uint64 {
	if x != nil {
		return x.Revision
	}
	return 0
}

func (x *LogLeavesForRevisionRequest) GetRequestUuid() string {
	if x != nil {
		return x.RequestUuid
	}
	return ""
}

type LogLeavesForRevisionResponse struct {
	state         protoimpl.MessageState               `protogen:"open.v1"`
	Status        Status                               `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"` // Returns NOT_FOUND if revision does not exist.
	Slh           *SignedObject                        `protobuf:"bytes,2,opt,name=slh,proto3" json:"slh,omitempty"`                    // for requested revision. Inclusion proofs will use this root.
	Leaves        []*LogLeavesForRevisionResponse_Leaf `protobuf:"bytes,3,rep,name=leaves,proto3" json:"leaves,omitempty"`              // not guaranteed to be in order.
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogLeavesForRevisionResponse) Reset() {
	*x = LogLeavesForRevisionResponse{}
	mi := &file_AuditorApi_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogLeavesForRevisionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogLeavesForRevisionResponse) ProtoMessage() {}

func (x *LogLeavesForRevisionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogLeavesForRevisionResponse.ProtoReflect.Descriptor instead.
func (*LogLeavesForRevisionResponse) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{5}
}

func (x *LogLeavesForRevisionResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *LogLeavesForRevisionResponse) GetSlh() *SignedObject {
	if x != nil {
		return x.Slh
	}
	return nil
}

func (x *LogLeavesForRevisionResponse) GetLeaves() []*LogLeavesForRevisionResponse_Leaf {
	if x != nil {
		return x.Leaves
	}
	return nil
}

type LogHeadRequest struct {
	state   protoimpl.MessageState `protogen:"open.v1"`
	Version ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	TreeId  uint64                 `protobuf:"varint,2,opt,name=treeId,proto3" json:"treeId,omitempty"`
	// 3 -- can reuse
	Revision      int64  `protobuf:"varint,4,opt,name=revision,proto3" json:"revision,omitempty"`      // Set to -1 to request latest revision
	RequestUuid   string `protobuf:"bytes,5,opt,name=requestUuid,proto3" json:"requestUuid,omitempty"` // Used for logging
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogHeadRequest) Reset() {
	*x = LogHeadRequest{}
	mi := &file_AuditorApi_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogHeadRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogHeadRequest) ProtoMessage() {}

func (x *LogHeadRequest) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogHeadRequest.ProtoReflect.Descriptor instead.
func (*LogHeadRequest) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{6}
}

func (x *LogHeadRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *LogHeadRequest) GetTreeId() uint64 {
	if x != nil {
		return x.TreeId
	}
	return 0
}

func (x *LogHeadRequest) GetRevision() int64 {
	if x != nil {
		return x.Revision
	}
	return 0
}

func (x *LogHeadRequest) GetRequestUuid() string {
	if x != nil {
		return x.RequestUuid
	}
	return ""
}

type LogHeadResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Status        Status                 `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	LogHead       *SignedObject          `protobuf:"bytes,4,opt,name=logHead,proto3" json:"logHead,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogHeadResponse) Reset() {
	*x = LogHeadResponse{}
	mi := &file_AuditorApi_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogHeadResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogHeadResponse) ProtoMessage() {}

func (x *LogHeadResponse) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogHeadResponse.ProtoReflect.Descriptor instead.
func (*LogHeadResponse) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{7}
}

func (x *LogHeadResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *LogHeadResponse) GetLogHead() *SignedObject {
	if x != nil {
		return x.LogHead
	}
	return nil
}

type MapHeadRequest struct {
	state   protoimpl.MessageState `protogen:"open.v1"`
	Version ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	TreeId  uint64                 `protobuf:"varint,2,opt,name=treeId,proto3" json:"treeId,omitempty"`
	// 3 -- can reuse
	Revision      int64  `protobuf:"varint,4,opt,name=revision,proto3" json:"revision,omitempty"`      // Set to -1 to request latest revision
	RequestUuid   string `protobuf:"bytes,5,opt,name=requestUuid,proto3" json:"requestUuid,omitempty"` // Used for logging
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MapHeadRequest) Reset() {
	*x = MapHeadRequest{}
	mi := &file_AuditorApi_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MapHeadRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MapHeadRequest) ProtoMessage() {}

func (x *MapHeadRequest) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MapHeadRequest.ProtoReflect.Descriptor instead.
func (*MapHeadRequest) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{8}
}

func (x *MapHeadRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *MapHeadRequest) GetTreeId() uint64 {
	if x != nil {
		return x.TreeId
	}
	return 0
}

func (x *MapHeadRequest) GetRevision() int64 {
	if x != nil {
		return x.Revision
	}
	return 0
}

func (x *MapHeadRequest) GetRequestUuid() string {
	if x != nil {
		return x.RequestUuid
	}
	return ""
}

type MapHeadResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Status        Status                 `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	Smh           *SignedObject          `protobuf:"bytes,2,opt,name=smh,proto3" json:"smh,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MapHeadResponse) Reset() {
	*x = MapHeadResponse{}
	mi := &file_AuditorApi_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MapHeadResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MapHeadResponse) ProtoMessage() {}

func (x *MapHeadResponse) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MapHeadResponse.ProtoReflect.Descriptor instead.
func (*MapHeadResponse) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{9}
}

func (x *MapHeadResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *MapHeadResponse) GetSmh() *SignedObject {
	if x != nil {
		return x.Smh
	}
	return nil
}

type MapNodeRequest struct {
	state   protoimpl.MessageState `protogen:"open.v1"`
	Version ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	TreeId  uint64                 `protobuf:"varint,2,opt,name=treeId,proto3" json:"treeId,omitempty"`
	// 3 -- can reuse
	Path  []byte `protobuf:"bytes,4,opt,name=path,proto3" json:"path,omitempty"`    // Must have at least depth bits, may be longer
	Depth uint32 `protobuf:"varint,5,opt,name=depth,proto3" json:"depth,omitempty"` // Top-down: 0 is root level, 255 is leaf level
	// Request for revision 'i' will return version of node with highest revision less than or equal to 'i'
	Revision      uint64 `protobuf:"varint,6,opt,name=revision,proto3" json:"revision,omitempty"`
	RequestUuid   string `protobuf:"bytes,7,opt,name=requestUuid,proto3" json:"requestUuid,omitempty"` // Used for logging
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MapNodeRequest) Reset() {
	*x = MapNodeRequest{}
	mi := &file_AuditorApi_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MapNodeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MapNodeRequest) ProtoMessage() {}

func (x *MapNodeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MapNodeRequest.ProtoReflect.Descriptor instead.
func (*MapNodeRequest) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{10}
}

func (x *MapNodeRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *MapNodeRequest) GetTreeId() uint64 {
	if x != nil {
		return x.TreeId
	}
	return 0
}

func (x *MapNodeRequest) GetPath() []byte {
	if x != nil {
		return x.Path
	}
	return nil
}

func (x *MapNodeRequest) GetDepth() uint32 {
	if x != nil {
		return x.Depth
	}
	return 0
}

func (x *MapNodeRequest) GetRevision() uint64 {
	if x != nil {
		return x.Revision
	}
	return 0
}

func (x *MapNodeRequest) GetRequestUuid() string {
	if x != nil {
		return x.RequestUuid
	}
	return ""
}

type MapNodeResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Return NOT_FOUND if requested node does not exist in map for specified revision
	Status        Status `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"`
	Hash          []byte `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"`
	Value         []byte `protobuf:"bytes,3,opt,name=value,proto3" json:"value,omitempty"` // only present if this is a leaf node
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MapNodeResponse) Reset() {
	*x = MapNodeResponse{}
	mi := &file_AuditorApi_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MapNodeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MapNodeResponse) ProtoMessage() {}

func (x *MapNodeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MapNodeResponse.ProtoReflect.Descriptor instead.
func (*MapNodeResponse) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{11}
}

func (x *MapNodeResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *MapNodeResponse) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

func (x *MapNodeResponse) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

type PaclInclusionProofRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Version       ProtocolVersion        `protobuf:"varint,1,opt,name=version,proto3,enum=ProtocolVersion" json:"version,omitempty"`
	Application   Application            `protobuf:"varint,2,opt,name=application,proto3,enum=Application" json:"application,omitempty"`
	Smts          []*SignedObject        `protobuf:"bytes,3,rep,name=smts,proto3" json:"smts,omitempty"`
	RequestUuid   string                 `protobuf:"bytes,4,opt,name=requestUuid,proto3" json:"requestUuid,omitempty"` // Used for logging
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PaclInclusionProofRequest) Reset() {
	*x = PaclInclusionProofRequest{}
	mi := &file_AuditorApi_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PaclInclusionProofRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PaclInclusionProofRequest) ProtoMessage() {}

func (x *PaclInclusionProofRequest) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PaclInclusionProofRequest.ProtoReflect.Descriptor instead.
func (*PaclInclusionProofRequest) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{12}
}

func (x *PaclInclusionProofRequest) GetVersion() ProtocolVersion {
	if x != nil {
		return x.Version
	}
	return ProtocolVersion_UNKNOWN_VERSION
}

func (x *PaclInclusionProofRequest) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *PaclInclusionProofRequest) GetSmts() []*SignedObject {
	if x != nil {
		return x.Smts
	}
	return nil
}

func (x *PaclInclusionProofRequest) GetRequestUuid() string {
	if x != nil {
		return x.RequestUuid
	}
	return ""
}

type PaclInclusionProofResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Status        Status                 `protobuf:"varint,1,opt,name=status,proto3,enum=Status" json:"status,omitempty"` // OK, INVALID_REQUEST, or INTERNAL_ERROR
	LogEntry      []*LogEntry            `protobuf:"bytes,2,rep,name=logEntry,proto3" json:"logEntry,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PaclInclusionProofResponse) Reset() {
	*x = PaclInclusionProofResponse{}
	mi := &file_AuditorApi_proto_msgTypes[13]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PaclInclusionProofResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PaclInclusionProofResponse) ProtoMessage() {}

func (x *PaclInclusionProofResponse) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[13]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PaclInclusionProofResponse.ProtoReflect.Descriptor instead.
func (*PaclInclusionProofResponse) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{13}
}

func (x *PaclInclusionProofResponse) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN_STATUS
}

func (x *PaclInclusionProofResponse) GetLogEntry() []*LogEntry {
	if x != nil {
		return x.LogEntry
	}
	return nil
}

type ListTreesResponse_Tree struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	TreeId         uint64                 `protobuf:"varint,1,opt,name=treeId,proto3" json:"treeId,omitempty"`
	LogBeginningMs uint64                 `protobuf:"varint,2,opt,name=logBeginningMs,proto3" json:"logBeginningMs,omitempty"`
	// Types that are valid to be assigned to Type:
	//
	//	*ListTreesResponse_Tree_LogType
	//	*ListTreesResponse_Tree_MapType
	Type           isListTreesResponse_Tree_Type `protobuf_oneof:"Type"`
	Application    Application                   `protobuf:"varint,5,opt,name=application,proto3,enum=Application" json:"application,omitempty"` // will be null if LogType is Top-level Tree
	State          ListTreesResponse_Tree_State  `protobuf:"varint,6,opt,name=state,proto3,enum=ListTreesResponse_Tree_State" json:"state,omitempty"`
	MergeGroups    uint64                        `protobuf:"varint,7,opt,name=mergeGroups,proto3" json:"mergeGroups,omitempty"`      // only present for Logs
	PublicKeyBytes []byte                        `protobuf:"bytes,8,opt,name=publicKeyBytes,proto3" json:"publicKeyBytes,omitempty"` // public key for signing roots of all trees for this app, encoded in DER SPKI
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *ListTreesResponse_Tree) Reset() {
	*x = ListTreesResponse_Tree{}
	mi := &file_AuditorApi_proto_msgTypes[14]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListTreesResponse_Tree) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListTreesResponse_Tree) ProtoMessage() {}

func (x *ListTreesResponse_Tree) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[14]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListTreesResponse_Tree.ProtoReflect.Descriptor instead.
func (*ListTreesResponse_Tree) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{1, 0}
}

func (x *ListTreesResponse_Tree) GetTreeId() uint64 {
	if x != nil {
		return x.TreeId
	}
	return 0
}

func (x *ListTreesResponse_Tree) GetLogBeginningMs() uint64 {
	if x != nil {
		return x.LogBeginningMs
	}
	return 0
}

func (x *ListTreesResponse_Tree) GetType() isListTreesResponse_Tree_Type {
	if x != nil {
		return x.Type
	}
	return nil
}

func (x *ListTreesResponse_Tree) GetLogType() LogType {
	if x != nil {
		if x, ok := x.Type.(*ListTreesResponse_Tree_LogType); ok {
			return x.LogType
		}
	}
	return LogType_UNKNOWN_LOG
}

func (x *ListTreesResponse_Tree) GetMapType() MapType {
	if x != nil {
		if x, ok := x.Type.(*ListTreesResponse_Tree_MapType); ok {
			return x.MapType
		}
	}
	return MapType_UNKNOWN_MAP
}

func (x *ListTreesResponse_Tree) GetApplication() Application {
	if x != nil {
		return x.Application
	}
	return Application_UNKNOWN_APPLICATION
}

func (x *ListTreesResponse_Tree) GetState() ListTreesResponse_Tree_State {
	if x != nil {
		return x.State
	}
	return ListTreesResponse_Tree_UNKNOWN
}

func (x *ListTreesResponse_Tree) GetMergeGroups() uint64 {
	if x != nil {
		return x.MergeGroups
	}
	return 0
}

func (x *ListTreesResponse_Tree) GetPublicKeyBytes() []byte {
	if x != nil {
		return x.PublicKeyBytes
	}
	return nil
}

type isListTreesResponse_Tree_Type interface {
	isListTreesResponse_Tree_Type()
}

type ListTreesResponse_Tree_LogType struct {
	LogType LogType `protobuf:"varint,3,opt,name=logType,proto3,enum=LogType,oneof"`
}

type ListTreesResponse_Tree_MapType struct {
	MapType MapType `protobuf:"varint,4,opt,name=mapType,proto3,enum=MapType,oneof"`
}

func (*ListTreesResponse_Tree_LogType) isListTreesResponse_Tree_Type() {}

func (*ListTreesResponse_Tree_MapType) isListTreesResponse_Tree_Type() {}

type LogLeavesResponse_Leaf struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	NodeType      NodeType               `protobuf:"varint,1,opt,name=nodeType,proto3,enum=NodeType" json:"nodeType,omitempty"`
	NodeBytes     []byte                 `protobuf:"bytes,2,opt,name=nodeBytes,proto3" json:"nodeBytes,omitempty"` // parse as appropriate for nodeType
	Index         uint64                 `protobuf:"varint,3,opt,name=index,proto3" json:"index,omitempty"`        // 0-indexed
	MergeGroup    uint32                 `protobuf:"varint,4,opt,name=mergeGroup,proto3" json:"mergeGroup,omitempty"`
	RawData       []byte                 `protobuf:"bytes,5,opt,name=rawData,proto3" json:"rawData,omitempty"`   // only for AT leaves
	Metadata      []byte                 `protobuf:"bytes,6,opt,name=metadata,proto3" json:"metadata,omitempty"` // only for AT leaves
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogLeavesResponse_Leaf) Reset() {
	*x = LogLeavesResponse_Leaf{}
	mi := &file_AuditorApi_proto_msgTypes[15]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogLeavesResponse_Leaf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogLeavesResponse_Leaf) ProtoMessage() {}

func (x *LogLeavesResponse_Leaf) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[15]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogLeavesResponse_Leaf.ProtoReflect.Descriptor instead.
func (*LogLeavesResponse_Leaf) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{3, 0}
}

func (x *LogLeavesResponse_Leaf) GetNodeType() NodeType {
	if x != nil {
		return x.NodeType
	}
	return NodeType_PACL_NODE
}

func (x *LogLeavesResponse_Leaf) GetNodeBytes() []byte {
	if x != nil {
		return x.NodeBytes
	}
	return nil
}

func (x *LogLeavesResponse_Leaf) GetIndex() uint64 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *LogLeavesResponse_Leaf) GetMergeGroup() uint32 {
	if x != nil {
		return x.MergeGroup
	}
	return 0
}

func (x *LogLeavesResponse_Leaf) GetRawData() []byte {
	if x != nil {
		return x.RawData
	}
	return nil
}

func (x *LogLeavesResponse_Leaf) GetMetadata() []byte {
	if x != nil {
		return x.Metadata
	}
	return nil
}

type LogLeavesForRevisionResponse_Leaf struct {
	state                     protoimpl.MessageState `protogen:"open.v1"`
	NodeType                  NodeType               `protobuf:"varint,1,opt,name=nodeType,proto3,enum=NodeType" json:"nodeType,omitempty"`
	NodeBytes                 []byte                 `protobuf:"bytes,2,opt,name=nodeBytes,proto3" json:"nodeBytes,omitempty"`                                 // parse as appropriate for nodeType
	NodePosition              uint64                 `protobuf:"varint,3,opt,name=nodePosition,proto3" json:"nodePosition,omitempty"`                          // in range [0, slh.logSize)
	HashesOfPeersInPathToRoot [][]byte               `protobuf:"bytes,4,rep,name=hashesOfPeersInPathToRoot,proto3" json:"hashesOfPeersInPathToRoot,omitempty"` // Path to slh above. Ordered with leaf at 0, root-1 at end
	RawData                   []byte                 `protobuf:"bytes,5,opt,name=rawData,proto3" json:"rawData,omitempty"`                                     // only for AT leaves
	Metadata                  []byte                 `protobuf:"bytes,6,opt,name=metadata,proto3" json:"metadata,omitempty"`                                   // only for AT leaves
	unknownFields             protoimpl.UnknownFields
	sizeCache                 protoimpl.SizeCache
}

func (x *LogLeavesForRevisionResponse_Leaf) Reset() {
	*x = LogLeavesForRevisionResponse_Leaf{}
	mi := &file_AuditorApi_proto_msgTypes[16]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogLeavesForRevisionResponse_Leaf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogLeavesForRevisionResponse_Leaf) ProtoMessage() {}

func (x *LogLeavesForRevisionResponse_Leaf) ProtoReflect() protoreflect.Message {
	mi := &file_AuditorApi_proto_msgTypes[16]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogLeavesForRevisionResponse_Leaf.ProtoReflect.Descriptor instead.
func (*LogLeavesForRevisionResponse_Leaf) Descriptor() ([]byte, []int) {
	return file_AuditorApi_proto_rawDescGZIP(), []int{5, 0}
}

func (x *LogLeavesForRevisionResponse_Leaf) GetNodeType() NodeType {
	if x != nil {
		return x.NodeType
	}
	return NodeType_PACL_NODE
}

func (x *LogLeavesForRevisionResponse_Leaf) GetNodeBytes() []byte {
	if x != nil {
		return x.NodeBytes
	}
	return nil
}

func (x *LogLeavesForRevisionResponse_Leaf) GetNodePosition() uint64 {
	if x != nil {
		return x.NodePosition
	}
	return 0
}

func (x *LogLeavesForRevisionResponse_Leaf) GetHashesOfPeersInPathToRoot() [][]byte {
	if x != nil {
		return x.HashesOfPeersInPathToRoot
	}
	return nil
}

func (x *LogLeavesForRevisionResponse_Leaf) GetRawData() []byte {
	if x != nil {
		return x.RawData
	}
	return nil
}

func (x *LogLeavesForRevisionResponse_Leaf) GetMetadata() []byte {
	if x != nil {
		return x.Metadata
	}
	return nil
}

var File_AuditorApi_proto protoreflect.FileDescriptor

const file_AuditorApi_proto_rawDesc = "" +
	"\n" +
	"\x10AuditorApi.proto\x1a\x12Transparency.proto\x1a\x11KtClientApi.proto\"`\n" +
	"\x10ListTreesRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12 \n" +
	"\vrequestUuid\x18\x02 \x01(\tR\vrequestUuid\"\xea\x03\n" +
	"\x11ListTreesResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12-\n" +
	"\x05trees\x18\x02 \x03(\v2\x17.ListTreesResponse.TreeR\x05trees\x1a\x84\x03\n" +
	"\x04Tree\x12\x16\n" +
	"\x06treeId\x18\x01 \x01(\x04R\x06treeId\x12&\n" +
	"\x0elogBeginningMs\x18\x02 \x01(\x04R\x0elogBeginningMs\x12$\n" +
	"\alogType\x18\x03 \x01(\x0e2\b.LogTypeH\x00R\alogType\x12$\n" +
	"\amapType\x18\x04 \x01(\x0e2\b.MapTypeH\x00R\amapType\x12.\n" +
	"\vapplication\x18\x05 \x01(\x0e2\f.ApplicationR\vapplication\x123\n" +
	"\x05state\x18\x06 \x01(\x0e2\x1d.ListTreesResponse.Tree.StateR\x05state\x12 \n" +
	"\vmergeGroups\x18\a \x01(\x04R\vmergeGroups\x12&\n" +
	"\x0epublicKeyBytes\x18\b \x01(\fR\x0epublicKeyBytes\"9\n" +
	"\x05State\x12\v\n" +
	"\aUNKNOWN\x10\x00\x12\n" +
	"\n" +
	"\x06STAGED\x10\x01\x12\n" +
	"\n" +
	"\x06ACTIVE\x10\x02\x12\v\n" +
	"\aRETIRED\x10\x03B\x06\n" +
	"\x04Type\"\x84\x02\n" +
	"\x10LogLeavesRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12\x16\n" +
	"\x06treeId\x18\x02 \x01(\x04R\x06treeId\x12\x1e\n" +
	"\n" +
	"startIndex\x18\x04 \x01(\x04R\n" +
	"startIndex\x12\x1a\n" +
	"\bendIndex\x18\x05 \x01(\x04R\bendIndex\x12 \n" +
	"\vrequestUuid\x18\x06 \x01(\tR\vrequestUuid\x12(\n" +
	"\x0fstartMergeGroup\x18\a \x01(\rR\x0fstartMergeGroup\x12$\n" +
	"\rendMergeGroup\x18\b \x01(\rR\rendMergeGroup\"\x9f\x02\n" +
	"\x11LogLeavesResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12/\n" +
	"\x06leaves\x18\x03 \x03(\v2\x17.LogLeavesResponse.LeafR\x06leaves\x1a\xb7\x01\n" +
	"\x04Leaf\x12%\n" +
	"\bnodeType\x18\x01 \x01(\x0e2\t.NodeTypeR\bnodeType\x12\x1c\n" +
	"\tnodeBytes\x18\x02 \x01(\fR\tnodeBytes\x12\x14\n" +
	"\x05index\x18\x03 \x01(\x04R\x05index\x12\x1e\n" +
	"\n" +
	"mergeGroup\x18\x04 \x01(\rR\n" +
	"mergeGroup\x12\x18\n" +
	"\arawData\x18\x05 \x01(\fR\arawData\x12\x1a\n" +
	"\bmetadata\x18\x06 \x01(\fR\bmetadata\"\xdb\x01\n" +
	"\x1bLogLeavesForRevisionRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12\"\n" +
	"\alogType\x18\x02 \x01(\x0e2\b.LogTypeR\alogType\x12.\n" +
	"\vapplication\x18\x03 \x01(\x0e2\f.ApplicationR\vapplication\x12\x1a\n" +
	"\brevision\x18\x04 \x01(\x04R\brevision\x12 \n" +
	"\vrequestUuid\x18\x05 \x01(\tR\vrequestUuid\"\x82\x03\n" +
	"\x1cLogLeavesForRevisionResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12\x1f\n" +
	"\x03slh\x18\x02 \x01(\v2\r.SignedObjectR\x03slh\x12:\n" +
	"\x06leaves\x18\x03 \x03(\v2\".LogLeavesForRevisionResponse.LeafR\x06leaves\x1a\xe3\x01\n" +
	"\x04Leaf\x12%\n" +
	"\bnodeType\x18\x01 \x01(\x0e2\t.NodeTypeR\bnodeType\x12\x1c\n" +
	"\tnodeBytes\x18\x02 \x01(\fR\tnodeBytes\x12\"\n" +
	"\fnodePosition\x18\x03 \x01(\x04R\fnodePosition\x12<\n" +
	"\x19hashesOfPeersInPathToRoot\x18\x04 \x03(\fR\x19hashesOfPeersInPathToRoot\x12\x18\n" +
	"\arawData\x18\x05 \x01(\fR\arawData\x12\x1a\n" +
	"\bmetadata\x18\x06 \x01(\fR\bmetadata\"\x92\x01\n" +
	"\x0eLogHeadRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12\x16\n" +
	"\x06treeId\x18\x02 \x01(\x04R\x06treeId\x12\x1a\n" +
	"\brevision\x18\x04 \x01(\x03R\brevision\x12 \n" +
	"\vrequestUuid\x18\x05 \x01(\tR\vrequestUuid\"[\n" +
	"\x0fLogHeadResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12'\n" +
	"\alogHead\x18\x04 \x01(\v2\r.SignedObjectR\alogHead\"\x92\x01\n" +
	"\x0eMapHeadRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12\x16\n" +
	"\x06treeId\x18\x02 \x01(\x04R\x06treeId\x12\x1a\n" +
	"\brevision\x18\x04 \x01(\x03R\brevision\x12 \n" +
	"\vrequestUuid\x18\x05 \x01(\tR\vrequestUuid\"S\n" +
	"\x0fMapHeadResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12\x1f\n" +
	"\x03smh\x18\x02 \x01(\v2\r.SignedObjectR\x03smh\"\xbc\x01\n" +
	"\x0eMapNodeRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12\x16\n" +
	"\x06treeId\x18\x02 \x01(\x04R\x06treeId\x12\x12\n" +
	"\x04path\x18\x04 \x01(\fR\x04path\x12\x14\n" +
	"\x05depth\x18\x05 \x01(\rR\x05depth\x12\x1a\n" +
	"\brevision\x18\x06 \x01(\x04R\brevision\x12 \n" +
	"\vrequestUuid\x18\a \x01(\tR\vrequestUuid\"\\\n" +
	"\x0fMapNodeResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12\x12\n" +
	"\x04hash\x18\x02 \x01(\fR\x04hash\x12\x14\n" +
	"\x05value\x18\x03 \x01(\fR\x05value\"\xbc\x01\n" +
	"\x19PaclInclusionProofRequest\x12*\n" +
	"\aversion\x18\x01 \x01(\x0e2\x10.ProtocolVersionR\aversion\x12.\n" +
	"\vapplication\x18\x02 \x01(\x0e2\f.ApplicationR\vapplication\x12!\n" +
	"\x04smts\x18\x03 \x03(\v2\r.SignedObjectR\x04smts\x12 \n" +
	"\vrequestUuid\x18\x04 \x01(\tR\vrequestUuid\"d\n" +
	"\x1aPaclInclusionProofResponse\x12\x1f\n" +
	"\x06status\x18\x01 \x01(\x0e2\a.StatusR\x06status\x12%\n" +
	"\blogEntry\x18\x02 \x03(\v2\t.LogEntryR\blogEntry2\xae\x04\n" +
	"\fKtAuditorApi\x12L\n" +
	"\x15auditConsistencyProof\x12\x18.ConsistencyProofRequest\x1a\x19.ConsistencyProofResponse\x12:\n" +
	"\x0fauditPublicKeys\x12\x12.PublicKeysRequest\x1a\x13.PublicKeysResponse\x122\n" +
	"\tlistTrees\x12\x11.ListTreesRequest\x1a\x12.ListTreesResponse\x122\n" +
	"\tlogLeaves\x12\x11.LogLeavesRequest\x1a\x12.LogLeavesResponse\x12S\n" +
	"\x14logLeavesForRevision\x12\x1c.LogLeavesForRevisionRequest\x1a\x1d.LogLeavesForRevisionResponse\x12,\n" +
	"\alogHead\x12\x0f.LogHeadRequest\x1a\x10.LogHeadResponse\x12,\n" +
	"\amapHead\x12\x0f.MapHeadRequest\x1a\x10.MapHeadResponse\x12,\n" +
	"\amapNode\x12\x0f.MapNodeRequest\x1a\x10.MapNodeResponse\x12M\n" +
	"\x12paclInclusionProof\x12\x1a.PaclInclusionProofRequest\x1a\x1b.PaclInclusionProofResponseBZ\n" +
	"\x12com.apple.keyt.apiB\n" +
	"AuditProtoP\x01Z.github.com/blacktop/ipsw/internal/download/pcc\xba\x02\x05TxPB_b\x06proto3"

var (
	file_AuditorApi_proto_rawDescOnce sync.Once
	file_AuditorApi_proto_rawDescData []byte
)

func file_AuditorApi_proto_rawDescGZIP() []byte {
	file_AuditorApi_proto_rawDescOnce.Do(func() {
		file_AuditorApi_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_AuditorApi_proto_rawDesc), len(file_AuditorApi_proto_rawDesc)))
	})
	return file_AuditorApi_proto_rawDescData
}

var file_AuditorApi_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_AuditorApi_proto_msgTypes = make([]protoimpl.MessageInfo, 17)
var file_AuditorApi_proto_goTypes = []any{
	(ListTreesResponse_Tree_State)(0),         // 0: ListTreesResponse.Tree.State
	(*ListTreesRequest)(nil),                  // 1: ListTreesRequest
	(*ListTreesResponse)(nil),                 // 2: ListTreesResponse
	(*LogLeavesRequest)(nil),                  // 3: LogLeavesRequest
	(*LogLeavesResponse)(nil),                 // 4: LogLeavesResponse
	(*LogLeavesForRevisionRequest)(nil),       // 5: LogLeavesForRevisionRequest
	(*LogLeavesForRevisionResponse)(nil),      // 6: LogLeavesForRevisionResponse
	(*LogHeadRequest)(nil),                    // 7: LogHeadRequest
	(*LogHeadResponse)(nil),                   // 8: LogHeadResponse
	(*MapHeadRequest)(nil),                    // 9: MapHeadRequest
	(*MapHeadResponse)(nil),                   // 10: MapHeadResponse
	(*MapNodeRequest)(nil),                    // 11: MapNodeRequest
	(*MapNodeResponse)(nil),                   // 12: MapNodeResponse
	(*PaclInclusionProofRequest)(nil),         // 13: PaclInclusionProofRequest
	(*PaclInclusionProofResponse)(nil),        // 14: PaclInclusionProofResponse
	(*ListTreesResponse_Tree)(nil),            // 15: ListTreesResponse.Tree
	(*LogLeavesResponse_Leaf)(nil),            // 16: LogLeavesResponse.Leaf
	(*LogLeavesForRevisionResponse_Leaf)(nil), // 17: LogLeavesForRevisionResponse.Leaf
	(ProtocolVersion)(0),                      // 18: ProtocolVersion
	(Status)(0),                               // 19: Status
	(LogType)(0),                              // 20: LogType
	(Application)(0),                          // 21: Application
	(*SignedObject)(nil),                      // 22: SignedObject
	(*LogEntry)(nil),                          // 23: LogEntry
	(MapType)(0),                              // 24: MapType
	(NodeType)(0),                             // 25: NodeType
	(*ConsistencyProofRequest)(nil),           // 26: ConsistencyProofRequest
	(*PublicKeysRequest)(nil),                 // 27: PublicKeysRequest
	(*ConsistencyProofResponse)(nil),          // 28: ConsistencyProofResponse
	(*PublicKeysResponse)(nil),                // 29: PublicKeysResponse
}
var file_AuditorApi_proto_depIdxs = []int32{
	18, // 0: ListTreesRequest.version:type_name -> ProtocolVersion
	19, // 1: ListTreesResponse.status:type_name -> Status
	15, // 2: ListTreesResponse.trees:type_name -> ListTreesResponse.Tree
	18, // 3: LogLeavesRequest.version:type_name -> ProtocolVersion
	19, // 4: LogLeavesResponse.status:type_name -> Status
	16, // 5: LogLeavesResponse.leaves:type_name -> LogLeavesResponse.Leaf
	18, // 6: LogLeavesForRevisionRequest.version:type_name -> ProtocolVersion
	20, // 7: LogLeavesForRevisionRequest.logType:type_name -> LogType
	21, // 8: LogLeavesForRevisionRequest.application:type_name -> Application
	19, // 9: LogLeavesForRevisionResponse.status:type_name -> Status
	22, // 10: LogLeavesForRevisionResponse.slh:type_name -> SignedObject
	17, // 11: LogLeavesForRevisionResponse.leaves:type_name -> LogLeavesForRevisionResponse.Leaf
	18, // 12: LogHeadRequest.version:type_name -> ProtocolVersion
	19, // 13: LogHeadResponse.status:type_name -> Status
	22, // 14: LogHeadResponse.logHead:type_name -> SignedObject
	18, // 15: MapHeadRequest.version:type_name -> ProtocolVersion
	19, // 16: MapHeadResponse.status:type_name -> Status
	22, // 17: MapHeadResponse.smh:type_name -> SignedObject
	18, // 18: MapNodeRequest.version:type_name -> ProtocolVersion
	19, // 19: MapNodeResponse.status:type_name -> Status
	18, // 20: PaclInclusionProofRequest.version:type_name -> ProtocolVersion
	21, // 21: PaclInclusionProofRequest.application:type_name -> Application
	22, // 22: PaclInclusionProofRequest.smts:type_name -> SignedObject
	19, // 23: PaclInclusionProofResponse.status:type_name -> Status
	23, // 24: PaclInclusionProofResponse.logEntry:type_name -> LogEntry
	20, // 25: ListTreesResponse.Tree.logType:type_name -> LogType
	24, // 26: ListTreesResponse.Tree.mapType:type_name -> MapType
	21, // 27: ListTreesResponse.Tree.application:type_name -> Application
	0,  // 28: ListTreesResponse.Tree.state:type_name -> ListTreesResponse.Tree.State
	25, // 29: LogLeavesResponse.Leaf.nodeType:type_name -> NodeType
	25, // 30: LogLeavesForRevisionResponse.Leaf.nodeType:type_name -> NodeType
	26, // 31: KtAuditorApi.auditConsistencyProof:input_type -> ConsistencyProofRequest
	27, // 32: KtAuditorApi.auditPublicKeys:input_type -> PublicKeysRequest
	1,  // 33: KtAuditorApi.listTrees:input_type -> ListTreesRequest
	3,  // 34: KtAuditorApi.logLeaves:input_type -> LogLeavesRequest
	5,  // 35: KtAuditorApi.logLeavesForRevision:input_type -> LogLeavesForRevisionRequest
	7,  // 36: KtAuditorApi.logHead:input_type -> LogHeadRequest
	9,  // 37: KtAuditorApi.mapHead:input_type -> MapHeadRequest
	11, // 38: KtAuditorApi.mapNode:input_type -> MapNodeRequest
	13, // 39: KtAuditorApi.paclInclusionProof:input_type -> PaclInclusionProofRequest
	28, // 40: KtAuditorApi.auditConsistencyProof:output_type -> ConsistencyProofResponse
	29, // 41: KtAuditorApi.auditPublicKeys:output_type -> PublicKeysResponse
	2,  // 42: KtAuditorApi.listTrees:output_type -> ListTreesResponse
	4,  // 43: KtAuditorApi.logLeaves:output_type -> LogLeavesResponse
	6,  // 44: KtAuditorApi.logLeavesForRevision:output_type -> LogLeavesForRevisionResponse
	8,  // 45: KtAuditorApi.logHead:output_type -> LogHeadResponse
	10, // 46: KtAuditorApi.mapHead:output_type -> MapHeadResponse
	12, // 47: KtAuditorApi.mapNode:output_type -> MapNodeResponse
	14, // 48: KtAuditorApi.paclInclusionProof:output_type -> PaclInclusionProofResponse
	40, // [40:49] is the sub-list for method output_type
	31, // [31:40] is the sub-list for method input_type
	31, // [31:31] is the sub-list for extension type_name
	31, // [31:31] is the sub-list for extension extendee
	0,  // [0:31] is the sub-list for field type_name
}

func init() { file_AuditorApi_proto_init() }
func file_AuditorApi_proto_init() {
	if File_AuditorApi_proto != nil {
		return
	}
	file_Transparency_proto_init()
	file_KtClientApi_proto_init()
	file_AuditorApi_proto_msgTypes[14].OneofWrappers = []any{
		(*ListTreesResponse_Tree_LogType)(nil),
		(*ListTreesResponse_Tree_MapType)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeFor[x]().PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_AuditorApi_proto_rawDesc), len(file_AuditorApi_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   17,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_AuditorApi_proto_goTypes,
		DependencyIndexes: file_AuditorApi_proto_depIdxs,
		EnumInfos:         file_AuditorApi_proto_enumTypes,
		MessageInfos:      file_AuditorApi_proto_msgTypes,
	}.Build()
	File_AuditorApi_proto = out.File
	file_AuditorApi_proto_goTypes = nil
	file_AuditorApi_proto_depIdxs = nil
}
