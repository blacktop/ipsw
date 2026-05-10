package iokit

import (
	"errors"
	"io"
)

const (
	KindMethod        = "iokit_method"
	KindServiceClient = "iokit_service_client"

	DispatchExternalMethod     = "IOExternalMethodDispatch"
	DispatchExternalMethod2022 = "IOExternalMethodDispatch2022"
	DispatchSwitch             = "switch"
	DispatchUnknown            = "unknown"

	SourceNewUserClient    = "newUserClient"
	SourceIOKitPersonality = "IOKitPersonality"
)

var ErrNoIOUserClients = errors.New("no IOUserClient subclasses discovered")

type Config struct {
	Kernelcache             string
	Stderr                  io.Writer
	MaxFunctionInstructions int
	MaxVtableSlots          int
}

type Record struct {
	Kind string

	Class             string
	Bundle            string
	Selector          int
	MethodSymbol      string
	MethodAddr        string
	DispatchKind      string
	ScalarInputCount  int64
	ScalarOutputCount int64
	StructInputSize   int64
	StructOutputSize  int64
	Flags             int64
	Resolved          bool
	Extra             map[string]string
	ServiceClass      string
	ServiceBundle     string
	UserClientClass   string
	UserClientBundle  string
	Source            string
}
