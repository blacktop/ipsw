package dyld

import "testing"

func TestParseWebKitIPCDescriptionString(t *testing.T) {
	receiver, message, ok := parseWebKitIPCDescriptionString("WebPage_LoadRequestWaitingForProcessLaunch")
	if !ok {
		t.Fatal("expected WebKit IPC description string")
	}
	if receiver != "WebPage" || message != "LoadRequestWaitingForProcessLaunch" {
		t.Fatalf("got %s/%s", receiver, message)
	}

	if _, _, ok := parseWebKitIPCDescriptionString("WebKit::WebPage::loadRequest"); ok {
		t.Fatal("expected C++ debug string to be rejected")
	}

	receiver, message, ok = parseWebKitIPCDescriptionString("WK_Foo_Bar")
	if !ok {
		t.Fatal("expected receiver with underscore to parse")
	}
	if receiver != "WK_Foo" || message != "Bar" {
		t.Fatalf("got %s/%s", receiver, message)
	}
}

func TestAddWebKitIPCSymbol(t *testing.T) {
	records := make(map[string]WebKitIPCRecord)
	addWebKitIPCSymbol(records, "__ZN8Messages7WebPage11LoadRequest6encodeEv", 0x1000)
	addWebKitIPCSymbol(records, "__ZN8Messages7WebPage11LoadRequest6decodeEv", 0x900)

	record, ok := records["WebPage_LoadRequest"]
	if !ok {
		t.Fatalf("missing WebPage_LoadRequest in %#v", records)
	}
	if record.Receiver != "WebPage" || record.Message != "LoadRequest" || record.SymbolAddress != 0x900 {
		t.Fatalf("unexpected record: %#v", record)
	}
	if len(record.Symbols) != 2 {
		t.Fatalf("symbols=%#v, want both encode and decode", record.Symbols)
	}
}

func TestWebKitIPCRecordMatches(t *testing.T) {
	record := WebKitIPCRecord{
		Receiver: "RemoteRenderingBackend",
		Message:  "CreateImageBuffer",
		Name:     "RemoteRenderingBackend_CreateImageBuffer",
	}

	if !webkitIPCRecordMatches(record, WebKitIPCConfig{ReceiverPattern: "Remote*", MessagePattern: "Create*"}) {
		t.Fatal("expected glob filters to match")
	}
	if webkitIPCRecordMatches(record, WebKitIPCConfig{ReceiverPattern: "WebPage"}) {
		t.Fatal("expected receiver filter to reject record")
	}
}

func TestWebKitIPCHandlerInfoParsesArgTypes(t *testing.T) {
	t.Parallel()

	symbol := "void IPC::handleMessage<Messages::GPUConnectionToWebProcess::CreateRenderingBackend, WebKit::GPUConnectionToWebProcess, void (WebKit::GPUConnectionToWebProcess::*)(WebKit::SharedMemory::Handle&&, WTF::Vector<unsigned char>&&)>(IPC::Connection&, IPC::Decoder&, WebKit::GPUConnectionToWebProcess*, void (WebKit::GPUConnectionToWebProcess::*)(WebKit::SharedMemory::Handle&&, WTF::Vector<unsigned char>&&))"
	handler, args, workQueue, ok := webKitIPCHandlerInfo(symbol)
	if !ok {
		t.Fatal("expected handler info")
	}
	if handler != "WebKit::GPUConnectionToWebProcess" {
		t.Fatalf("handler=%q", handler)
	}
	if workQueue {
		t.Fatal("did not expect workqueue receiver")
	}
	if len(args) != 2 || args[0] != "WebKit::SharedMemory::Handle&&" || args[1] != "WTF::Vector<unsigned char>&&" {
		t.Fatalf("args=%#v", args)
	}
}

func TestWebKitIPCHandlerInfoDetectsWorkQueue(t *testing.T) {
	t.Parallel()

	symbol := "void IPC::handleMessage<Messages::Foo::Bar, IPC::WorkQueueMessageReceiver, void (IPC::WorkQueueMessageReceiver::*)()>()"
	_, _, workQueue, ok := webKitIPCHandlerInfo(symbol)
	if !ok || !workQueue {
		t.Fatalf("ok=%v workQueue=%v", ok, workQueue)
	}
}
