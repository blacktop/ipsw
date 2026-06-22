package crashlog

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/dustin/go-humanize"
)

// StreamStall is an AMTStreamingStallNetworkDiagnostics report (bug_type 241):
// CoreMedia HLS streaming-stall telemetry. Its header line is JSON whose
// custom_headers carry the actionable summary (client, service, stall count);
// the body is a raw-deflate-compressed binary "ABRTrace" — an undocumented
// CoreMedia struct dump we decompress and size but do not decode.
type StreamStall struct {
	Header    IpsMetadata
	Custom    StreamStallHeaders
	TraceSize int      // decompressed body size in bytes
	TraceTags []string // 4-char record magics found in the trace (e.g. RHWN, RRBA)
	TraceErr  string   // set if the body could not be decompressed
	Config    *Config
}

// StreamStallHeaders is the "custom_headers" object on a 241 report.
type StreamStallHeaders struct {
	Stalls      int    `json:"stalls"`
	Sender      string `json:"sender,omitempty"`
	ClientName  string `json:"clientName,omitempty"`
	SessionID   string `json:"sessionID,omitempty"`
	Type        string `json:"type,omitempty"`
	ServiceName string `json:"serviceName,omitempty"`
	Version     string `json:"version,omitempty"`
	Compression string `json:"compression,omitempty"`
}

// OpenStreamStall parses an AMTStreamingStall (241) report.
func OpenStreamStall(in string, conf *Config) (*StreamStall, error) {
	data, err := os.ReadFile(in)
	if err != nil {
		return nil, err
	}
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		nl = len(data)
	}
	// custom_headers is not part of IpsMetadata, so decode into a struct that
	// embeds it and adds custom_headers.
	var hdr struct {
		IpsMetadata
		CustomHeaders StreamStallHeaders `json:"custom_headers"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data[:nl]), &hdr); err != nil {
		return nil, fmt.Errorf("stream stall %s: decode header: %w", in, err)
	}
	ss := &StreamStall{Header: hdr.IpsMetadata, Custom: hdr.CustomHeaders, Config: conf}
	if db, err := GetLogTypes(); err == nil {
		if bt, ok := (*db)[ss.Header.BugType]; ok {
			ss.Header.BugTypeDesc = bt.Name
		}
	}

	// The body is raw DEFLATE (despite the "zlib" label there is no zlib header).
	// A decompress failure degrades to a header-only report, not a hard error.
	if nl < len(data) {
		raw, derr := io.ReadAll(flate.NewReader(bytes.NewReader(data[nl+1:])))
		if derr != nil {
			ss.TraceErr = fmt.Sprintf("could not decompress ABRTrace body: %v", derr)
		} else {
			ss.TraceSize = len(raw)
			ss.TraceTags = traceTags(raw)
		}
	}
	return ss, nil
}

// traceTags collects the distinct 4-byte uppercase-ASCII record magics in the
// decompressed trace (the only labeled structure in the binary blob).
func traceTags(b []byte) []string {
	seen := map[string]bool{}
	var tags []string
	for i := 0; i+4 <= len(b); i++ {
		w := b[i : i+4]
		if w[0] < 'A' || w[0] > 'Z' || w[1] < 'A' || w[1] > 'Z' || w[2] < 'A' || w[2] > 'Z' || w[3] < 'A' || w[3] > 'Z' {
			continue
		}
		if tag := string(w); !seen[tag] {
			seen[tag] = true
			tags = append(tags, tag)
		}
	}
	return tags
}

func (s *StreamStall) String() string {
	var out strings.Builder
	c := s.Custom
	who := s.Header.Name // 241 reports carry no top-level name; fall back to the client
	if who == "" {
		who = c.ClientName
	}
	fmt.Fprintf(&out, "[%s] - %s", colorTime(s.Header.Timestamp.Format("02Jan2006 15:04:05")), colorError(s.Header.BugTypeDesc))
	if who != "" {
		fmt.Fprintf(&out, " - %s", colorImage("%s", who))
	}
	out.WriteString("\n\n")

	buf := bytes.NewBufferString("")
	w := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
	if c.ClientName != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Client"), colorImage("%s", c.ClientName))
	}
	if c.ServiceName != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Service"), c.ServiceName)
	}
	if c.Sender != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Sender"), c.Sender)
	}
	if c.Type != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Trace Type"), c.Type)
	}
	stalls := colorBold("%d", c.Stalls)
	if c.Stalls > 0 {
		stalls = colorError(fmt.Sprintf("%d", c.Stalls))
	}
	fmt.Fprintf(w, "%s\t%s\n", colorField("Stalls"), stalls)
	if c.SessionID != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Session"), c.SessionID)
	}
	if c.Version != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Version"), c.Version)
	}
	w.Flush()
	out.WriteString(buf.String())

	switch {
	case s.TraceErr != "":
		fmt.Fprintf(&out, "\n%s: %s\n", colorField("Trace"), colorError(s.TraceErr))
	case s.TraceSize > 0:
		fmt.Fprintf(&out, "\n%s: %s decompressed", colorField("ABRTrace"), humanize.IBytes(uint64(s.TraceSize)))
		if c.Compression != "" {
			fmt.Fprintf(&out, " (%s)", c.Compression)
		}
		if len(s.TraceTags) > 0 {
			out.WriteString(" • tags: " + strings.Join(s.TraceTags, ", "))
		}
		out.WriteString("\n")
	}
	return out.String()
}
