package crashlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"
)

// OTAUpdate is an OTASUpdate report (bug_type 183): a JSON header describing a
// software-update/restore attempt followed by a free-form text log. The header's
// restore_error is the key actionable field; when the log carries a trailing
// "<X>ErrorDomain error N - message" line we surface it as the plain-English cause.
type OTAUpdate struct {
	Header       OTAHeader
	BugTypeDesc  string
	Body         []string // raw log lines (everything after the header line)
	ErrorDomain  string
	ErrorCode    string
	ErrorMessage string
	Config       *Config
}

// OTAHeader is the JSON header line of a 183 report. restore_error is sent as a
// string ("78") today but is decoded as json.Number so a bare-number variant
// (78) doesn't fail the whole report; it is absent in the patchd variant.
type OTAHeader struct {
	RestorePayloadVersion string      `json:"restore_payload_version,omitempty"`
	RestoreType           string      `json:"restore_type,omitempty"`
	OsVersion             string      `json:"os_version,omitempty"`
	ItunesVersion         string      `json:"itunes_version,omitempty"`
	BugType               string      `json:"bug_type,omitempty"`
	RestoreError          json.Number `json:"restore_error,omitempty"`
	Name                  string      `json:"name,omitempty"`
}

// otaErrRe matches a trailing error-domain summary line, e.g.
//
//	<hex> : MobileSoftwareUpdateErrorDomain error 78 - Update finish took too long...
var otaErrRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9.]*ErrorDomain) error (-?\d+) - (.+?)\s*$`)

// OpenOTAUpdate parses an OTASUpdate (183) report.
func OpenOTAUpdate(in string, conf *Config) (*OTAUpdate, error) {
	data, err := os.ReadFile(in)
	if err != nil {
		return nil, err
	}
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 { // header-only file (no body)
		nl = len(data)
	}
	o := &OTAUpdate{Config: conf}
	if err := json.Unmarshal(bytes.TrimSpace(data[:nl]), &o.Header); err != nil {
		return nil, fmt.Errorf("ota update %s: decode header: %w", in, err)
	}
	o.BugTypeDesc = o.Header.BugType
	if db, err := GetLogTypes(); err == nil {
		if bt, ok := (*db)[o.Header.BugType]; ok {
			o.BugTypeDesc = bt.Name
		}
	}

	// Split manually rather than via bufio.Scanner: the whole file is already in
	// memory and OTA logs embed multi-KB analytics lines that would trip a
	// scanner's token cap and silently truncate the body.
	if nl >= len(data) {
		return o, nil // header-only file (no body)
	}
	if body := bytes.TrimRight(data[nl+1:], "\n"); len(body) > 0 {
		for _, raw := range bytes.Split(body, []byte("\n")) {
			line := string(raw)
			o.Body = append(o.Body, line)
			if m := otaErrRe.FindStringSubmatch(line); m != nil {
				o.ErrorDomain, o.ErrorCode, o.ErrorMessage = m[1], m[2], m[3] // keep the last match
			}
		}
	}
	return o, nil
}

const otaLogTail = 40

func (o *OTAUpdate) String() string {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s - %s\n\n", colorError(o.BugTypeDesc), colorImage("%s", o.Header.Name)))

	buf := bytes.NewBufferString("")
	w := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
	if o.Header.RestoreType != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Restore Type"), o.Header.RestoreType)
	}
	if o.Header.OsVersion != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("OS Version"), o.Header.OsVersion)
	}
	if o.Header.ItunesVersion != "" && o.Header.ItunesVersion != o.Header.OsVersion {
		fmt.Fprintf(w, "%s\t%s\n", colorField("iTunes Version"), o.Header.ItunesVersion)
	}
	if o.Header.RestoreError != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Restore Error"), colorError(o.Header.RestoreError))
	}
	w.Flush()
	out.WriteString(buf.String())

	if o.ErrorDomain != "" {
		out.WriteString(fmt.Sprintf("\n%s: %s\n", colorField("Cause"), colorError(fmt.Sprintf("%s error %s", o.ErrorDomain, o.ErrorCode))))
		if o.ErrorMessage != "" {
			out.WriteString("  " + o.ErrorMessage + "\n")
		}
	}

	if len(o.Body) > 0 {
		out.WriteString("\n" + colorField("Update Log") + ":\n")
		body := o.Body
		verbose := o.Config != nil && (o.Config.Verbose || o.Config.All)
		if !verbose && len(body) > otaLogTail {
			out.WriteString(colorAddr("  ... %d earlier lines (use --all for the full log)\n", len(body)-otaLogTail))
			body = body[len(body)-otaLogTail:]
		}
		for _, l := range body {
			out.WriteString("  " + l + "\n")
		}
	}
	return out.String()
}
