//go:build darwin

// Package notif reads macOS Notification Center's SQLite store.
//
// Records persist on disk after dismissal — including "disappearing" message
// previews from Signal/WhatsApp/etc. See objective-see.com/blog/blog_0x2E.html.
//
// macOS 26+ moved the store under a group container; reading it requires that
// the calling process (terminal/IDE) has Full Disk Access.
package notif

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/blacktop/go-plist"
	_ "github.com/glebarez/go-sqlite" // registers "sqlite" driver (cgo-free)
)

// dbPaths returns candidate notification DB locations, newest first.
func dbPaths() []string {
	home, _ := os.UserHomeDir()
	tmp := os.TempDir() // .../T/ — strip last component to reach .../0/
	return []string{
		filepath.Join(home, "Library/Group Containers/group.com.apple.usernoted/db2/db"), // macOS 26+
		filepath.Join(filepath.Dir(filepath.Clean(tmp)), "0/com.apple.notificationcenter/db2/db"),
	}
}

// Open finds and opens the notification database read-only.
// If path is empty, the standard locations are probed.
func Open(path string) (*sql.DB, error) {
	candidates := []string{path}
	if path == "" {
		candidates = dbPaths()
	}
	var permErr error
	for _, p := range candidates {
		if p == "" {
			continue
		}
		// TCC permits stat() but denies open(); probe the read path so we
		// surface a clean EPERM instead of SQLite's "out of memory" (CANTOPEN).
		f, err := os.Open(p)
		if err != nil {
			if permErr == nil && (errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)) {
				permErr = fmt.Errorf("cannot read %s: %w\n  grant Full Disk Access to your terminal in System Settings → Privacy & Security → Full Disk Access", p, err)
			}
			continue
		}
		f.Close()
		db, err := sql.Open("sqlite", "file:"+p+"?mode=ro")
		if err != nil {
			return nil, err
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, fmt.Errorf("ping %s: %w", p, err)
		}
		return db, nil
	}
	if permErr != nil {
		return nil, permErr
	}
	return nil, fmt.Errorf("notification database not found (tried: %v)", candidates)
}

// Record is one notification entry from the `record` table with its
// associated app identifier and the decoded request payload.
type Record struct {
	BundleID  string    `json:"bundle_id"`
	Delivered time.Time `json:"delivered,omitzero"`
	Title     string    `json:"title,omitempty"`
	Subtitle  string    `json:"subtitle,omitempty"`
	Body      string    `json:"body,omitempty"`
	Raw       []byte    `json:"-"` // unparsed bplist blob
}

// List returns notification records, optionally filtered by bundle identifier.
func List(db *sql.DB, bundleID string) ([]Record, error) {
	q := `SELECT app.identifier, record.delivered_date, record.data
	      FROM record LEFT JOIN app ON record.app_id = app.app_id`
	args := []any{}
	if bundleID != "" {
		q += ` WHERE app.identifier = ?`
		args = append(args, bundleID)
	}
	q += ` ORDER BY record.delivered_date DESC`

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var id sql.NullString
		var ts sql.NullFloat64
		var data []byte
		if err := rows.Scan(&id, &ts, &data); err != nil {
			return nil, err
		}
		r := Record{BundleID: id.String, Raw: data}
		if ts.Valid && ts.Float64 > 0 {
			r.Delivered = cfAbsoluteToTime(ts.Float64)
		}
		r.Title, r.Subtitle, r.Body = decodeRequest(data)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Apps returns the bundle identifiers known to Notification Center along with
// their persisted record counts.
func Apps(db *sql.DB) (map[string]int, error) {
	rows, err := db.Query(`SELECT app.identifier, COUNT(record.rec_id)
	                       FROM app LEFT JOIN record ON app.app_id = record.app_id
	                       GROUP BY app.identifier`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// cfAbsoluteToTime converts a Core Foundation absolute time (seconds since
// 2001-01-01 00:00:00 UTC) to a time.Time.
func cfAbsoluteToTime(cf float64) time.Time {
	const cfEpoch = 978307200 // 2001-01-01 in Unix seconds
	sec, frac := int64(cf), cf-float64(int64(cf))
	return time.Unix(cfEpoch+sec, int64(frac*1e9)).UTC()
}

// decodeRequest extracts the user-visible title/subtitle/body strings from a
// notification record blob. On modern macOS the blob is a plain bplist dict
// with the request under "req"; keys are 4-char shortenings (titl/subt/body).
// go-plist silently no-ops nested struct fields, so walk the map manually.
func decodeRequest(data []byte) (title, subtitle, body string) {
	var top map[string]any
	if _, err := plist.Unmarshal(data, &top); err != nil {
		return
	}
	req, _ := top["req"].(map[string]any)
	if req == nil {
		return
	}
	title, _ = req["titl"].(string)
	subtitle, _ = req["subt"].(string)
	body, _ = req["body"].(string)
	return
}

// DumpRaw returns the bplist blob decoded as a generic plist tree — useful for
// `--raw` inspection when the schema-aware path misses fields.
func DumpRaw(data []byte) (any, error) {
	var v any
	_, err := plist.Unmarshal(data, &v)
	return v, err
}
