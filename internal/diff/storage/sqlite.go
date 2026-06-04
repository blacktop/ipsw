package storage

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/glebarez/go-sqlite" // registers "sqlite" driver (cgo-free)
)

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS diff_state (
    ipsw_old   TEXT NOT NULL,
    ipsw_new   TEXT NOT NULL,
    task       TEXT NOT NULL,
    task_ver   INTEGER NOT NULL,
    opts_hash  TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (ipsw_old, ipsw_new, task, task_ver, opts_hash, input_hash, key)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_diff_state_updated ON diff_state(updated_at);

CREATE TABLE IF NOT EXISTS diff_complete (
    ipsw_old   TEXT NOT NULL,
    ipsw_new   TEXT NOT NULL,
    task       TEXT NOT NULL,
    task_ver   INTEGER NOT NULL,
    opts_hash  TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    PRIMARY KEY (ipsw_old, ipsw_new, task, task_ver, opts_hash, input_hash)
) WITHOUT ROWID;
`

// writeRequest is the unit of work sent to the single writer goroutine. Either
// putKey/payload are populated (a Put) or markComplete is true (a
// MarkComplete). resp receives the error result so callers block synchronously.
type writeRequest struct {
	scope        Scope
	putKey       string
	payload      []byte
	markComplete bool
	resp         chan error
}

// SQLiteStore is the persistent Store implementation backed by a single SQLite
// database in WAL mode. All writes are funneled through one goroutine to keep
// transactions simple and to sidestep "database is locked" under burst load;
// reads go straight to the database and may run in parallel.
type SQLiteStore struct {
	db *sql.DB

	getStmt      *sql.Stmt
	iterStmt     *sql.Stmt
	completeStmt *sql.Stmt
	putStmt      *sql.Stmt
	markStmt     *sql.Stmt

	writeCh chan writeRequest

	// mu guards closed-vs-writeCh ordering: writers take RLock around the
	// send, Close takes Lock to drain in-flight writers before closing
	// writeCh. Without this, a send on writeCh could race the close in
	// Close and panic ("send on closed channel"), even with the closed
	// signal channel handled in the select.
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	writerWG  sync.WaitGroup
}

// NewSQLiteStore opens (or creates) the SQLite database at path, applies the
// diff schema, and starts the single writer goroutine. Parent directories are
// created on demand so callers may pass paths under cache directories that do
// not yet exist.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite store: path is required")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("sqlite store: create parent dir: %w", err)
		}
	}

	// _journal=WAL keeps readers concurrent with the single writer; _busy_timeout
	// gives the writer goroutine a chance to drain before the driver errors out
	// on a transient lock.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite store: open %s: %w", path, err)
	}
	if _, err := db.Exec(sqliteSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite store: apply schema: %w", err)
	}

	s := &SQLiteStore{
		db:      db,
		writeCh: make(chan writeRequest, 64),
	}
	if err := s.prepare(); err != nil {
		_ = db.Close()
		return nil, err
	}

	s.writerWG.Add(1)
	go s.runWriter()
	return s, nil
}

func (s *SQLiteStore) prepare() error {
	var err error
	s.getStmt, err = s.db.Prepare(`SELECT value FROM diff_state
		WHERE ipsw_old=? AND ipsw_new=? AND task=? AND task_ver=? AND opts_hash=? AND input_hash=? AND key=?`)
	if err != nil {
		return fmt.Errorf("sqlite store: prepare get: %w", err)
	}
	s.iterStmt, err = s.db.Prepare(`SELECT key, value FROM diff_state
		WHERE ipsw_old=? AND ipsw_new=? AND task=? AND task_ver=? AND opts_hash=? AND input_hash=?`)
	if err != nil {
		return fmt.Errorf("sqlite store: prepare iter: %w", err)
	}
	s.completeStmt, err = s.db.Prepare(`SELECT 1 FROM diff_complete
		WHERE ipsw_old=? AND ipsw_new=? AND task=? AND task_ver=? AND opts_hash=? AND input_hash=?`)
	if err != nil {
		return fmt.Errorf("sqlite store: prepare complete: %w", err)
	}
	s.putStmt, err = s.db.Prepare(`INSERT INTO diff_state
		(ipsw_old, ipsw_new, task, task_ver, opts_hash, input_hash, key, value, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ipsw_old, ipsw_new, task, task_ver, opts_hash, input_hash, key)
		DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`)
	if err != nil {
		return fmt.Errorf("sqlite store: prepare put: %w", err)
	}
	s.markStmt, err = s.db.Prepare(`INSERT INTO diff_complete
		(ipsw_old, ipsw_new, task, task_ver, opts_hash, input_hash)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(ipsw_old, ipsw_new, task, task_ver, opts_hash, input_hash) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("sqlite store: prepare mark complete: %w", err)
	}
	return nil
}

// Put encodes v with gob and forwards the write to the single writer
// goroutine. Returns when the writer has reported success or failure.
func (s *SQLiteStore) Put(scope Scope, key string, v any) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return fmt.Errorf("sqlite store: encode %s/%s: %w", scope.Task, key, err)
	}
	resp := make(chan error, 1)
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return errors.New("sqlite store: closed")
	}
	s.writeCh <- writeRequest{scope: scope, putKey: key, payload: buf.Bytes(), resp: resp}
	s.mu.RUnlock()
	return <-resp
}

// Get loads the value at (scope, key) directly from the database. Reads bypass
// the writer goroutine so they can run in parallel.
func (s *SQLiteStore) Get(scope Scope, key string, v any) (bool, error) {
	var payload []byte
	row := s.getStmt.QueryRow(
		scope.IpswOld, scope.IpswNew, scope.Task, scope.TaskVersion,
		scope.OptionsHash, scope.InputHash, key,
	)
	if err := row.Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("sqlite store: scan %s/%s: %w", scope.Task, key, err)
	}
	if err := gob.NewDecoder(bytes.NewReader(payload)).Decode(v); err != nil {
		return true, fmt.Errorf("sqlite store: decode %s/%s: %w", scope.Task, key, err)
	}
	return true, nil
}

// Iter streams every row in scope through fn. Each row is delivered with a
// decode callback that copies the gob payload into the caller's destination,
// so iteration cost stays proportional to what the caller actually needs.
func (s *SQLiteStore) Iter(scope Scope, fn func(key string, decode func(v any) error) error) error {
	rows, err := s.iterStmt.Query(
		scope.IpswOld, scope.IpswNew, scope.Task, scope.TaskVersion,
		scope.OptionsHash, scope.InputHash,
	)
	if err != nil {
		return fmt.Errorf("sqlite store: iter %s: %w", scope.Task, err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var payload []byte
		if err := rows.Scan(&key, &payload); err != nil {
			return fmt.Errorf("sqlite store: iter scan %s: %w", scope.Task, err)
		}
		decode := func(v any) error {
			if err := gob.NewDecoder(bytes.NewReader(payload)).Decode(v); err != nil {
				return fmt.Errorf("sqlite store: decode %s/%s: %w", scope.Task, key, err)
			}
			return nil
		}
		if err := fn(key, decode); err != nil {
			return err
		}
	}
	return rows.Err()
}

// MarkComplete forwards the completion record to the writer goroutine.
func (s *SQLiteStore) MarkComplete(scope Scope) error {
	resp := make(chan error, 1)
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return errors.New("sqlite store: closed")
	}
	s.writeCh <- writeRequest{scope: scope, markComplete: true, resp: resp}
	s.mu.RUnlock()
	return <-resp
}

// Complete reports whether MarkComplete has been recorded for scope.
func (s *SQLiteStore) Complete(scope Scope) (bool, error) {
	var one int
	row := s.completeStmt.QueryRow(
		scope.IpswOld, scope.IpswNew, scope.Task, scope.TaskVersion,
		scope.OptionsHash, scope.InputHash,
	)
	if err := row.Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("sqlite store: complete %s: %w", scope.Task, err)
	}
	return true, nil
}

// Close drains pending writes, stops the writer goroutine, and closes the
// underlying database. Calling Close more than once is safe.
//
// The write lock blocks until every in-flight Put/MarkComplete has finished
// its send, so writeCh can be closed without racing a concurrent send.
func (s *SQLiteStore) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.writeCh)
		s.mu.Unlock()
		s.writerWG.Wait()

		for _, stmt := range []*sql.Stmt{s.getStmt, s.iterStmt, s.completeStmt, s.putStmt, s.markStmt} {
			if stmt != nil {
				_ = stmt.Close()
			}
		}
		closeErr = s.db.Close()
	})
	return closeErr
}

// runWriter is the body of the single writer goroutine. It pulls requests off
// writeCh until the channel is closed and applies each one through the
// prepared statements.
func (s *SQLiteStore) runWriter() {
	defer s.writerWG.Done()
	for req := range s.writeCh {
		now := time.Now().Unix()
		var err error
		switch {
		case req.markComplete:
			_, err = s.markStmt.Exec(
				req.scope.IpswOld, req.scope.IpswNew, req.scope.Task,
				req.scope.TaskVersion, req.scope.OptionsHash, req.scope.InputHash,
			)
			if err != nil {
				err = fmt.Errorf("sqlite store: mark complete %s: %w", req.scope.Task, err)
			}
		default:
			_, err = s.putStmt.Exec(
				req.scope.IpswOld, req.scope.IpswNew, req.scope.Task,
				req.scope.TaskVersion, req.scope.OptionsHash, req.scope.InputHash,
				req.putKey, req.payload, now,
			)
			if err != nil {
				err = fmt.Errorf("sqlite store: put %s/%s: %w", req.scope.Task, req.putKey, err)
			}
		}
		req.resp <- err
	}
}
