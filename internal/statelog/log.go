// Package statelog persists a JSONL transcript of every sync --apply run
// so operators can answer "what did sync do last Tuesday?" without piping
// to tee. Also provides an advisory file lock for the fleet repo so two
// concurrent sync operations serialize.
//
// Layout:
//
//	~/.local/state/incus-sync/apply-<YYYYMMDD-HHMMSS>-<host>.log
//	$INCUS_SYNC_FLEET_PATH/.incus-sync.lock                (created + flock'd)
package statelog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Event is one JSONL record. Kind identifies the phase; Data is a
// free-form map so we can extend without a schema migration.
type Event struct {
	Time time.Time      `json:"ts"`
	Kind string         `json:"kind"`
	Data map[string]any `json:"data,omitempty"`
}

// Apply is one apply session. Open per sync run; Close when done.
type Apply struct {
	f    *os.File
	path string
}

// Open creates a new log file under XDG state dir. Best-effort: if the
// dir cannot be created (read-only home, disk full) the returned Apply
// is a no-op wrapper — sync still runs; the operator sees a warning.
func Open(host string) (*Apply, string, error) {
	base := stateDir()
	if err := os.MkdirAll(base, 0o755); err != nil {
		return &Apply{}, "", fmt.Errorf("mkdir %s: %w", base, err)
	}
	name := fmt.Sprintf("apply-%s-%s.log", time.Now().Format("20060102-150405"), host)
	path := filepath.Join(base, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return &Apply{}, "", fmt.Errorf("open %s: %w", path, err)
	}
	return &Apply{f: f, path: path}, path, nil
}

// Path returns the log file path (empty when Open failed).
func (a *Apply) Path() string { return a.path }

// Write appends one event. Silent if Apply has no file.
func (a *Apply) Write(kind string, data map[string]any) {
	if a == nil || a.f == nil {
		return
	}
	e := Event{Time: time.Now().UTC(), Kind: kind, Data: data}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_, _ = a.f.Write(append(b, '\n'))
}

// Close flushes and closes the log.
func (a *Apply) Close() {
	if a != nil && a.f != nil {
		_ = a.f.Close()
	}
}

func stateDir() string {
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "incus-sync")
	}
	if v := os.Getenv("HOME"); v != "" {
		return filepath.Join(v, ".local", "state", "incus-sync")
	}
	return filepath.Join(os.TempDir(), "incus-sync")
}

// Lock is an advisory file lock for the fleet repository. Acquired at
// the start of sync --apply and released on function return.
type Lock struct {
	f *os.File
}

// Acquire creates and flocks $fleetPath/.incus-sync.lock exclusively.
// Blocks up to timeout, then errors out with a helpful "held by pid N"
// message.
func Acquire(fleetPath string, timeout time.Duration) (*Lock, error) {
	path := filepath.Join(fleetPath, ".incus-sync.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open lockfile %s: %w", path, err)
	}
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			// Record our pid so a contender sees who to blame.
			_ = f.Truncate(0)
			_, _ = f.Seek(0, 0)
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			return &Lock{f: f}, nil
		}
		if time.Now().After(deadline) {
			existing, _ := os.ReadFile(path)
			_ = f.Close()
			return nil, fmt.Errorf(
				"lockfile %s held (contents: %q) — waited %s. Another sync in progress?",
				path, string(existing), timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Release drops the flock and closes the file. Idempotent.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}
