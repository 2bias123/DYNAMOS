package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// identifierPattern is the validation regex for state_class and state_key.
// Human-readable to keep audit logs and on-disk paths debuggable for the demo;
// production hashing of identifiers is future work.
var identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// createTempFn is a seam so tests can assert that the atomic-write temp file
// is created in the class dir (not /tmp); production code uses os.CreateTemp.
var createTempFn = os.CreateTemp

// ErrInvalidIdentifier is returned when state_class or state_key fails the
// identifierPattern check.
var ErrInvalidIdentifier = errors.New("state_class and state_key must match ^[a-zA-Z0-9_-]{1,64}$")

// Identity mirrors the proto Identity message; carried in audit records.
type Identity struct {
	Steward      string `json:"steward"`
	User         string `json:"user"`
	RequestType  string `json:"requestType"`
	JobID        string `json:"jobId"`
	LocalJobName string `json:"localJobName"`
}

// AuditRecord is the NDJSON line written to both the audit file and stdout.
// Policy fields (AgreementHash, PolicySource, CacheAgeMs) carry zero values
// in Ticket 3 and receive real values from the policy layer in Ticket 5.
type AuditRecord struct {
	Ts            string   `json:"ts"`
	Op            string   `json:"op"`
	StateClass    string   `json:"stateClass"`
	StateKey      string   `json:"stateKey"`
	Decision      string   `json:"decision"`
	Reason        string   `json:"reason"`
	AgreementHash string   `json:"agreementHash"`
	PolicySource  string   `json:"policySource"`
	CacheAgeMs    int64    `json:"cacheAgeMs"`
	Identity      Identity `json:"identity"`
}

// Store owns the gateway's on-disk state and audit primitives.
//
// keyMutexes serializes goroutines inside this process; inter-pod concurrency
// is the PVC access mode's job (RWOP), not this mutex.
type Store struct {
	dataDir  string
	auditDir string

	keyMutexes sync.Map

	auditMu   sync.Mutex
	auditFile *os.File
	auditOut  *os.File
}

// NewStore prepares /state/data and /state/audit under baseDir and opens the
// audit log in append mode. The audit file handle is kept open for the
// process lifetime; close it via (*Store).Close on shutdown.
func NewStore(baseDir string) (*Store, error) {
	dataDir := filepath.Join(baseDir, "data")
	auditDir := filepath.Join(baseDir, "audit")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir data dir: %w", err)
	}
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir audit dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(auditDir, "audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Store{
		dataDir:   dataDir,
		auditDir:  auditDir,
		auditFile: f,
		auditOut:  os.Stdout,
	}, nil
}

// Close releases the audit file handle.
func (s *Store) Close() error {
	return s.auditFile.Close()
}

// Sync fsyncs the audit file. Called during teardown so the durable record
// survives an os.Exit before the kernel flushes.
func (s *Store) Sync() error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	return s.auditFile.Sync()
}

// DataDir returns the absolute path to /state/data.
func (s *Store) DataDir() string { return s.dataDir }

// AuditDir returns the absolute path to /state/audit.
func (s *Store) AuditDir() string { return s.auditDir }

func (s *Store) keyMutex(class, key string) *sync.Mutex {
	id := class + "/" + key
	if m, ok := s.keyMutexes.Load(id); ok {
		return m.(*sync.Mutex)
	}
	m, _ := s.keyMutexes.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func validateIdentifiers(class, key string) error {
	if !identifierPattern.MatchString(class) || !identifierPattern.MatchString(key) {
		return ErrInvalidIdentifier
	}
	return nil
}

// Write atomically persists payload at /state/data/{class}/{key}.bin.
// The temp file is created inside the class directory so the rename stays on
// a single filesystem.
func (s *Store) Write(class, key string, payload []byte) error {
	if err := validateIdentifiers(class, key); err != nil {
		return err
	}
	m := s.keyMutex(class, key)
	m.Lock()
	defer m.Unlock()

	classDir := filepath.Join(s.dataDir, class)
	if err := os.MkdirAll(classDir, 0o755); err != nil {
		return fmt.Errorf("mkdir class dir: %w", err)
	}

	tmp, err := createTempFn(classDir, key+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}

	finalPath := filepath.Join(classDir, key+".bin")
	if err := os.Rename(tmpName, finalPath); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// Read returns the payload at /state/data/{class}/{key}.bin. When the key is
// absent the returned error wraps os.ErrNotExist (matchable via errors.Is).
func (s *Store) Read(class, key string) ([]byte, error) {
	if err := validateIdentifiers(class, key); err != nil {
		return nil, err
	}
	m := s.keyMutex(class, key)
	m.Lock()
	defer m.Unlock()

	path := filepath.Join(s.dataDir, class, key+".bin")
	return os.ReadFile(path)
}

// Audit serializes rec as one NDJSON line and writes it to both the audit
// file and stdout under a single process-global mutex, before returning.
// If rec.Ts is empty it is filled with time.Now().UTC() in RFC3339Nano.
func (s *Store) Audit(rec AuditRecord) error {
	if rec.Ts == "" {
		rec.Ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal audit: %w", err)
	}
	line = append(line, '\n')

	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if _, err := s.auditFile.Write(line); err != nil {
		return fmt.Errorf("write audit file: %w", err)
	}
	if _, err := s.auditOut.Write(line); err != nil {
		return fmt.Errorf("write audit stdout: %w", err)
	}
	return nil
}
