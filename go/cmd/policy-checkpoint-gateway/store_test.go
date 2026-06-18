package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gotest.tools/assert"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir())
	assert.NilError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestWriteReadRoundTrip(t *testing.T) {
	s := newTestStore(t)
	payload := []byte("hello-world-\x00\x01\x02")
	assert.NilError(t, s.Write("kv", "k1", payload))

	got, err := s.Read("kv", "k1")
	assert.NilError(t, err)
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}

	finalPath := filepath.Join(s.DataDir(), "kv", "k1.bin")
	if _, err := os.Stat(finalPath); err != nil {
		t.Fatalf("final file missing: %v", err)
	}
}

func TestReadMissingKeyIsNotExist(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Read("kv", "absent")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	if !os.IsNotExist(err) && !errorsIsNotExist(err) {
		t.Fatalf("expected os.ErrNotExist-matchable error, got %v", err)
	}
}

func errorsIsNotExist(err error) bool {
	// stdlib: os.ReadFile returns *fs.PathError wrapping fs.ErrNotExist
	// which is the same target as os.ErrNotExist; both errors.Is paths work.
	return os.IsNotExist(err)
}

func TestValidationRejects(t *testing.T) {
	s := newTestStore(t)
	cases := []struct {
		name, class, key string
	}{
		{"emptyClass", "", "k"},
		{"emptyKey", "kv", ""},
		{"slashInClass", "kv/sub", "k"},
		{"slashInKey", "kv", "k/sub"},
		{"dotInClass", "k.v", "k"},
		{"dotInKey", "kv", "k.bin"},
		{"tooLongClass", strings.Repeat("a", 65), "k"},
		{"tooLongKey", "kv", strings.Repeat("a", 65)},
		{"spaceInClass", "k v", "k"},
		{"spaceInKey", "kv", "k 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Write(tc.class, tc.key, []byte("x")); err == nil {
				t.Fatal("expected validation error on Write, got nil")
			}
			if _, err := s.Read(tc.class, tc.key); err == nil {
				t.Fatal("expected validation error on Read, got nil")
			}
		})
	}

	t.Run("validMaxLen", func(t *testing.T) {
		s := newTestStore(t)
		class := strings.Repeat("a", 64)
		key := strings.Repeat("b", 64)
		assert.NilError(t, s.Write(class, key, []byte("y")))
		got, err := s.Read(class, key)
		assert.NilError(t, err)
		if !bytes.Equal(got, []byte("y")) {
			t.Fatalf("payload mismatch")
		}
	})
}

func TestCreateTempInClassDir(t *testing.T) {
	s := newTestStore(t)
	var capturedDir string
	prev := createTempFn
	createTempFn = func(dir, pattern string) (*os.File, error) {
		capturedDir = dir
		return os.CreateTemp(dir, pattern)
	}
	t.Cleanup(func() { createTempFn = prev })

	assert.NilError(t, s.Write("kv", "seam", []byte("z")))
	wantDir := filepath.Join(s.DataDir(), "kv")
	if capturedDir != wantDir {
		t.Fatalf("CreateTemp dir = %q, want %q (must be class dir, not /tmp)", capturedDir, wantDir)
	}
}

func TestNoTempLeftoverAfterWrite(t *testing.T) {
	s := newTestStore(t)
	assert.NilError(t, s.Write("kv", "leftover", []byte("p")))
	entries, err := os.ReadDir(filepath.Join(s.DataDir(), "kv"))
	assert.NilError(t, err)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Fatalf("leftover temp file in class dir: %s", e.Name())
		}
	}
}

func TestConcurrentSameKeyWrites(t *testing.T) {
	s := newTestStore(t)
	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			payload := []byte{byte(i), 0xAA, 0xBB, 0xCC}
			if err := s.Write("kv", "hot", payload); err != nil {
				t.Errorf("write %d: %v", i, err)
			}
		}()
	}
	wg.Wait()

	got, err := s.Read("kv", "hot")
	assert.NilError(t, err)
	if len(got) != 4 || got[1] != 0xAA || got[2] != 0xBB || got[3] != 0xCC {
		t.Fatalf("corrupted payload after concurrent writes: %v", got)
	}
}

func TestAuditDualWriteByteIdentical(t *testing.T) {
	s := newTestStore(t)

	r, w, err := os.Pipe()
	assert.NilError(t, err)
	s.auditOut = w

	rec := AuditRecord{
		Op:         "write",
		StateClass: "kv",
		StateKey:   "k1",
		Decision:   "ALLOW",
		Reason:     "stub",
		Identity: Identity{
			Steward:      "UVA",
			User:         "u@x",
			RequestType:  "sqlDataRequest",
			JobID:        "jobX",
			LocalJobName: "jobX-1",
		},
	}
	assert.NilError(t, s.Audit(rec))
	assert.NilError(t, w.Close())

	stdoutBytes, err := io.ReadAll(r)
	assert.NilError(t, err)

	fileBytes, err := os.ReadFile(filepath.Join(s.AuditDir(), "audit.log"))
	assert.NilError(t, err)

	if !bytes.Equal(stdoutBytes, fileBytes) {
		t.Fatalf("stdout vs file mismatch:\n  stdout: %q\n  file:   %q", stdoutBytes, fileBytes)
	}
	if !bytes.HasSuffix(stdoutBytes, []byte("\n")) {
		t.Fatalf("audit line not newline-terminated: %q", stdoutBytes)
	}
}

func TestAuditDirUntouchedByDataWrite(t *testing.T) {
	s := newTestStore(t)
	auditLog := filepath.Join(s.AuditDir(), "audit.log")
	before, err := os.ReadFile(auditLog)
	assert.NilError(t, err)

	assert.NilError(t, s.Write("kv", "untouched", []byte("payload")))

	after, err := os.ReadFile(auditLog)
	assert.NilError(t, err)
	if !bytes.Equal(before, after) {
		t.Fatalf("audit log changed by data Write: before=%q after=%q", before, after)
	}
}

func TestAuditNDJSONSchemaComplete(t *testing.T) {
	s := newTestStore(t)
	rec := AuditRecord{
		Op:            "write",
		StateClass:    "kv",
		StateKey:      "k1",
		Decision:      "ALLOW",
		Reason:        "stub",
		AgreementHash: "",
		PolicySource:  "",
		CacheAgeMs:    0,
		Identity: Identity{
			Steward:      "UVA",
			User:         "u@x",
			RequestType:  "sqlDataRequest",
			JobID:        "jobX",
			LocalJobName: "jobX-1",
		},
	}
	assert.NilError(t, s.Audit(rec))

	raw, err := os.ReadFile(filepath.Join(s.AuditDir(), "audit.log"))
	assert.NilError(t, err)
	line := bytes.TrimRight(raw, "\n")

	var obj map[string]any
	assert.NilError(t, json.Unmarshal(line, &obj))

	for _, k := range []string{
		"ts", "op", "stateClass", "stateKey", "decision", "reason",
		"agreementHash", "policySource", "cacheAgeMs", "identity",
	} {
		if _, ok := obj[k]; !ok {
			t.Errorf("audit NDJSON missing top-level key %q (full: %s)", k, line)
		}
	}
	id, ok := obj["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity not a JSON object: %T", obj["identity"])
	}
	for _, k := range []string{"steward", "user", "requestType", "jobId", "localJobName"} {
		if _, ok := id[k]; !ok {
			t.Errorf("audit identity missing key %q (full: %s)", k, line)
		}
	}
}
