package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemadump"
)

// captureStdout temporarily redirects os.Stdout for the duration of fn.
// runValidate/runBacktest print directly to os.Stdout rather than accepting
// an io.Writer, so this is the only way to assert on their output without
// changing their signatures.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	fnErr := fn()

	w.Close()
	os.Stdout = orig

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	return string(data), fnErr
}

func writeSchemaDump(t *testing.T, field string) string {
	t.Helper()
	dir := t.TempDir()
	if err := schemadump.Write(dir, catalogWithField(t, field)); err != nil {
		t.Fatalf("schemadump.Write: %v", err)
	}
	return dir
}

func TestRunValidate_AllRulesValid(t *testing.T) {
	rulesDir := writeRulesDir(t, `has(params.path) && params.path == "x"`)
	schemasDir := writeSchemaDump(t, "path")

	var out string
	var runErr error
	out, runErr = captureStdout(t, func() error {
		return runValidate([]string{"--schemas-dir", schemasDir, rulesDir})
	})
	if runErr != nil {
		t.Fatalf("runValidate: %v (output: %s)", runErr, out)
	}
	if !strings.Contains(out, "all rules valid") {
		t.Fatalf("expected success message, got %q", out)
	}
}

func TestRunValidate_CompileErrorFails(t *testing.T) {
	rulesDir := writeRulesDir(t, `tool ===`)
	schemasDir := writeSchemaDump(t, "path")

	out, runErr := captureStdout(t, func() error {
		return runValidate([]string{"--schemas-dir", schemasDir, rulesDir})
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "validation failed") {
		t.Fatalf("expected a validation failed error, got %v", runErr)
	}
	if !strings.Contains(out, "FAIL") {
		t.Fatalf("expected a FAIL line in output, got %q", out)
	}
}

func TestRunValidate_UnknownSchemaFieldFails(t *testing.T) {
	rulesDir := writeRulesDir(t, `has(params.brnach) && params.brnach == "main"`)
	schemasDir := writeSchemaDump(t, "path") // "path" exists, "brnach" does not

	out, runErr := captureStdout(t, func() error {
		return runValidate([]string{"--schemas-dir", schemasDir, rulesDir})
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "validation failed") {
		t.Fatalf("expected a validation failed error, got %v", runErr)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "brnach") {
		t.Fatalf("expected a FAIL line naming the unknown field, got %q", out)
	}
}

func TestRunValidate_PerFileLoadFailureFailsValidation(t *testing.T) {
	// A malformed rule file is reported per-server via loadErrors (not the
	// fatal rulestore.Load error return — see rulestore_test.go's
	// TestLoad_BrokenFileIsolatedToItsServer for the same isolation
	// guarantee), so runValidate should still surface it as a FAIL and a
	// non-nil "validation failed" error.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "github.yaml"), []byte("not: [valid: yaml"), 0o644); err != nil {
		t.Fatalf("writing malformed rules file: %v", err)
	}

	out, runErr := captureStdout(t, func() error {
		return runValidate([]string{"--schemas-dir", writeSchemaDump(t, "path"), dir})
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "validation failed") {
		t.Fatalf("expected a validation failed error, got %v", runErr)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "failed to load") {
		t.Fatalf("expected a FAIL line reporting the load failure, got %q", out)
	}
}
