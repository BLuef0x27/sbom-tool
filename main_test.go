package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGeneratesBothFormats(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"testdata/sample-repo", "--out", out}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}

	for _, name := range []string{"sbom.cdx.json", "sbom.spdx.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("expected %s to be written: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "vulns.json")); err == nil {
		t.Errorf("vulns.json must not be written in offline mode")
	}
	if !strings.Contains(stdout.String(), "scanned 3 manifest(s), found 5 package(s)") {
		t.Errorf("unexpected summary output: %q", stdout.String())
	}

	data, err := os.ReadFile(filepath.Join(out, "sbom.cdx.json"))
	if err != nil {
		t.Fatalf("read cdx output: %v", err)
	}
	var cdx map[string]any
	if err := json.Unmarshal(data, &cdx); err != nil {
		t.Fatalf("invalid cdx json: %v", err)
	}
	if cdx["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", cdx["bomFormat"])
	}
}

func TestRunFormatCDXOnly(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	var stdout bytes.Buffer
	if err := run([]string{"testdata/sample-repo", "--format", "cdx", "--out", out}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "sbom.cdx.json")); err != nil {
		t.Errorf("sbom.cdx.json should exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "sbom.spdx.json")); err == nil {
		t.Errorf("sbom.spdx.json must not be written with --format cdx")
	}
}

func TestRunFlagsAfterPath(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	var stdout bytes.Buffer
	// Flags placed after the positional path must still parse.
	if err := run([]string{"testdata/sample-repo", "--format", "spdx", "--out", out}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "sbom.spdx.json")); err != nil {
		t.Errorf("sbom.spdx.json should exist: %v", err)
	}
}

func TestRunQuietSuppressesOutput(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"testdata/sample-repo", "--quiet", "--out", out}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty in quiet mode", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty when there are no warnings", stderr.String())
	}
}

func TestRunVersionFlag(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if err := run([]string{"--version"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "sbom-tool 1.0.0" {
		t.Errorf("version output = %q, want %q", got, "sbom-tool 1.0.0")
	}
}

func TestRunRejectsBadFormat(t *testing.T) {
	t.Parallel()

	err := run([]string{"testdata/sample-repo", "--format", "pdf"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "invalid --format") {
		t.Errorf("err = %v, want invalid --format error", err)
	}
}

func TestRunRequiresPath(t *testing.T) {
	t.Parallel()

	if err := run(nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Errorf("run without a path should fail")
	}
}

func TestRunMissingDirectory(t *testing.T) {
	t.Parallel()

	err := run([]string{"testdata/does-not-exist"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Errorf("run on a missing directory should fail")
	}
}
