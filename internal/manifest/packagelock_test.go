package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePackageLockFixture(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "package-lock.json")
	pkgs, err := parsePackageLock(path)
	if err != nil {
		t.Fatalf("parsePackageLock: %v", err)
	}
	// Keys are processed in sorted order, so this ordering is deterministic.
	want := []Package{
		{Name: "@babel/core", Version: "7.23.5", Ecosystem: EcosystemNPM, Source: path},
		{Name: "chalk", Version: "2.4.2", Ecosystem: EcosystemNPM, Source: path},
		{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNPM, Source: path},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("parsed %d packages, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for i, w := range want {
		if pkgs[i] != w {
			t.Errorf("package[%d] = %+v, want %+v", i, pkgs[i], w)
		}
	}
	for _, p := range pkgs {
		if p.Name == "workspace-pkg" || p.Name == "linked-package" {
			t.Errorf("workspace or link entry leaked into packages: %+v", p)
		}
	}
}

func TestParsePackageLockV1Fallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	content := `{
  "name": "legacy-app",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {"version": "4.17.15"},
    "chalk": {"version": "2.4.2"},
    "nested": {"version": "1.0.0", "dependencies": {"inner": {"version": "0.1.0"}}},
    "empty": {"requires": true}
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	pkgs, err := parsePackageLock(path)
	if err != nil {
		t.Fatalf("parsePackageLock: %v", err)
	}
	want := []Package{
		{Name: "chalk", Version: "2.4.2", Ecosystem: EcosystemNPM, Source: path},
		{Name: "lodash", Version: "4.17.15", Ecosystem: EcosystemNPM, Source: path},
		{Name: "nested", Version: "1.0.0", Ecosystem: EcosystemNPM, Source: path},
		{Name: "inner", Version: "0.1.0", Ecosystem: EcosystemNPM, Source: path},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("parsed %d packages, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for i, w := range want {
		if pkgs[i] != w {
			t.Errorf("package[%d] = %+v, want %+v", i, pkgs[i], w)
		}
	}
}
