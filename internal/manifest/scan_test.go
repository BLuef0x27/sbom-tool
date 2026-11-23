package manifest

import (
	"path/filepath"
	"testing"
)

func TestScanSampleRepo(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "sample-repo")

	var warnings []string
	pkgs, manifests, err := Scan(root, func(msg string) { warnings = append(warnings, msg) })
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(manifests) != 3 {
		t.Errorf("manifests found = %d (%v), want 3", len(manifests), manifests)
	}

	// Scan sorts by ecosystem (Go < PyPI < npm), then name, then version.
	want := []Package{
		{Name: "github.com/pkg/errors", Version: "v0.9.1", Ecosystem: EcosystemGo},
		{Name: "golang.org/x/text", Version: "v0.14.0", Ecosystem: EcosystemGo, Indirect: true},
		{Name: "requests", Version: "2.31.0", Ecosystem: EcosystemPyPI},
		{Name: "@babel/core", Version: "7.23.5", Ecosystem: EcosystemNPM},
		{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNPM},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("packages = %d (%+v), want %d", len(pkgs), pkgs, len(want))
	}
	for i, w := range want {
		got := pkgs[i]
		if got.Name != w.Name || got.Version != w.Version || got.Ecosystem != w.Ecosystem || got.Indirect != w.Indirect {
			t.Errorf("package[%d] = %+v, want %+v", i, got, w)
		}
	}

	// Dependency store internals and VCS metadata must not leak packages.
	for _, p := range pkgs {
		if p.Name == "evil" || p.Name == "should-not-appear" {
			t.Errorf("skipped directory leaked package %q", p.Name)
		}
	}
}

func TestScanMissingRoot(t *testing.T) {
	t.Parallel()

	if _, _, err := Scan(filepath.Join("testdata", "does-not-exist"), nil); err == nil {
		t.Errorf("Scan on a missing directory should fail")
	}
}

func TestDedupeAndSort(t *testing.T) {
	t.Parallel()

	pkgs := []Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNPM},
		{Name: "@babel/core", Version: "7.23.5", Ecosystem: EcosystemNPM},
		{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNPM},
		{Name: "requests", Version: "2.31.0", Ecosystem: EcosystemPyPI},
		{Name: "lodash", Version: "4.17.20", Ecosystem: EcosystemNPM},
	}
	pkgs = dedupe(pkgs)
	sortPackages(pkgs)

	if len(pkgs) != 4 {
		t.Fatalf("packages = %d (%+v), want 4", len(pkgs), pkgs)
	}
	wantNames := []string{"requests", "@babel/core", "lodash", "lodash"}
	wantVersions := []string{"2.31.0", "7.23.5", "4.17.20", "4.17.21"}
	for i := range wantNames {
		if pkgs[i].Name != wantNames[i] || pkgs[i].Version != wantVersions[i] {
			t.Errorf("package[%d] = %s@%s, want %s@%s",
				i, pkgs[i].Name, pkgs[i].Version, wantNames[i], wantVersions[i])
		}
	}
}
