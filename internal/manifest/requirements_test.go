package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRequirementsTxtFixture(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "requirements.txt")
	pkgs, err := parseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("parseRequirementsTxt: %v", err)
	}
	want := []Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: EcosystemPyPI, Source: path},
		{Name: "numpy", Version: "1.26.4", Ecosystem: EcosystemPyPI, Source: path},
		{Name: "django", Version: "", Ecosystem: EcosystemPyPI, Source: path},
		{Name: "flask", Version: "", Ecosystem: EcosystemPyPI, Source: path},
		{Name: "urllib3", Version: "2.2.1", Ecosystem: EcosystemPyPI, Source: path},
		{Name: "click", Version: "", Ecosystem: EcosystemPyPI, Source: path},
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

func TestParseRequirementsTxtEdgeCases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	content := "requests[security,socks]==2.31.0\n" +
		"\"Click\"==8.1.7\n" +
		"urllib3==\\\n" +
		"  2.2.1\n" +
		"My_Pkg==1.0.0\n" +
		"pandas>=2.0\n" +
		"web==1.0 ; python_version < \"3.10\" # marker and comment\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	pkgs, err := parseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("parseRequirementsTxt: %v", err)
	}
	want := []Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: EcosystemPyPI, Source: path}, // extras stripped
		{Name: "click", Version: "8.1.7", Ecosystem: EcosystemPyPI, Source: path},     // quotes stripped
		{Name: "urllib3", Version: "2.2.1", Ecosystem: EcosystemPyPI, Source: path},   // continuation joined
		{Name: "my-pkg", Version: "1.0.0", Ecosystem: EcosystemPyPI, Source: path},    // normalized
		{Name: "pandas", Version: "", Ecosystem: EcosystemPyPI, Source: path},         // range, unpinned
		{Name: "web", Version: "1.0", Ecosystem: EcosystemPyPI, Source: path},         // marker stripped
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
