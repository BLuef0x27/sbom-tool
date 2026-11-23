package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGoModFixture(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "go.mod")
	pkgs, err := parseGoMod(path)
	if err != nil {
		t.Fatalf("parseGoMod: %v", err)
	}
	want := []Package{
		{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", Ecosystem: EcosystemGo, Source: path},
		{Name: "golang.org/x/mod", Version: "v0.0.0-20240101000000-000000000000", Ecosystem: EcosystemGo, Indirect: true, Source: path},
		{Name: "golang.org/x/text", Version: "v0.14.0", Ecosystem: EcosystemGo, Indirect: true, Source: path},
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

func TestParseGoModSingleLineRequire(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	content := "module example.com/single\n\n" +
		"go 1.23\n\n" +
		"require github.com/pkg/errors v0.9.1\n" +
		"require(\n" +
		"\texample.com/other v1.2.3 // indirect\n" +
		")\n" +
		"require onlyname\n" // malformed entry must be dropped
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	pkgs, err := parseGoMod(path)
	if err != nil {
		t.Fatalf("parseGoMod: %v", err)
	}
	want := []Package{
		{Name: "github.com/pkg/errors", Version: "v0.9.1", Ecosystem: EcosystemGo, Source: path},
		{Name: "example.com/other", Version: "v1.2.3", Ecosystem: EcosystemGo, Indirect: true, Source: path},
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
