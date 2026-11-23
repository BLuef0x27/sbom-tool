package sbom

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/BLuef0x27/sbom-tool/internal/manifest"
)

func testPackages() []manifest.Package {
	return []manifest.Package{
		{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", Ecosystem: manifest.EcosystemGo},
		{Name: "requests", Version: "2.31.0", Ecosystem: manifest.EcosystemPyPI},
		{Name: "lodash", Version: "4.17.21", Ecosystem: manifest.EcosystemNPM},
		{Name: "click", Version: "", Ecosystem: manifest.EcosystemPyPI},
	}
}

func testTime() time.Time {
	return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
}

func TestNewCycloneDXKeyFields(t *testing.T) {
	t.Parallel()

	doc := NewCycloneDX(testPackages(), "1.0.0", testTime(), "/home/dev/sample-repo")

	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.5" {
		t.Errorf("specVersion = %q, want 1.5", doc.SpecVersion)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	serialRe := regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !serialRe.MatchString(doc.SerialNumber) {
		t.Errorf("serialNumber %q is not a urn:uuid carrying a version 5 UUID", doc.SerialNumber)
	}
	if doc.Metadata == nil || doc.Metadata.Timestamp != "2026-11-23T12:00:00Z" {
		t.Errorf("metadata.timestamp missing or wrong: %+v", doc.Metadata)
	}
	if doc.Metadata.Tools == nil || len(doc.Metadata.Tools.Components) != 1 {
		t.Fatalf("metadata.tools missing or empty: %+v", doc.Metadata)
	}
	tool := doc.Metadata.Tools.Components[0]
	if tool.Type != "application" || tool.Name != "sbom-tool" || tool.Version != "1.0.0" {
		t.Errorf("tool metadata = %+v, want application sbom-tool 1.0.0", tool)
	}
	if doc.Metadata.Component == nil || doc.Metadata.Component.Name != "sample-repo" {
		t.Errorf("root component = %+v, want name sample-repo", doc.Metadata.Component)
	}
	if len(doc.Components) != 4 {
		t.Fatalf("components = %d, want 4", len(doc.Components))
	}

	byName := map[string]cdxComponent{}
	for _, c := range doc.Components {
		byName[c.Name] = c
	}
	wantPURLs := map[string]string{
		"github.com/gin-gonic/gin": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
		"requests":                 "pkg:pypi/requests@2.31.0",
		"lodash":                   "pkg:npm/lodash@4.17.21",
		"click":                    "pkg:pypi/click",
	}
	for name, want := range wantPURLs {
		c, ok := byName[name]
		if !ok {
			t.Fatalf("component %q missing", name)
		}
		if c.PURL != want {
			t.Errorf("%s purl = %q, want %q", name, c.PURL, want)
		}
		if c.BomRef != c.PURL {
			t.Errorf("%s bom-ref = %q, want purl %q", name, c.BomRef, c.PURL)
		}
		if c.Type != "library" {
			t.Errorf("%s type = %q, want library", name, c.Type)
		}
	}
	if byName["click"].Version != "" {
		t.Errorf("unpinned component version = %q, want empty", byName["click"].Version)
	}

	// The root dependency entry lists every direct package (none of the test
	// packages are Go indirect dependencies).
	if len(doc.Dependencies) != 1 || doc.Dependencies[0].Ref != "root:sample-repo" {
		t.Fatalf("dependencies = %+v, want a single root entry", doc.Dependencies)
	}
	if len(doc.Dependencies[0].DependsOn) != 4 {
		t.Errorf("root dependsOn = %d entries, want 4", len(doc.Dependencies[0].DependsOn))
	}
}

func TestNewCycloneDXJSONShape(t *testing.T) {
	t.Parallel()

	data, err := json.MarshalIndent(NewCycloneDX(testPackages(), "1.0.0", testTime(), "/repo"), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("top level key %q missing", key)
		}
	}
	meta, ok := generic["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata is not an object")
	}
	for _, key := range []string{"timestamp", "tools", "component"} {
		if _, ok := meta[key]; !ok {
			t.Errorf("metadata key %q missing", key)
		}
	}
}

func TestNewCycloneDXDeterministic(t *testing.T) {
	t.Parallel()

	first := NewCycloneDX(testPackages(), "1.0.0", testTime(), "/repo")
	second := NewCycloneDX(testPackages(), "1.0.0", testTime(), "/repo")
	if first.SerialNumber != second.SerialNumber {
		t.Errorf("serial numbers differ for identical input: %q vs %q", first.SerialNumber, second.SerialNumber)
	}
	a, errA := json.Marshal(first)
	b, errB := json.Marshal(second)
	if errA != nil || errB != nil {
		t.Fatalf("marshal: %v %v", errA, errB)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("serialized documents differ for identical input")
	}
}
