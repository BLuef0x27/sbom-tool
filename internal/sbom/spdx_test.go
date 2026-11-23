package sbom

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestNewSPDXKeyFields(t *testing.T) {
	t.Parallel()

	doc := NewSPDX(testPackages(), "1.0.0", testTime(), "/home/dev/sample-repo")

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q, want SPDX-2.3", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense = %q, want CC0-1.0", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want SPDXRef-DOCUMENT", doc.SPDXID)
	}
	nsRe := regexp.MustCompile(`^https://spdx\.org/spdxdocs/sbom-tool-[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !nsRe.MatchString(doc.DocumentNamespace) {
		t.Errorf("documentNamespace %q does not carry a version 5 UUID", doc.DocumentNamespace)
	}
	if !strings.HasPrefix(doc.Name, "sbom-tool-") {
		t.Errorf("name = %q, want sbom-tool prefix", doc.Name)
	}
	if doc.CreationInfo.Created != "2026-11-23T12:00:00Z" {
		t.Errorf("creationInfo.created = %q, want RFC 3339 UTC timestamp", doc.CreationInfo.Created)
	}
	foundTool := false
	for _, c := range doc.CreationInfo.Creators {
		if c == "Tool: sbom-tool-1.0.0" {
			foundTool = true
		}
	}
	if !foundTool {
		t.Errorf("creators missing tool entry: %+v", doc.CreationInfo.Creators)
	}
	if len(doc.Packages) != 4 {
		t.Fatalf("packages = %d, want 4", len(doc.Packages))
	}

	byName := map[string]spdxPackage{}
	ids := map[string]bool{}
	for _, p := range doc.Packages {
		byName[p.Name] = p
		if ids[p.SPDXID] {
			t.Errorf("duplicate SPDXID %q", p.SPDXID)
		}
		ids[p.SPDXID] = true
	}

	lodash, ok := byName["lodash"]
	if !ok {
		t.Fatal("lodash package missing")
	}
	if lodash.VersionInfo != "4.17.21" {
		t.Errorf("lodash versionInfo = %q, want 4.17.21", lodash.VersionInfo)
	}
	if lodash.DownloadLocation != "NOASSERTION" {
		t.Errorf("lodash downloadLocation = %q, want NOASSERTION", lodash.DownloadLocation)
	}
	if lodash.FilesAnalyzed {
		t.Errorf("lodash filesAnalyzed = true, want false")
	}
	if lodash.LicenseConcluded != "NOASSERTION" || lodash.LicenseDeclared != "NOASSERTION" || lodash.CopyrightText != "NOASSERTION" {
		t.Errorf("lodash license/copyright fields = %+v, want NOASSERTION values", lodash)
	}
	if len(lodash.ExternalRefs) != 1 {
		t.Fatalf("lodash externalRefs = %+v, want one entry", lodash.ExternalRefs)
	}
	ref := lodash.ExternalRefs[0]
	if ref.ReferenceCategory != "PACKAGE-MANAGER" || ref.ReferenceType != "purl" || ref.ReferenceLocator != "pkg:npm/lodash@4.17.21" {
		t.Errorf("lodash externalRef = %+v, want PACKAGE-MANAGER purl pkg:npm/lodash@4.17.21", ref)
	}
	if !strings.HasPrefix(lodash.SPDXID, "SPDXRef-Package-") {
		t.Errorf("lodash SPDXID = %q, want SPDXRef-Package prefix", lodash.SPDXID)
	}

	click, ok := byName["click"]
	if !ok {
		t.Fatal("click package missing")
	}
	if click.VersionInfo != "" {
		t.Errorf("unpinned package versionInfo = %q, want empty", click.VersionInfo)
	}

	if len(doc.Relationships) != 4 {
		t.Fatalf("relationships = %d, want 4", len(doc.Relationships))
	}
	for _, r := range doc.Relationships {
		if r.SPDXElementID != "SPDXRef-DOCUMENT" || r.RelationshipType != "DESCRIBES" || r.RelatedSPDXElement == "" {
			t.Errorf("relationship = %+v, want DOCUMENT DESCRIBES package", r)
		}
	}
}

func TestNewSPDXJSONShape(t *testing.T) {
	t.Parallel()

	data, err := json.MarshalIndent(NewSPDX(testPackages(), "1.0.0", testTime(), "/repo"), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"spdxVersion", "dataLicense", "SPDXID", "documentNamespace", "name", "creationInfo", "packages", "relationships"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("top level key %q missing", key)
		}
	}
	ci, ok := generic["creationInfo"].(map[string]any)
	if !ok {
		t.Fatalf("creationInfo is not an object")
	}
	for _, key := range []string{"created", "creators"} {
		if _, ok := ci[key]; !ok {
			t.Errorf("creationInfo key %q missing", key)
		}
	}
}

func TestNewSPDXDeterministic(t *testing.T) {
	t.Parallel()

	first := NewSPDX(testPackages(), "1.0.0", testTime(), "/repo")
	second := NewSPDX(testPackages(), "1.0.0", testTime(), "/repo")
	if first.DocumentNamespace != second.DocumentNamespace {
		t.Errorf("document namespaces differ for identical input: %q vs %q",
			first.DocumentNamespace, second.DocumentNamespace)
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
