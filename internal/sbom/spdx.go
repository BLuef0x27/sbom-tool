package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/BLuef0x27/sbom-tool/internal/manifest"
)

const (
	spdxVersion       = "SPDX-2.3"
	spdxDataLicense   = "CC0-1.0"
	spdxNamespaceBase = "https://spdx.org/spdxdocs/sbom-tool-"
	spdxDocID         = "SPDXRef-DOCUMENT"
)

// SPDXDocument is an SPDX 2.3 document.
type SPDXDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	DocumentNamespace string             `json:"documentNamespace"`
	Name              string             `json:"name"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// spdxPackage is one package in the document. File level analysis is not
// performed, so filesAnalyzed is false and license fields carry NOASSERTION
// as the SPDX specification requires when values are unknown.
type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// NewSPDX renders packages into an SPDX 2.3 document. The document namespace
// embeds a UUIDv5 derived from the sorted package set, so rescanning an
// unchanged dependency tree produces the same namespace. Packages are
// expected in the sorted order produced by manifest.Scan.
func NewSPDX(packages []manifest.Package, toolVersion string, now time.Time, root string) *SPDXDocument {
	uuid := uuidV5("sbom-tool:spdx:" + fingerprint(packages))

	pkgs := make([]spdxPackage, 0, len(packages))
	rels := make([]spdxRelationship, 0, len(packages))
	for _, p := range packages {
		purl := PackageURL(p)
		id := spdxPackageID(purl)
		pkgs = append(pkgs, spdxPackage{
			Name:        p.Name,
			SPDXID:      id,
			VersionInfo: p.Version, // omitted when unpinned via omitempty
			// The SPDX spec requires these fields even when nothing is
			// known; NOASSERTION is the specified placeholder.
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
			CopyrightText:    "NOASSERTION",
			ExternalRefs: []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			}},
		})
		rels = append(rels, spdxRelationship{
			SPDXElementID:      spdxDocID,
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: id,
		})
	}

	return &SPDXDocument{
		SPDXVersion:       spdxVersion,
		DataLicense:       spdxDataLicense,
		SPDXID:            spdxDocID,
		DocumentNamespace: spdxNamespaceBase + uuid,
		Name:              "sbom-tool-" + sanitizeSPDXRef(filepath.Base(root)),
		CreationInfo: spdxCreationInfo{
			Created:  now.Format(time.RFC3339),
			Creators: []string{"Tool: sbom-tool-" + toolVersion},
		},
		Packages:      pkgs,
		Relationships: rels,
	}
}

// spdxPackageID builds a unique, deterministic SPDXRef id from a purl. The
// short hash suffix guards against collisions introduced by sanitization.
func spdxPackageID(purl string) string {
	sum := sha256.Sum256([]byte(purl))
	return fmt.Sprintf("SPDXRef-Package-%s-%s", sanitizeSPDXRef(purl), hex.EncodeToString(sum[:4]))
}

// sanitizeSPDXRef keeps only the characters SPDX element ids allow
// (letters, digits, ".", "-") and replaces everything else with "-".
func sanitizeSPDXRef(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '.', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
