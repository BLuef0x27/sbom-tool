package sbom

import (
	"path/filepath"
	"time"

	"github.com/BLuef0x27/sbom-tool/internal/manifest"
)

const (
	cdxFormat     = "CycloneDX"
	cdxSpecVer    = "1.5"
	cdxRootPrefix = "root:"
)

// CycloneDX is a CycloneDX 1.5 BOM document.
type CycloneDX struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     *cdxMetadata    `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

// cdxMetadata carries generator and subject information. Tools use the 1.5
// form where the tools object wraps component entries.
type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     *cdxTools     `json:"tools"`
	Component *cdxComponent `json:"component"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

// cdxComponent is one software item in the BOM. Library dependencies use the
// purl as the bom-ref so references stay unique and stable.
type cdxComponent struct {
	Type    string `json:"type"`
	BomRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// NewCycloneDX renders packages into a CycloneDX 1.5 document. The serial
// number is a UUIDv5 derived from the sorted package set, so rescanning an
// unchanged dependency tree produces the same serial number. Packages are
// expected in the sorted order produced by manifest.Scan.
func NewCycloneDX(packages []manifest.Package, toolVersion string, now time.Time, root string) *CycloneDX {
	serial := uuidV5("sbom-tool:cdx:" + fingerprint(packages))

	components := make([]cdxComponent, 0, len(packages))
	direct := make([]string, 0, len(packages))
	for _, p := range packages {
		purl := PackageURL(p)
		components = append(components, cdxComponent{
			Type:    "library",
			BomRef:  purl,
			Name:    p.Name,
			Version: p.Version,
			PURL:    purl,
		})
		if !p.Indirect {
			direct = append(direct, purl)
		}
	}

	rootRef := cdxRootPrefix + filepath.Base(root)
	doc := &CycloneDX{
		BOMFormat:    cdxFormat,
		SpecVersion:  cdxSpecVer,
		SerialNumber: "urn:uuid:" + serial,
		Version:      1,
		Metadata: &cdxMetadata{
			Timestamp: now.Format(time.RFC3339),
			Tools: &cdxTools{Components: []cdxComponent{{
				Type:    "application",
				Name:    "sbom-tool",
				Version: toolVersion,
			}}},
			Component: &cdxComponent{
				Type:   "application",
				BomRef: rootRef,
				Name:   filepath.Base(root),
			},
		},
		Components: components,
	}
	if len(direct) > 0 {
		doc.Dependencies = []cdxDependency{{Ref: rootRef, DependsOn: direct}}
	}
	return doc
}
