package sbom

import (
	"fmt"
	"strings"

	"github.com/BLuef0x27/sbom-tool/internal/manifest"
)

// fingerprint builds a canonical string describing the package set. Callers
// pass the sorted, deduplicated list produced by manifest.Scan, so the same
// dependency tree always yields the same fingerprint and therefore the same
// document identifiers.
func fingerprint(packages []manifest.Package) string {
	parts := make([]string, 0, len(packages))
	for _, p := range packages {
		parts = append(parts, fmt.Sprintf("%s\x1f%s\x1f%s", p.Ecosystem, p.Name, p.Version))
	}
	return strings.Join(parts, "\x1e")
}
