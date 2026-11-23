package sbom

import (
	"fmt"
	"strings"

	"github.com/BLuef0x27/sbom-tool/internal/manifest"
)

// PackageURL returns the purl (Package URL) for a package, following the
// purl-spec type rules for golang, pypi, and npm. Packages without a version
// get the versionless form. It returns an empty string for unknown ecosystems.
//
// See https://github.com/package-url/purl-spec.
func PackageURL(p manifest.Package) string {
	var typ, name string
	switch p.Ecosystem {
	case manifest.EcosystemGo:
		typ = "golang"
		// Go module paths are slash separated; encode each segment.
		name = encodeSegments(p.Name)
	case manifest.EcosystemPyPI:
		typ = "pypi"
		name = encodeSegment(p.Name)
	case manifest.EcosystemNPM:
		typ = "npm"
		// npm names are case insensitive; the "@" of scoped packages is
		// percent encoded while the scope separator slash is preserved.
		name = encodeSegments(strings.ToLower(p.Name))
	default:
		return ""
	}
	if p.Version == "" {
		return "pkg:" + typ + "/" + name
	}
	return "pkg:" + typ + "/" + name + "@" + encodeSegment(p.Version)
}

// encodeSegments percent encodes each "/" separated segment individually so
// the separators are preserved.
func encodeSegments(s string) string {
	parts := strings.Split(s, "/")
	for i, part := range parts {
		parts[i] = encodeSegment(part)
	}
	return strings.Join(parts, "/")
}

// encodeSegment percent encodes every byte outside the unreserved purl
// character set (letters, digits, ".", "-", "_", "~") using uppercase hex.
func encodeSegment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '.', c == '-', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
