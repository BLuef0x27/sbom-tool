// Package manifest detects and parses dependency manifests (go.mod,
// requirements.txt, and package-lock.json) into a uniform package list.
package manifest

import (
	"slices"
	"strings"
)

// Ecosystem identifies the package ecosystem a dependency belongs to. The
// values match the ecosystem names used by OSV.dev.
type Ecosystem string

// Supported ecosystems.
const (
	EcosystemGo   Ecosystem = "Go"
	EcosystemPyPI Ecosystem = "PyPI"
	EcosystemNPM  Ecosystem = "npm"
)

// Package is a single dependency discovered in a manifest.
type Package struct {
	// Name is the Go module path, the normalized PyPI distribution name
	// (lowercase, underscores replaced with dashes), or the lowercase npm
	// package name.
	Name string
	// Version is the pinned version exactly as recorded in the manifest. It
	// is empty when the manifest does not pin one (for example a
	// requirements.txt entry with only a range constraint).
	Version string
	// Ecosystem is the OSV.dev ecosystem name.
	Ecosystem Ecosystem
	// Indirect marks transitive Go dependencies ("// indirect" in go.mod).
	Indirect bool
	// Source is the path of the manifest the package was read from.
	Source string
}

// dedupe collapses packages that share ecosystem, name, and version, keeping
// the first occurrence in input order.
func dedupe(pkgs []Package) []Package {
	seen := make(map[string]struct{}, len(pkgs))
	out := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		key := string(p.Ecosystem) + "\x00" + p.Name + "\x00" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}

// sortPackages orders packages by ecosystem, name, and version so every
// generated artifact has a stable, deterministic component order.
func sortPackages(pkgs []Package) {
	slices.SortFunc(pkgs, func(a, b Package) int {
		if c := strings.Compare(string(a.Ecosystem), string(b.Ecosystem)); c != 0 {
			return c
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
}
