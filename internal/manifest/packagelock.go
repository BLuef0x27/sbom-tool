package manifest

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
)

// packageLockFile mirrors the top level of an npm package-lock.json. Version
// 2 and 3 use the flat "packages" map; version 1 uses the recursive
// "dependencies" tree, kept as a fallback.
type packageLockFile struct {
	Name            string                      `json:"name"`
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]packageLockEntry `json:"packages"`
	Dependencies    map[string]packageLockDepV1 `json:"dependencies"`
}

// packageLockEntry is one installed package in a v2/v3 lockfile.
type packageLockEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Link    bool   `json:"link"`
}

// packageLockDepV1 is one entry in a v1 lockfile dependency tree.
type packageLockDepV1 struct {
	Version      string                      `json:"version"`
	Dependencies map[string]packageLockDepV1 `json:"dependencies"`
}

// parsePackageLock extracts installed packages from an npm package-lock.json
// file. Workspace targets, links, and entries without a version are skipped;
// nested duplicate installs are preserved when their version differs and
// deduplicated later by the scan.
func parsePackageLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock packageLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var pkgs []Package
	if len(lock.Packages) > 0 {
		// lockfileVersion 2 and 3: flat packages map keyed by node_modules
		// paths. Sorted keys keep the output deterministic.
		for _, key := range slices.Sorted(maps.Keys(lock.Packages)) {
			entry := lock.Packages[key]
			if key == "" || entry.Link || entry.Version == "" {
				continue // root, workspace links, or versionless entries
			}
			if !strings.Contains(key, "node_modules/") {
				continue // workspace target packages, not installed deps
			}
			name := entry.Name
			if name == "" {
				name = packageNameFromLockKey(key)
			}
			if name == "" {
				continue
			}
			pkgs = append(pkgs, Package{
				Name:      strings.ToLower(name),
				Version:   entry.Version,
				Ecosystem: EcosystemNPM,
				Source:    path,
			})
		}
		return pkgs, nil
	}

	// lockfileVersion 1 fallback: recursive dependencies tree.
	var walk func(deps map[string]packageLockDepV1)
	walk = func(deps map[string]packageLockDepV1) {
		for _, name := range slices.Sorted(maps.Keys(deps)) {
			dep := deps[name]
			if dep.Version != "" {
				pkgs = append(pkgs, Package{
					Name:      strings.ToLower(name),
					Version:   dep.Version,
					Ecosystem: EcosystemNPM,
					Source:    path,
				})
			}
			if len(dep.Dependencies) > 0 {
				walk(dep.Dependencies)
			}
		}
	}
	walk(lock.Dependencies)
	return pkgs, nil
}

// packageNameFromLockKey derives the package name from a lockfile key such as
// "node_modules/@babel/core" or "node_modules/a/node_modules/b" by taking the
// segments after the last "node_modules/" separator.
func packageNameFromLockKey(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		return ""
	}
	return key[idx+len("node_modules/"):]
}
