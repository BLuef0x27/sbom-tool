package manifest

import (
	"fmt"
	"io/fs"
	"path/filepath"
)

// skipDirs are directory names excluded from the recursive walk. Dependency
// store internals and VCS metadata never contain manifests that describe the
// scanned project.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
}

// parsers maps a supported manifest file name to its parser.
var parsers = map[string]func(string) ([]Package, error){
	"go.mod":            parseGoMod,
	"requirements.txt":  parseRequirementsTxt,
	"package-lock.json": parsePackageLock,
}

// Scan walks root recursively, parses every supported dependency manifest it
// finds, and returns the combined, deduplicated, sorted package list together
// with the manifest paths that were parsed. Manifests that cannot be read or
// parsed are reported through warn and skipped; they never abort the scan.
func Scan(root string, warn func(string)) ([]Package, []string, error) {
	var (
		pkgs      []Package
		manifests []string
	)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				// The root itself is unreadable or missing: that is fatal.
				return err
			}
			reportWarn(warn, fmt.Sprintf("skipping %s: %v", path, err))
			return nil
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		parse, ok := parsers[d.Name()]
		if !ok {
			return nil
		}
		found, err := parse(path)
		if err != nil {
			reportWarn(warn, err.Error())
			return nil
		}
		pkgs = append(pkgs, found...)
		manifests = append(manifests, path)
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("walk %s: %w", root, err)
	}
	pkgs = dedupe(pkgs)
	sortPackages(pkgs)
	return pkgs, manifests, nil
}

// reportWarn delivers a non fatal diagnostic, tolerating a nil callback.
func reportWarn(warn func(string), msg string) {
	if warn != nil {
		warn(msg)
	}
}
