package manifest

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// parseRequirementsTxt extracts dependencies from a pip requirements.txt
// file. Only "==" pins produce a version; range constraints are recorded as
// unpinned packages. Environment markers, inline comments, extras, line
// continuations, and pip options (-r, -e, --index-url) are handled.
func parseRequirementsTxt(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var raw []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw = append(raw, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var pkgs []Package
	for _, line := range joinContinuations(raw) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, ";"); idx >= 0 {
			// Strip environment markers such as ; python_version >= "3.9".
			line = line[:idx]
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			// Strip inline comments.
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			// pip options such as -r, -e, --index-url.
			continue
		}
		name, version, _ := splitRequirement(line)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   version,
			Ecosystem: EcosystemPyPI,
			Source:    path,
		})
	}
	return pkgs, nil
}

// joinContinuations merges requirement lines ending with a backslash into
// single logical lines.
func joinContinuations(lines []string) []string {
	var logical []string
	var buf string
	for _, raw := range lines {
		t := strings.TrimSpace(raw)
		if strings.HasSuffix(t, "\\") {
			buf += strings.TrimSuffix(t, "\\") + " "
			continue
		}
		logical = append(logical, buf+t)
		buf = ""
	}
	if buf != "" {
		logical = append(logical, buf)
	}
	return logical
}

// splitRequirement extracts the package name and, when present, the pinned
// version from a requirement line. isPinned reports whether the line carried
// an "==" (or "===") pin.
func splitRequirement(line string) (name, version string, isPinned bool) {
	if idx := strings.Index(line, "=="); idx >= 0 {
		name = strings.TrimSpace(line[:idx])
		rest := line[idx+2:]
		if strings.HasPrefix(rest, "=") {
			// Arbitrary equality ("===") pins an arbitrary string.
			rest = rest[1:]
		}
		return cleanName(name), cleanVersion(rest), true
	}
	name = line
	// Range constraints (>=, <=, ~=, !=, <, >, =) mean the version is not
	// pinned; record the name only.
	for _, op := range []string{"<=", ">=", "~=", "!=", "<", ">", "="} {
		if idx := strings.Index(name, op); idx >= 0 {
			name = name[:idx]
		}
	}
	if idx := strings.IndexAny(name, " \t"); idx >= 0 {
		name = name[:idx]
	}
	return cleanName(name), "", false
}

// cleanName trims whitespace, quotes, and extras ("pkg[extra]") and applies
// the PyPI name normalization (lowercase, underscores become dashes) that
// both PyPI and OSV.dev use.
func cleanName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Trim(name, "\"'")
	if idx := strings.IndexAny(name, "[ \t"); idx >= 0 {
		name = name[:idx]
	}
	name = strings.ToLower(name)
	return strings.ReplaceAll(name, "_", "-")
}

// cleanVersion trims whitespace and surrounding quotes from a pinned version.
func cleanVersion(v string) string {
	return strings.Trim(strings.TrimSpace(v), "\"'")
}
