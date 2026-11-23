package manifest

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// parseGoMod extracts dependencies from a go.mod file. It handles single line
// require statements and require blocks, records "// indirect" markers, and
// ignores module, go, toolchain, exclude, replace, and retract directives.
// Replace and exclude directives are not resolved: the version from the
// require line is reported exactly as written.
func parseGoMod(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var pkgs []Package
	inRequireBlock := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if inRequireBlock {
			if strings.HasPrefix(line, ")") {
				inRequireBlock = false
				continue
			}
			pkgs = append(pkgs, parseRequireLine(line)...)
			continue
		}
		if !strings.HasPrefix(line, "require") {
			// module, go, toolchain, exclude, replace, retract directives
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "require"))
		switch {
		case rest == "(":
			inRequireBlock = true
		case rest != "":
			pkgs = append(pkgs, parseRequireLine(rest)...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	for i := range pkgs {
		pkgs[i].Source = path
	}
	return pkgs, nil
}

// parseRequireLine parses one "path version [// indirect]" entry. Malformed
// entries are dropped so a single bad line cannot fail the whole manifest.
func parseRequireLine(line string) []Package {
	indirect := false
	if idx := strings.Index(line, "//"); idx >= 0 {
		indirect = strings.Contains(line[idx:], "indirect")
		line = strings.TrimSpace(line[:idx])
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	return []Package{{
		Name:      fields[0],
		Version:   fields[1],
		Ecosystem: EcosystemGo,
		Indirect:  indirect,
	}}
}
