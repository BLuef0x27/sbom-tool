package sbom

import (
	"regexp"
	"testing"
)

func TestUUIDV5Deterministic(t *testing.T) {
	t.Parallel()

	a := uuidV5("sbom-tool:cdx:test")
	b := uuidV5("sbom-tool:cdx:test")
	if a != b {
		t.Errorf("uuidV5 not deterministic: %q vs %q", a, b)
	}
	if c := uuidV5("sbom-tool:spdx:test"); c == a {
		t.Errorf("different names produced the same UUID")
	}
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !re.MatchString(a) {
		t.Errorf("uuid %q is not a canonical version 5 UUID", a)
	}
}
