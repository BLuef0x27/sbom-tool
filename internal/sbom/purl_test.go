package sbom

import (
	"testing"

	"github.com/BLuef0x27/sbom-tool/internal/manifest"
)

func TestPackageURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		pkg  manifest.Package
		want string
	}{
		{
			name: "go module",
			pkg:  manifest.Package{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", Ecosystem: manifest.EcosystemGo},
			want: "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
		},
		{
			name: "go build metadata is percent encoded",
			pkg:  manifest.Package{Name: "example.com/lib", Version: "v2.0.0+incompatible", Ecosystem: manifest.EcosystemGo},
			want: "pkg:golang/example.com/lib@v2.0.0%2Bincompatible",
		},
		{
			name: "npm",
			pkg:  manifest.Package{Name: "lodash", Version: "4.17.21", Ecosystem: manifest.EcosystemNPM},
			want: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "npm scoped name encodes @ and keeps the slash",
			pkg:  manifest.Package{Name: "@babel/core", Version: "7.23.5", Ecosystem: manifest.EcosystemNPM},
			want: "pkg:npm/%40babel/core@7.23.5",
		},
		{
			name: "npm names are lowercased",
			pkg:  manifest.Package{Name: "Lodash", Version: "4.17.21", Ecosystem: manifest.EcosystemNPM},
			want: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "pypi",
			pkg:  manifest.Package{Name: "requests", Version: "2.31.0", Ecosystem: manifest.EcosystemPyPI},
			want: "pkg:pypi/requests@2.31.0",
		},
		{
			name: "unpinned packages use the versionless form",
			pkg:  manifest.Package{Name: "click", Ecosystem: manifest.EcosystemPyPI},
			want: "pkg:pypi/click",
		},
		{
			name: "unknown ecosystem",
			pkg:  manifest.Package{Name: "x", Version: "1", Ecosystem: "bogus"},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := PackageURL(tc.pkg); got != tc.want {
				t.Errorf("PackageURL(%+v) = %q, want %q", tc.pkg, got, tc.want)
			}
		})
	}
}
