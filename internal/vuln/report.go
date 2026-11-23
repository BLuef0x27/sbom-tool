package vuln

import "time"

// PackageMatch pairs one scanned package with the advisories OSV.dev returned
// for it.
type PackageMatch struct {
	Package   string     `json:"package"`
	Ecosystem string     `json:"ecosystem"`
	Version   string     `json:"version"`
	Vulns     []Advisory `json:"vulns,omitempty"`
}

// Report is the summary written to vulns.json when running with --online.
type Report struct {
	GeneratedAt             time.Time      `json:"generated_at"`
	Source                  string         `json:"source"`
	PackagesQueried         int            `json:"packages_queried"`
	PackagesSkippedUnpinned int            `json:"packages_skipped_unpinned"`
	PackagesWithVulns       int            `json:"packages_with_vulnerabilities"`
	TotalVulns              int            `json:"total_vulnerabilities"`
	Matches                 []PackageMatch `json:"matches"`
}
