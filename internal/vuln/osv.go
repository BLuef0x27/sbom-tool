// Package vuln matches scanned packages against the OSV.dev advisory database
// using the batch query API, then enriches every match with the full advisory
// details (severity, affected versions) from the per advisory endpoint.
package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/BLuef0x27/sbom-tool/internal/manifest"
)

const (
	// DefaultEndpoint is the OSV.dev batch query endpoint.
	DefaultEndpoint = "https://api.osv.dev/v1/querybatch"
	// DefaultDetailEndpoint is the OSV.dev per advisory endpoint used to
	// enrich batch results with severity and affected version ranges.
	DefaultDetailEndpoint = "https://api.osv.dev/v1/vulns"
)

// defaultBatchSize caps the number of queries sent per HTTP request. OSV.dev
// accepts large batches; 500 keeps every request comfortably within limits.
const defaultBatchSize = 500

// maxExplicitVersions caps how many entries of an advisory's explicit
// versions list are rendered. Some advisories list hundreds of versions
// while also carrying ranges; the ranges are the useful form.
const maxExplicitVersions = 25

// Query is one OSV.dev vulnerability query: a package at a version within an
// ecosystem.
type Query struct {
	Package QueryPackage `json:"package"`
	Version string       `json:"version"`
}

// QueryPackage names the queried package and its OSV ecosystem.
type QueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// BuildQueries converts packages into OSV.dev batch queries. Packages without
// a pinned version are skipped because advisories are matched per version.
func BuildQueries(packages []manifest.Package) []Query {
	queries := make([]Query, 0, len(packages))
	for _, p := range packages {
		if p.Version == "" {
			continue
		}
		queries = append(queries, Query{
			Package: QueryPackage{Name: p.Name, Ecosystem: string(p.Ecosystem)},
			Version: p.Version,
		})
	}
	return queries
}

// Client queries OSV.dev in batches, enriches matches with full advisory
// details, and caches both response kinds in memory for the lifetime of the
// client. All network failures are non fatal: they are reported through the
// warn callback and yield degraded results instead of errors.
type Client struct {
	endpoint       string
	detailEndpoint string
	batchSize      int
	http           *http.Client
	warn           func(string)

	mu            sync.Mutex
	queryCache    map[string][]Advisory
	advisoryCache map[string]Advisory
}

// Option configures a Client.
type Option func(*Client)

// WithEndpoint overrides the OSV.dev batch endpoint (used by tests).
func WithEndpoint(endpoint string) Option {
	return func(c *Client) { c.endpoint = endpoint }
}

// WithDetailEndpoint overrides the OSV.dev advisory detail endpoint (used by
// tests).
func WithDetailEndpoint(endpoint string) Option {
	return func(c *Client) { c.detailEndpoint = endpoint }
}

// WithBatchSize overrides the per request query limit.
func WithBatchSize(n int) Option {
	return func(c *Client) { c.batchSize = n }
}

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.http = hc }
}

// WithWarn sets the callback for non fatal diagnostics. It may be nil.
func WithWarn(warn func(string)) Option {
	return func(c *Client) { c.warn = warn }
}

// NewClient returns a ready to use OSV.dev client.
func NewClient(opts ...Option) *Client {
	c := &Client{
		endpoint:       DefaultEndpoint,
		detailEndpoint: DefaultDetailEndpoint,
		batchSize:      defaultBatchSize,
		http:           &http.Client{Timeout: 30 * time.Second},
		queryCache:     make(map[string][]Advisory),
		advisoryCache:  make(map[string]Advisory),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// MatchAll queries OSV.dev for every package with a pinned version and
// returns a report whose Matches preserve the input order. Unpinned packages
// are counted in PackagesSkippedUnpinned and never hit the network.
func (c *Client) MatchAll(ctx context.Context, packages []manifest.Package) *Report {
	report := &Report{
		GeneratedAt: time.Now().UTC(),
		Source:      DefaultEndpoint,
		Matches:     []PackageMatch{},
	}

	matches := make([]PackageMatch, 0, len(packages))
	pending := make(map[int]Query)
	for _, p := range packages {
		if p.Version == "" {
			report.PackagesSkippedUnpinned++
			continue
		}
		idx := len(matches)
		matches = append(matches, PackageMatch{
			Package:   p.Name,
			Ecosystem: string(p.Ecosystem),
			Version:   p.Version,
			Vulns:     []Advisory{},
		})
		key := cacheKey(string(p.Ecosystem), p.Name, p.Version)
		if cached, ok := c.lookupQuery(key); ok {
			matches[idx].Vulns = cached
			continue
		}
		pending[idx] = Query{
			Package: QueryPackage{Name: p.Name, Ecosystem: string(p.Ecosystem)},
			Version: p.Version,
		}
	}
	report.PackagesQueried = len(matches)

	idxs := slices.Sorted(maps.Keys(pending))
	for start := 0; start < len(idxs); start += c.batchSize {
		end := min(start+c.batchSize, len(idxs))
		chunk := idxs[start:end]

		queries := make([]Query, 0, len(chunk))
		for _, idx := range chunk {
			queries = append(queries, pending[idx])
		}

		results, err := c.batch(ctx, queries)
		if err != nil {
			c.warnf("OSV.dev batch query failed; continuing without vulnerability data: %v", err)
			continue
		}
		for i, idx := range chunk {
			if i >= len(results) {
				c.warnf("OSV.dev response truncated; no data for %d package(s)", len(chunk)-i)
				break
			}
			advisories := make([]Advisory, 0, len(results[i].Vulns))
			for _, v := range results[i].Vulns {
				advisories = append(advisories, convertVuln(v))
			}
			matches[idx].Vulns = advisories

			q := pending[idx]
			c.storeQuery(cacheKey(q.Package.Ecosystem, q.Package.Name, q.Version), advisories)
		}
	}

	c.enrichMatches(ctx, matches)

	report.Matches = matches
	for _, m := range matches {
		if len(m.Vulns) > 0 {
			report.PackagesWithVulns++
			report.TotalVulns += len(m.Vulns)
		}
	}
	return report
}

// batchResponse and batchResult mirror the OSV.dev batch API response shape.
type batchResponse struct {
	Results []batchResult `json:"results"`
}

type batchResult struct {
	Vulns []osvVuln `json:"vulns"`
}

// batch sends one POST carrying the given queries and returns the per query
// results. The returned slice may be shorter than queries when the API
// truncates its response.
func (c *Client) batch(ctx context.Context, queries []Query) ([]batchResult, error) {
	body, err := json.Marshal(struct {
		Queries []Query `json:"queries"`
	}{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("encode batch query: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", c.endpoint, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s: unexpected HTTP status %s", c.endpoint, resp.Status)
	}
	var parsed batchResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return parsed.Results, nil
}

// enrichMatches replaces every batch summary advisory with the full advisory
// fetched from the detail endpoint. Detail lookups are cached by advisory id.
// When a detail fetch fails, the batch summary is kept and a warning is
// reported, so a degraded match is always visible.
func (c *Client) enrichMatches(ctx context.Context, matches []PackageMatch) {
	for mi := range matches {
		for ai := range matches[mi].Vulns {
			summary := matches[mi].Vulns[ai]
			if summary.ID == "" {
				continue
			}
			if full, ok := c.lookupAdvisory(summary.ID); ok {
				matches[mi].Vulns[ai] = full
				continue
			}
			full, err := c.fetchVuln(ctx, summary.ID)
			if err != nil {
				c.warnf("OSV.dev advisory details for %s unavailable; keeping batch summary: %v", summary.ID, err)
				c.storeAdvisory(summary.ID, summary)
				continue
			}
			full = mergeSummary(full, summary)
			c.storeAdvisory(summary.ID, full)
			matches[mi].Vulns[ai] = full
		}
	}
}

// fetchVuln retrieves one full advisory from the OSV.dev detail endpoint.
func (c *Client) fetchVuln(ctx context.Context, id string) (Advisory, error) {
	endpoint := c.detailEndpoint + "/" + url.PathEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Advisory{}, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Advisory{}, fmt.Errorf("GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return Advisory{}, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Advisory{}, fmt.Errorf("GET %s: unexpected HTTP status %s", endpoint, resp.Status)
	}
	var v osvVuln
	if err := json.Unmarshal(data, &v); err != nil {
		return Advisory{}, fmt.Errorf("decode response: %w", err)
	}
	return convertVuln(v), nil
}

// mergeSummary fills advisory fields the batch summary may have carried but
// the detail response omitted.
func mergeSummary(full, summary Advisory) Advisory {
	if full.ID == "" {
		full.ID = summary.ID
	}
	if full.Summary == "" {
		full.Summary = summary.Summary
	}
	if len(full.Aliases) == 0 {
		full.Aliases = summary.Aliases
	}
	return full
}

// Advisory is an OSV.dev advisory reduced to the fields sbom-tool reports.
type Advisory struct {
	ID               string   `json:"id"`
	Summary          string   `json:"summary,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Aliases          []string `json:"aliases,omitempty"`
	AffectedVersions []string `json:"affected_versions,omitempty"`
}

// osvVuln mirrors the subset of the OSV.dev advisory schema sbom-tool reads.
type osvVuln struct {
	ID               string               `json:"id"`
	Summary          string               `json:"summary"`
	Aliases          []string             `json:"aliases"`
	Severity         []osvSeverity        `json:"severity"`
	Affected         []osvAffected        `json:"affected"`
	DatabaseSpecific *osvDatabaseSpecific `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Versions []string   `json:"versions"`
	Ranges   []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

// convertVuln maps an OSV.dev advisory onto the reported Advisory shape.
// Severity prefers the structured severity list and falls back to the
// database_specific severity string.
func convertVuln(v osvVuln) Advisory {
	a := Advisory{
		ID:               v.ID,
		Summary:          v.Summary,
		Aliases:          v.Aliases,
		AffectedVersions: affectedVersionStrings(v),
	}
	if len(v.Severity) > 0 && v.Severity[0].Score != "" {
		a.Severity = strings.TrimSpace(v.Severity[0].Type + ": " + v.Severity[0].Score)
	} else if v.DatabaseSpecific != nil && v.DatabaseSpecific.Severity != "" {
		a.Severity = v.DatabaseSpecific.Severity
	}
	return a
}

// affectedVersionStrings renders human readable affected version ranges from
// OSV range events. An introduced value of "0" means every version before
// the fixed or last_affected bound. Explicit version lists are used only
// when an affected entry carries no ranges, and are capped because some
// advisories list hundreds of versions.
func affectedVersionStrings(v osvVuln) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, aff := range v.Affected {
		if len(aff.Ranges) == 0 {
			for i, version := range aff.Versions {
				if i >= maxExplicitVersions {
					break
				}
				add(version)
			}
			continue
		}
		for _, r := range aff.Ranges {
			var current []string
			flush := func() {
				if len(current) > 0 {
					add(strings.Join(current, ", "))
				}
				current = nil
			}
			for _, ev := range r.Events {
				switch {
				case ev["introduced"] != "":
					flush()
					if ev["introduced"] != "0" {
						current = append(current, ">= "+ev["introduced"])
					}
				case ev["fixed"] != "":
					current = append(current, "< "+ev["fixed"])
					flush()
				case ev["last_affected"] != "":
					current = append(current, "<= "+ev["last_affected"])
					flush()
				}
			}
			flush()
		}
	}
	return out
}

// cacheKey builds the in-memory cache key for a package query.
func cacheKey(ecosystem, name, version string) string {
	return ecosystem + "\x00" + name + "\x00" + version
}

func (c *Client) lookupQuery(key string) ([]Advisory, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	got, ok := c.queryCache[key]
	return got, ok
}

func (c *Client) storeQuery(key string, advisories []Advisory) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queryCache[key] = advisories
}

func (c *Client) lookupAdvisory(id string) (Advisory, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	got, ok := c.advisoryCache[id]
	return got, ok
}

func (c *Client) storeAdvisory(id string, advisory Advisory) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advisoryCache[id] = advisory
}

func (c *Client) warnf(format string, args ...any) {
	if c.warn == nil {
		return
	}
	c.warn(fmt.Sprintf(format, args...))
}
