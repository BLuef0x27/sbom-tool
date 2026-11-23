package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BLuef0x27/sbom-tool/internal/manifest"
)

func osvTestPackages() []manifest.Package {
	return []manifest.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: manifest.EcosystemNPM},
		{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", Ecosystem: manifest.EcosystemGo},
		{Name: "click", Version: "", Ecosystem: manifest.EcosystemPyPI},
	}
}

// batchStub is a canned OSV.dev /v1/querybatch response. The real batch API
// returns only advisory summaries, so the stub mirrors that.
const batchStub = `{"results":[{"vulns":[{"id":"GHSA-pgw2-7h7q-67mq","summary":"Prototype pollution in lodash","aliases":["CVE-2020-8203"]},{"id":"CVE-2020-8203","summary":"Prototype pollution in lodash"}]},{"vulns":[]}]}`

// detailStubs map advisory ids to canned GET /v1/vulns/{id} responses with
// the full fields (severity, affected ranges) the batch API omits.
const detailLodash = `{"id":"GHSA-pgw2-7h7q-67mq","summary":"Prototype pollution in lodash","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"4.17.0"},{"fixed":"4.17.20"}]}]}]}`

const detailCVE = `{"id":"CVE-2020-8203","summary":"Prototype pollution in lodash","database_specific":{"severity":"HIGH"},"affected":[{"versions":["4.17.19","4.17.20","4.17.21"]}]}`

// osvTestServer builds an httptest server that answers both OSV.dev request
// kinds and records how many of each it served.
type osvTestServer struct {
	batchCalls  int
	detailCalls int
	mu          sync.Mutex

	batchStatus  int
	detailStatus int
}

func (s *osvTestServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			s.batchCalls++
			if s.batchStatus != 0 {
				w.WriteHeader(s.batchStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, batchStub)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/GHSA-pgw2-7h7q-67mq":
			s.detailCalls++
			if s.detailStatus != 0 {
				w.WriteHeader(s.detailStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, detailLodash)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/CVE-2020-8203":
			s.detailCalls++
			if s.detailStatus != 0 {
				w.WriteHeader(s.detailStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, detailCVE)
		default:
			t := "unexpected request: %s %s"
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, t, r.Method, r.URL.Path)
		}
	}
}

func (s *osvTestServer) counts() (batch, detail int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.batchCalls, s.detailCalls
}

func newTestClient(srv *httptest.Server, warn func(string)) *Client {
	return NewClient(
		WithEndpoint(srv.URL+"/v1/querybatch"),
		WithDetailEndpoint(srv.URL+"/v1/vulns"),
		WithWarn(warn),
	)
}

func TestBuildQueries(t *testing.T) {
	t.Parallel()

	pkgs := []manifest.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: manifest.EcosystemNPM},
		{Name: "unpinned", Ecosystem: manifest.EcosystemPyPI},
		{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", Ecosystem: manifest.EcosystemGo},
	}
	queries := BuildQueries(pkgs)
	if len(queries) != 2 {
		t.Fatalf("queries = %d, want 2 (unpinned packages are skipped)", len(queries))
	}
	if queries[0].Package.Name != "lodash" || queries[0].Package.Ecosystem != "npm" || queries[0].Version != "4.17.20" {
		t.Errorf("query 0 = %+v", queries[0])
	}
	if queries[1].Package.Name != "github.com/gin-gonic/gin" || queries[1].Package.Ecosystem != "Go" || queries[1].Version != "v1.9.1" {
		t.Errorf("query 1 = %+v", queries[1])
	}

	// The wire format must use the OSV.dev field names.
	data, err := json.Marshal(queries[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pkg, ok := generic["package"].(map[string]any)
	if !ok {
		t.Fatalf("query has no package object: %s", data)
	}
	for _, key := range []string{"name", "ecosystem"} {
		if _, ok := pkg[key]; !ok {
			t.Errorf("package key %q missing in %s", key, data)
		}
	}
	if _, ok := generic["version"]; !ok {
		t.Errorf("version key missing in %s", data)
	}
}

func TestMatchAll(t *testing.T) {
	t.Parallel()

	srvState := &osvTestServer{}
	srv := httptest.NewServer(srvState.handler())
	defer srv.Close()

	var warnings []string
	client := newTestClient(srv, func(msg string) { warnings = append(warnings, msg) })
	report := client.MatchAll(context.Background(), osvTestPackages())

	if report.PackagesQueried != 2 {
		t.Errorf("packages_queried = %d, want 2", report.PackagesQueried)
	}
	if report.PackagesSkippedUnpinned != 1 {
		t.Errorf("packages_skipped_unpinned = %d, want 1", report.PackagesSkippedUnpinned)
	}
	if report.Source != DefaultEndpoint {
		t.Errorf("source = %q, want %q", report.Source, DefaultEndpoint)
	}

	batch, detail := srvState.counts()
	if batch != 1 || detail != 2 {
		t.Errorf("HTTP calls = batch %d, detail %d; want 1, 2", batch, detail)
	}

	if len(report.Matches) != 2 {
		t.Fatalf("matches = %d, want 2", len(report.Matches))
	}
	m := report.Matches[0]
	if m.Package != "lodash" || m.Ecosystem != "npm" || m.Version != "4.17.20" {
		t.Errorf("match 0 = %+v", m)
	}
	if len(m.Vulns) != 2 {
		t.Fatalf("lodash advisories = %d, want 2", len(m.Vulns))
	}
	v := m.Vulns[0]
	if v.ID != "GHSA-pgw2-7h7q-67mq" {
		t.Errorf("id = %q", v.ID)
	}
	if v.Summary != "Prototype pollution in lodash" {
		t.Errorf("summary = %q", v.Summary)
	}
	if want := "CVSS_V3: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"; v.Severity != want {
		t.Errorf("severity = %q, want %q", v.Severity, want)
	}
	if want := []string{">= 4.17.0, < 4.17.20"}; !reflect.DeepEqual(v.AffectedVersions, want) {
		t.Errorf("affected versions = %+v, want %+v", v.AffectedVersions, want)
	}
	if want := []string{"CVE-2020-8203"}; !reflect.DeepEqual(v.Aliases, want) {
		t.Errorf("aliases = %+v, want %+v", v.Aliases, want)
	}
	second := m.Vulns[1]
	if second.ID != "CVE-2020-8203" {
		t.Errorf("second id = %q", second.ID)
	}
	if second.Severity != "HIGH" {
		t.Errorf("database_specific severity = %q, want HIGH", second.Severity)
	}
	// The explicit versions list is used without ranges; the cap itself is
	// covered by TestAffectedVersionStringsCapsExplicitList.
	if want := []string{"4.17.19", "4.17.20", "4.17.21"}; !reflect.DeepEqual(second.AffectedVersions, want) {
		t.Errorf("explicit versions = %+v, want %+v", second.AffectedVersions, want)
	}
	if got := second.AffectedVersions[0]; got != "4.17.19" {
		t.Errorf("first explicit version = %q, want 4.17.19", got)
	}
	if len(report.Matches[1].Vulns) != 0 {
		t.Errorf("gin advisories = %d, want 0", len(report.Matches[1].Vulns))
	}
	if report.PackagesWithVulns != 1 || report.TotalVulns != 2 {
		t.Errorf("counters = %d/%d, want 1/2", report.PackagesWithVulns, report.TotalVulns)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestMatchAllUsesCache(t *testing.T) {
	t.Parallel()

	srvState := &osvTestServer{}
	srv := httptest.NewServer(srvState.handler())
	defer srv.Close()

	client := newTestClient(srv, nil)
	pkgs := []manifest.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: manifest.EcosystemNPM},
		{Name: "gin", Version: "v1.9.1", Ecosystem: manifest.EcosystemGo},
	}
	first := client.MatchAll(context.Background(), pkgs)
	second := client.MatchAll(context.Background(), pkgs)

	batch, detail := srvState.counts()
	if batch != 1 || detail != 2 {
		t.Errorf("HTTP calls after two scans = batch %d, detail %d; want 1, 2 (the second scan must be served from the in-memory caches)", batch, detail)
	}
	if len(first.Matches) == 0 || len(second.Matches) == 0 {
		t.Fatalf("matches missing: %d %d", len(first.Matches), len(second.Matches))
	}
	if got := first.Matches[0].Vulns[0].ID; got != "GHSA-pgw2-7h7q-67mq" {
		t.Errorf("first result id = %q", got)
	}
	if got := second.Matches[0].Vulns[0].Severity; got == "" {
		t.Errorf("cached result lost the enriched severity")
	}
}

func TestMatchAllChunksBatches(t *testing.T) {
	t.Parallel()

	srvState := &osvTestServer{batchStatus: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srvState.mu.Lock()
		srvState.batchCalls++
		srvState.mu.Unlock()
		var parsed struct {
			Queries []Query `json:"queries"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Errorf("bad body: %v", err)
			return
		}
		results := make([]string, len(parsed.Queries))
		for i := range results {
			results[i] = "{}"
		}
		_, _ = io.WriteString(w, `{"results":[`+strings.Join(results, ",")+`]}`)
	}))
	defer srv.Close()

	var pkgs []manifest.Package
	for i := 0; i < 5; i++ {
		pkgs = append(pkgs, manifest.Package{
			Name:      "pkg" + strings.Repeat("x", i),
			Version:   "1.0.0",
			Ecosystem: manifest.EcosystemNPM,
		})
	}
	client := NewClient(WithEndpoint(srv.URL+"/v1/querybatch"), WithBatchSize(2))
	report := client.MatchAll(context.Background(), pkgs)

	if srvState.batchCalls != 3 {
		t.Errorf("batch requests = %d, want 3 (batches of 2, 2, 1)", srvState.batchCalls)
	}
	if report.PackagesQueried != 5 {
		t.Errorf("packages_queried = %d, want 5", report.PackagesQueried)
	}
}

func TestMatchAllToleratesFailure(t *testing.T) {
	t.Parallel()

	pkgs := []manifest.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: manifest.EcosystemNPM},
		{Name: "gin", Version: "v1.9.1", Ecosystem: manifest.EcosystemGo},
	}

	t.Run("batch returns HTTP 500", func(t *testing.T) {
		t.Parallel()
		srvState := &osvTestServer{batchStatus: http.StatusInternalServerError}
		srv := httptest.NewServer(srvState.handler())
		defer srv.Close()

		var warnings []string
		client := newTestClient(srv, func(msg string) { warnings = append(warnings, msg) })
		report := client.MatchAll(context.Background(), pkgs)

		if report.PackagesQueried != 2 {
			t.Errorf("packages_queried = %d, want 2", report.PackagesQueried)
		}
		for _, m := range report.Matches {
			if len(m.Vulns) != 0 {
				t.Errorf("match %s should carry no advisories after failure", m.Package)
			}
		}
		if len(warnings) == 0 {
			t.Errorf("a warning should be reported on API failure")
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := srv.URL
		srv.Close() // the port is now closed: every request is refused

		var warnings []string
		client := NewClient(
			WithEndpoint(url+"/v1/querybatch"),
			WithDetailEndpoint(url+"/v1/vulns"),
			WithWarn(func(msg string) { warnings = append(warnings, msg) }),
		)
		report := client.MatchAll(context.Background(), pkgs)

		if len(report.Matches) != 2 {
			t.Errorf("matches = %d, want 2 (the scan must still produce the package list)", len(report.Matches))
		}
		if len(warnings) == 0 {
			t.Errorf("a warning should be reported when the network is unreachable")
		}
	})

	t.Run("detail fetch failure keeps batch summary", func(t *testing.T) {
		t.Parallel()
		srvState := &osvTestServer{detailStatus: http.StatusInternalServerError}
		srv := httptest.NewServer(srvState.handler())
		defer srv.Close()

		var warnings []string
		client := newTestClient(srv, func(msg string) { warnings = append(warnings, msg) })
		report := client.MatchAll(context.Background(), pkgs)

		if len(report.Matches) == 0 || len(report.Matches[0].Vulns) != 2 {
			t.Fatalf("matches[0].vulns = %+v, want the two batch advisories", report.Matches)
		}
		v := report.Matches[0].Vulns[0]
		if v.ID != "GHSA-pgw2-7h7q-67mq" || v.Summary == "" {
			t.Errorf("degraded advisory = %+v, want id and summary kept", v)
		}
		if v.Severity != "" {
			t.Errorf("degraded advisory should have no severity, got %q", v.Severity)
		}
		if len(warnings) == 0 {
			t.Errorf("a warning should be reported when details are unavailable")
		}
	})
}

func TestAffectedVersionStrings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		vuln osvVuln
		want []string
	}{
		{
			name: "introduced then fixed",
			vuln: osvVuln{Affected: []osvAffected{{Ranges: []osvRange{{Events: []map[string]string{
				{"introduced": "4.17.0"}, {"fixed": "4.17.20"},
			}}}}}},
			want: []string{">= 4.17.0, < 4.17.20"},
		},
		{
			name: "introduced zero means all prior versions",
			vuln: osvVuln{Affected: []osvAffected{{Ranges: []osvRange{{Events: []map[string]string{
				{"introduced": "0"}, {"fixed": "1.5.0"},
			}}}}}},
			want: []string{"< 1.5.0"},
		},
		{
			name: "multiple introduced/fixed cycles",
			vuln: osvVuln{Affected: []osvAffected{{Ranges: []osvRange{{Events: []map[string]string{
				{"introduced": "1.0.0"}, {"fixed": "1.5.0"},
				{"introduced": "2.0.0"}, {"fixed": "2.3.0"},
			}}}}}},
			want: []string{">= 1.0.0, < 1.5.0", ">= 2.0.0, < 2.3.0"},
		},
		{
			name: "last affected",
			vuln: osvVuln{Affected: []osvAffected{{Ranges: []osvRange{{Events: []map[string]string{
				{"introduced": "1.0.0"}, {"last_affected": "1.9.9"},
			}}}}}},
			want: []string{">= 1.0.0, <= 1.9.9"},
		},
		{
			name: "explicit version list without ranges",
			vuln: osvVuln{Affected: []osvAffected{{Versions: []string{"1.2.3", "1.2.4"}}}},
			want: []string{"1.2.3", "1.2.4"},
		},
		{
			name: "ranges win over explicit versions",
			vuln: osvVuln{Affected: []osvAffected{{
				Versions: []string{"1.0.0", "1.0.1"},
				Ranges: []osvRange{{Events: []map[string]string{
					{"introduced": "0"}, {"fixed": "2.32.4"},
				}}},
			}}},
			want: []string{"< 2.32.4"},
		},
		{
			name: "no affected data",
			vuln: osvVuln{},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := affectedVersionStrings(tc.vuln); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("affectedVersionStrings = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAffectedVersionStringsCapsExplicitList(t *testing.T) {
	t.Parallel()

	versions := make([]string, 0, maxExplicitVersions+10)
	for i := 0; i < maxExplicitVersions+10; i++ {
		versions = append(versions, fmt.Sprintf("1.0.%d", i))
	}
	vuln := osvVuln{Affected: []osvAffected{{Versions: versions}}}
	got := affectedVersionStrings(vuln)
	if len(got) != maxExplicitVersions {
		t.Errorf("explicit list = %d entries, want %d (capped)", len(got), maxExplicitVersions)
	}
}

func TestReportJSONShape(t *testing.T) {
	t.Parallel()

	report := &Report{
		GeneratedAt: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
		Source:      DefaultEndpoint,
		Matches: []PackageMatch{{
			Package: "lodash", Ecosystem: "npm", Version: "4.17.20",
			Vulns: []Advisory{{ID: "GHSA-1", Summary: "s", Severity: "HIGH", AffectedVersions: []string{"< 4.17.20"}}},
		}},
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"generated_at", "source", "packages_queried", "packages_skipped_unpinned", "packages_with_vulnerabilities", "total_vulnerabilities", "matches"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("top level key %q missing", key)
		}
	}
	matchList, ok := generic["matches"].([]any)
	if !ok || len(matchList) != 1 {
		t.Fatalf("matches = %+v, want one entry", generic["matches"])
	}
	match := matchList[0].(map[string]any)
	for _, key := range []string{"package", "ecosystem", "version", "vulns"} {
		if _, ok := match[key]; !ok {
			t.Errorf("match key %q missing", key)
		}
	}
	vulnList := match["vulns"].([]any)
	if len(vulnList) != 1 {
		t.Fatalf("vulns = %+v, want one entry", match["vulns"])
	}
	advisory := vulnList[0].(map[string]any)
	for _, key := range []string{"id", "summary", "severity", "affected_versions"} {
		if _, ok := advisory[key]; !ok {
			t.Errorf("advisory key %q missing", key)
		}
	}
}
