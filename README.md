# sbom-tool

A Software Bill of Materials (SBOM) generator with vulnerability matching, written in Go using only the standard library.

sbom-tool scans a repository for dependency manifests (go.mod, requirements.txt, package-lock.json), builds a deduplicated package inventory, and writes standards based SBOM documents. With the --online flag it also matches every pinned package against the OSV.dev advisory database and writes a vulnerability report.

## What and why

Modern applications are mostly other people's code. When the next ecosystem wide vulnerability lands, the first question an engineering team must answer is: which of our projects contain the affected package, and at which version? A Software Bill of Materials answers that question mechanically instead of by grep archaeology.

Executive Order 14028 ("Improving the Nation's Cybersecurity", May 2021) made SBOMs part of the US federal software supply chain baseline: software sold to the US government must ship with a machine readable inventory of its components. CISA coordinates the follow-on work and recognizes SPDX and CycloneDX as the two formats in wide use. This tool targets exactly those two formats so its output can be consumed by existing tooling such as Dependency Track, Grype, OSV Scanner, and GitHub dependency review.

sbom-tool is a portfolio project for application security engineering. It favors small, auditable code: no third party dependencies, deterministic output, and a network client that stays off unless you ask for it.

## Features

- Recursive repository scanning for `go.mod`, `requirements.txt`, and `package-lock.json` (lockfileVersion 2 and 3, with a best effort v1 fallback)
- CycloneDX 1.5 JSON output with tool metadata, a root component, and a dependency graph entry
- SPDX 2.3 JSON output with purl external references and DESCRIBES relationships
- Package URLs (purl) for Go, PyPI, and npm packages, including scoped npm names
- Deterministic identifiers: the CycloneDX serial number and the SPDX document namespace are UUIDv5 values derived from the sorted package set, so an unchanged dependency tree always produces the same identifiers
- Vulnerability matching against the OSV.dev batch API with in-memory caching (opt in via --online)
- Graceful network handling: connectivity problems produce warnings and partial results, never a failed scan

## Install

Requires Go 1.23 or newer.

```bash
go install github.com/BLuef0x27/sbom-tool@latest
```

Or build from a source checkout:

```bash
git clone https://github.com/BLuef0x27/sbom-tool
cd sbom-tool
go build -o sbom-tool .
```

## Usage

```text
sbom-tool <path> [flags]
```

| Argument or flag | Default | Description |
| --- | --- | --- |
| `<path>` | (required) | Repository root to scan recursively |
| `--format` | `both` | Output format: `cdx`, `spdx`, or `both` |
| `--online` | off | Query the OSV.dev batch API for known vulnerabilities |
| `--out` | `.` | Directory for generated files |
| `--quiet` | off | Suppress informational output; warnings and errors still print |
| `--version` | off | Print the tool version and exit |

Examples:

```bash
# Generate both SBOMs for the current repository (offline)
sbom-tool .

# CycloneDX only, written to a dist folder
sbom-tool ~/projects/webapp --format cdx --out dist

# Generate both formats and match vulnerabilities against OSV.dev
sbom-tool . --online --out sbom-out

# Quiet mode for CI pipelines
sbom-tool . --quiet
```

## Output files

| File | Contents |
| --- | --- |
| `sbom.cdx.json` | CycloneDX 1.5 BOM: metadata (tool, timestamp, root component) plus one component per dependency with name, version, and purl |
| `sbom.spdx.json` | SPDX 2.3 document: creation info, one package per dependency with a purl external reference, DESCRIBES relationships |
| `vulns.json` | Vulnerability report (written only with `--online`): per package matches with advisory id, summary, affected versions, and severity when present |

## SBOM format notes

Both formats are generated from the same sorted, deduplicated package list. Versions keep their native form: Go module versions keep the `v` prefix, PyPI and npm versions are recorded exactly as pinned.

CycloneDX 1.5: `metadata.tools` records the generator, `metadata.component` describes the scanned root, and a `dependencies` entry lists what the root depends on (Go `// indirect` dependencies are excluded from that list because they are transitive). The `serialNumber` is a UUIDv5 computed from the package set, so identical inputs produce identical serial numbers and diffs between releases stay meaningful.

SPDX 2.3: `creationInfo.creators` records the generator, every package carries a purl `externalRefs` entry with category `PACKAGE-MANAGER`, and the document `DESCRIBES` each package. The `documentNamespace` embeds a UUIDv5 derived from the same package set.

Unpinned entries (requirements.txt lines without `==`) are still listed as components, but without a version. Vulnerability matching skips them because an advisory match requires a version.

## Vulnerability matching and offline mode

Vulnerability matching is off by default. This keeps scans fast, deterministic, and hermetic: an SBOM generator should never require network access, and CI jobs should not depend on api.osv.dev being reachable.

Pass `--online` to enable it. sbom-tool then:

1. Builds one OSV query per pinned package (`name`, `ecosystem`, `version`).
2. Sends them in batches of up to 500 queries per request to `POST https://api.osv.dev/v1/querybatch`, which returns matching advisory summaries.
3. Fetches the full advisory for every matched id from `GET https://api.osv.dev/v1/vulns/{id}` to collect the severity and the affected version ranges, which the batch endpoint deliberately omits.
4. Caches every response in memory for the lifetime of the run, so repeated packages and repeated advisories cost one request each.
5. Writes `vulns.json` with the matched advisories: id, summary, affected versions (rendered from OSV range events), and severity when the advisory carries one.

If the network or the API fails, sbom-tool prints a warning, leaves the affected packages with no advisories, still writes all SBOM files, and exits 0. If only the detail lookups fail, the batch summaries are kept and the missing fields are simply absent from `vulns.json`. Nothing is silently dropped: a warning makes every degraded result visible.

One rendering rule worth knowing: an advisory's explicit version list is used only when it carries no version ranges, and it is capped at 25 entries, because some advisories list hundreds of versions while the ranges say the same thing in one line.

## Architecture

```text
main.go                      CLI entry point: flags, orchestration, file writing
internal/manifest/           manifest detection and parsing
  scan.go                    recursive walk, filename dispatch, dedupe and sort
  gomod.go                   go.mod parser (require lines and blocks, indirect markers)
  requirements.go            requirements.txt parser (pins, markers, extras, continuations)
  packagelock.go             package-lock.json parser (v2/v3 packages map, v1 fallback)
internal/sbom/               SBOM serializers
  cdx.go                     CycloneDX 1.5 document model and builder
  spdx.go                    SPDX 2.3 document model and builder
  purl.go                    purl generation and percent encoding
  uuid.go                    deterministic UUIDv5 derivation
  fingerprint.go             canonical package set fingerprint
internal/vuln/               OSV.dev integration
  osv.go                     query builder, batch client, detail enrichment, in-memory caches
  report.go                  vulns.json data model
internal/version/            single source of the tool version string
testdata/sample-repo/        small fixture repo used by the scan and CLI tests
```

Data flow: `<path>` is walked, manifests are parsed into a uniform package list, the list is deduplicated and sorted, and then serialized into CycloneDX and/or SPDX documents. With `--online`, the same sorted list is matched against OSV.dev before the files are written.

Design notes:

- Standard library only: the parsers (go.mod line scanner, pip requirement syntax, npm lockfile JSON) are a few hundred lines that are easy to audit.
- Parsers never abort a scan on malformed input; they warn and continue.
- All network code lives in `internal/vuln`; tests exercise it against httptest servers, never the real API.

## Testing

```bash
go vet ./...
go test ./...
```

The test suite covers every parser, both serializers (key fields, JSON shape, and determinism), the purl builder, the UUID helper, the OSV query builder and batch client (including caching, batching, and failure tolerance), and an end to end CLI run against the testdata fixture. No test touches the network.

## Limitations

- go.mod `replace` and `exclude` directives are not resolved; versions come from the `require` lines as written.
- requirements.txt entries without an `==` pin are recorded without a version and skipped by vulnerability matching.
- package-lock.json v1 support is a best effort fallback; v2 and v3 are the supported formats.
- Vulnerability matching requires network access and is off by default.
- SBOM timestamps reflect the scan time; only the identifiers are deterministic.
- `node_modules/` and `.git/` directories are skipped during the walk; everything else is scanned.

## License

MIT. See [LICENSE](LICENSE).
