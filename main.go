// Command sbom-tool generates Software Bill of Materials (SBOM) documents
// (CycloneDX 1.5 and SPDX 2.3) from dependency manifests found under a
// repository root, and optionally matches the discovered packages against the
// OSV.dev advisory database.
//
// Usage:
//
//	sbom-tool <path> [--format cdx|spdx|both] [--online] [--out dir] [--quiet]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BLuef0x27/sbom-tool/internal/manifest"
	"github.com/BLuef0x27/sbom-tool/internal/sbom"
	"github.com/BLuef0x27/sbom-tool/internal/version"
	"github.com/BLuef0x27/sbom-tool/internal/vuln"
)

// Output file names written by the tool.
const (
	cdxOutFile   = "sbom.cdx.json"
	spdxOutFile  = "sbom.spdx.json"
	vulnsOutFile = "vulns.json"
)

// errUsageReported signals that the flag package already printed the error
// message and usage text, so main exits non-zero without printing again.
var errUsageReported = errors.New("usage already reported")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, errUsageReported) {
			fmt.Fprintln(os.Stderr, "sbom-tool:", err)
		}
		os.Exit(1)
	}
}

// run performs one scan and returns the process level error. Input and output
// streams are injected so the command is fully testable.
func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sbom-tool", flag.ContinueOnError)
	fs.SetOutput(stderr)

	format := fs.String("format", "both", "output format: cdx, spdx, or both")
	online := fs.Bool("online", false, "query the OSV.dev batch API for known vulnerabilities (default is offline)")
	outDir := fs.String("out", ".", "directory for generated files")
	quiet := fs.Bool("quiet", false, "suppress informational output; warnings and errors are still printed")
	showVersion := fs.Bool("version", false, "print the tool version and exit")
	fs.Usage = func() { printUsage(stderr) }

	if err := fs.Parse(reorderArgs(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errUsageReported
	}
	if *showVersion {
		fmt.Fprintf(stdout, "sbom-tool %s\n", version.Version)
		return nil
	}
	if fs.NArg() != 1 {
		printUsage(stderr)
		return fmt.Errorf("exactly one positional argument is required: the repository path to scan")
	}
	switch *format {
	case "cdx", "spdx", "both":
	default:
		return fmt.Errorf("invalid --format %q: expected cdx, spdx, or both", *format)
	}

	root, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("resolve scan path: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("scan path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("scan path %s is not a directory", root)
	}

	warn := func(msg string) {
		if *quiet {
			return
		}
		fmt.Fprintln(stderr, "warning:", msg)
	}

	pkgs, manifests, err := manifest.Scan(root, warn)
	if err != nil {
		return err
	}
	if len(manifests) == 0 {
		return fmt.Errorf("no supported dependency manifests found under %s (looked for go.mod, requirements.txt, and package-lock.json)", root)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	now := time.Now().UTC()

	var report *vuln.Report
	if *online {
		client := vuln.NewClient(vuln.WithWarn(warn))
		report = client.MatchAll(context.Background(), pkgs)
		if err := writeJSONFile(filepath.Join(*outDir, vulnsOutFile), report); err != nil {
			return err
		}
	} else if !*quiet {
		fmt.Fprintln(stdout, "offline mode: skipping vulnerability matching (pass --online to query OSV.dev)")
	}

	var written []string
	if *format == "cdx" || *format == "both" {
		path := filepath.Join(*outDir, cdxOutFile)
		if err := writeJSONFile(path, sbom.NewCycloneDX(pkgs, version.Version, now, root)); err != nil {
			return err
		}
		written = append(written, path)
	}
	if *format == "spdx" || *format == "both" {
		path := filepath.Join(*outDir, spdxOutFile)
		if err := writeJSONFile(path, sbom.NewSPDX(pkgs, version.Version, now, root)); err != nil {
			return err
		}
		written = append(written, path)
	}

	if !*quiet {
		fmt.Fprintf(stdout, "scanned %d manifest(s), found %d package(s)\n", len(manifests), len(pkgs))
		for _, path := range written {
			fmt.Fprintf(stdout, "wrote %s\n", path)
		}
		if report != nil {
			fmt.Fprintf(stdout, "wrote %s (%d package(s) queried, %d with advisories, %d advisories total)\n",
				filepath.Join(*outDir, vulnsOutFile),
				report.PackagesQueried, report.PackagesWithVulns, report.TotalVulns)
		}
	}
	return nil
}

// flagNeedsValue lists the flags that consume a separate value token; all
// other flags are boolean.
var flagNeedsValue = map[string]bool{
	"format": true,
	"out":    true,
}

// reorderArgs moves positional arguments to the end of the argument list so
// the standard flag package, which stops parsing at the first positional
// argument, accepts flags placed before or after the scan path.
func reorderArgs(args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			// Everything after the terminator is positional.
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positionals = append(positionals, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // value embedded as --name=value
		}
		if flagNeedsValue[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}

// writeJSONFile marshals v as indented JSON with a trailing newline and
// writes it to path.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// printUsage writes a hand rolled usage message that documents the positional
// argument as well as the flags.
func printUsage(w io.Writer) {
	fmt.Fprint(w, `sbom-tool generates SBOM documents (CycloneDX 1.5 and SPDX 2.3) from dependency
manifests found under a repository root, and can match the discovered packages
against the OSV.dev advisory database.

Usage:
  sbom-tool <path> [flags]

Arguments:
  <path>            repository root to scan recursively

Flags:
  --format string   output format: cdx, spdx, or both (default "both")
  --online          query the OSV.dev batch API for known vulnerabilities (default: offline)
  --out string      directory for generated files (default ".")
  --quiet           suppress informational output; warnings and errors still print
  --version         print the tool version and exit
`)
}
