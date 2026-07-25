package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	// Adjust this import path based on your actual go.mod module name
	"javascript-security-scanner/internal/baseline"
	"javascript-security-scanner/internal/dataclass"
	"javascript-security-scanner/internal/deps"
	"javascript-security-scanner/internal/engine"
	"javascript-security-scanner/internal/fetcher"
	"javascript-security-scanner/internal/reporter"
)

// severityRank ranks severity strings so the --min-severity gate can
// compare findings consistently. Unknown values get the lowest rank
// so they are never filtered out by accident.
var severityRank = map[string]int{
	"LOW":      1,
	"MEDIUM":   2,
	"HIGH":     3,
	"CRITICAL": 4,
}

// confidenceRank does the same for the --min-confidence gate.
var confidenceRank = map[string]int{
	"LOW":    1,
	"MEDIUM": 2,
	"HIGH":   3,
}

func main() {
	targetDir := flag.String("dir", ".", "Directory to scan")
	rulesDir := flag.String("rules", "./rules", "Directory containing YAML rule files")
	// --config is a Semgrep-compatible alias for --rules.
	configDir := flag.String("config", "", "Directory containing YAML rule files (Semgrep-compatible alias for -rules; takes precedence when set)")
	advisoriesDir := flag.String("advisories", "./advisories", "Directory containing dependency advisory YAML files")
	packagesOut := flag.String("packages-out", "./package_versions.txt", "Output text file for package/version table")
	packagesCSVOut := flag.String("packages-csv-out", "./package_versions.csv", "Output CSV file for package/version table")
	packagesSummaryCSVOut := flag.String("packages-summary-csv-out", "./package_summary.csv", "Output summary CSV file for CI dashboards")
	compromisedRules := flag.String("compromised-rules", "./intel/compromised_packages.yaml", "YAML file containing compromised package rules")
	compromisedFeedURL := flag.String("compromised-feed-url", "", "Optional JSON API URL that returns compromised package rules and IoCs")
	compromisedFeedTimeout := flag.Duration("compromised-feed-timeout", 15*time.Second, "HTTP timeout used when fetching compromised package intelligence")
	compromisedFeedUserAgent := flag.String("compromised-feed-user-agent", "", "User-Agent header used when fetching compromised package intelligence")
	compromisedFeedMaxBytes := flag.Int64("compromised-feed-max-bytes", 2*1024*1024, "Maximum bytes accepted from the compromised package intelligence feed")
	compromisedGeneratedRulesOut := flag.String("compromised-generated-rules-out", "", "Optional path to write the merged compromised package rule set as YAML before the SAST scan")
	compromisedJSONOut := flag.String("compromised-json-out", "./compromised_packages.json", "Output JSON file for compromised package matches")
	compromisedCSVOut := flag.String("compromised-csv-out", "./compromised_packages.csv", "Output CSV file for compromised package matches")
	advisoryRules := flag.String("advisory-rules", "./intel/advisories.yaml", "YAML or JSON file containing package vulnerability advisories")
	advisoryFeedURL := flag.String("advisory-feed-url", "", "Optional JSON API URL that returns package vulnerability advisories, or github://<ecosystem> (npm|pip|go|cargo|all) for GitHub Advisory Database ingestion")
	advisoryFeedTimeout := flag.Duration("advisory-feed-timeout", 15*time.Second, "HTTP timeout used when fetching package vulnerability advisories")
	advisoryFeedUserAgent := flag.String("advisory-feed-user-agent", "", "User-Agent header used when fetching package vulnerability advisories")
	advisoryFeedMaxBytes := flag.Int64("advisory-feed-max-bytes", 2*1024*1024, "Maximum bytes accepted from the package vulnerability advisory feed")
	advisoryGeneratedRulesOut := flag.String("advisory-generated-rules-out", "", "Optional path to write the merged advisory rule set as YAML")
	advisoryPolicyPath := flag.String("advisory-policy", "", "Optional YAML policy file that suppresses specific advisory findings with expiry support")
	advisoryJSONOut := flag.String("oss-vulns-json-out", "./oss_vulnerabilities.json", "Output JSON file for OSS dependency vulnerability matches")
	advisoryCSVOut := flag.String("oss-vulns-csv-out", "./oss_vulnerabilities.csv", "Output CSV file for OSS dependency vulnerability matches")
	advisorySummaryCSVOut := flag.String("oss-vulns-summary-csv-out", "./oss_vulnerabilities_summary.csv", "Output summary CSV file for OSS dependency vulnerability matches")
	failOnOSSVulnSeverity := flag.String("fail-on-oss-vuln-severity", "", "Exit with code 1 when OSS dependency findings at or above this severity remain after policy filtering: LOW, MEDIUM, HIGH, CRITICAL")
	failOnCategories := flag.String("fail-on-categories", "", "Comma-separated finding categories that should fail CI when present (case-insensitive, for example: \"Secrets Exposure,Injection\")")
	findingsJSONOut := flag.String("findings-json-out", "./findings_report.json", "Output JSON file for SAST findings")
	findingsSARIFOut := flag.String("findings-sarif-out", "", "Optional SARIF file for SAST findings")
	findingsFrameworkCSVOut := flag.String("findings-framework-csv-out", "./findings_framework_summary.csv", "Output CSV file for framework/severity finding counts")
	findingsCSVOut := flag.String("findings-csv-out", "./findings.csv", "Output CSV file with one row per finding")
	// --findings-semgrep-json-out emits a Semgrep-compatible JSON report.
	findingsSemgrepJSONOut := flag.String("findings-semgrep-json-out", "", "Optional path to write a Semgrep-compatible JSON findings report")
	includeTests := flag.Bool("include-tests", false, "Include test/spec files (*.test.*, *.spec.*, __tests__, cypress, e2e, playwright) in scans")
	includeVendored := flag.Bool("include-vendored", false, "Include vendored / build-output files (node_modules, dist, build, out, coverage, .next, vendor, *.min.js, *.d.ts) in scans")
	gateByDependency := flag.Bool("gate-by-dependency", false, "Suppress framework-specific rules whose `requires_dependency` list does not match the scanned project's package.json (e.g. skip Angular rules when @angular/core is absent)")
	minSeverity := flag.String("min-severity", "LOW", "Minimum finding severity to report: LOW, MEDIUM, HIGH, CRITICAL")
	minConfidence := flag.String("min-confidence", "LOW", "Minimum finding confidence to report: LOW, MEDIUM, HIGH")
	baselinePath := flag.String("baseline", "", "Optional JSON baseline file: findings whose fingerprint is listed are suppressed from the report (legacy debt remains hidden).")
	baselineOut := flag.String("baseline-out", "", "Optional JSON path to write the current fingerprint set as a baseline (run once to bless legacy findings, then commit the file).")
	failOnNewFindings := flag.Bool("fail-on-new-findings", false, "Exit non-zero when, after baseline filtering, at least one finding remains. Combine with -baseline to gate CI only on net-new findings.")
	// --fail-on-findings mirrors Semgrep's default behavior of exiting 1 when any findings are present.
	failOnFindings := flag.Bool("fail-on-findings", false, "Exit non-zero when any findings remain after all filtering. Compatible with Semgrep's exit-code behavior.")
	changedFilesPath := flag.String("changed-files", "", "Optional newline-delimited file (typically `git diff --name-only`) restricting the scan to listed files while still loading full project dependency context.")
	// --include / --exclude are Semgrep-compatible glob-based file filters.
	// Multiple patterns can be given as a comma-separated list.
	includeGlobs := flag.String("include", "", "Comma-separated glob patterns restricting scan to matching files (e.g. \"*.js,src/**/*.ts\"). Semgrep-compatible.")
	excludeGlobs := flag.String("exclude", "", "Comma-separated glob patterns excluding matching files from the scan. Semgrep-compatible.")

	// Sensitive-data inventory ("data map") pass. Independent of the
	// vulnerability findings pipeline so users can audit what
	// categories of sensitive data appear in the codebase even when
	// no rule fires.
	enableDataInventory := flag.Bool("enable-data-inventory", true, "Run the sensitive-data inventory pass and write the JSON/CSV inventory reports.")
	dataInventoryJSONOut := flag.String("data-inventory-json-out", "./data_inventory.json", "Output JSON file for the sensitive-data inventory pass.")
	dataInventoryCSVOut := flag.String("data-inventory-csv-out", "./data_inventory.csv", "Output CSV file with one row per sensitive-data detection.")
	dataInventorySummaryCSVOut := flag.String("data-inventory-summary-csv-out", "./data_inventory_summary.csv", "Output summary CSV grouped by (category, data_type, severity).")

	// Optional "fetch from URL" front end. When -url is empty the
	// scanner behaves exactly as before, so existing CLI/script
	// invocations are unaffected.
	pageURL := flag.String("url", "", "Optional URL to download JavaScript from before scanning. When set, inline <script> blocks and same-origin external scripts are saved to -fetch-out and that directory becomes the scan target.")
	fetchOut := flag.String("fetch-out", "./fetched-site", "Directory to write fetched JavaScript into when -url is set")
	fetchTimeout := flag.Duration("fetch-timeout", 30*time.Second, "Per-request HTTP timeout used when fetching JavaScript")
	fetchUserAgent := flag.String("fetch-user-agent", "", "User-Agent header used when fetching JavaScript (defaults to a clearly-identified scanner UA)")
	fetchMaxBytes := flag.Int64("fetch-max-bytes", 5*1024*1024, "Maximum bytes accepted per HTTP response when fetching JavaScript")
	fetchSameOrigin := flag.Bool("fetch-same-origin", true, "Only download external scripts whose host matches the page URL")
	flag.Parse()

	// --config takes precedence over --rules when both are provided.
	if cfg := strings.TrimSpace(*configDir); cfg != "" {
		*rulesDir = cfg
	}

	// If a URL was supplied, fetch JavaScript first and redirect the
	// rest of the pipeline at the directory we just populated.
	if strings.TrimSpace(*pageURL) != "" {
		fmt.Printf("[*] Fetching JavaScript from %s into %s ...\n", *pageURL, *fetchOut)
		manifest, err := fetcher.Fetch(*pageURL, *fetchOut, fetcher.Options{
			Timeout:        *fetchTimeout,
			UserAgent:      *fetchUserAgent,
			MaxBytes:       *fetchMaxBytes,
			SameOriginOnly: *fetchSameOrigin,
		})
		if err != nil {
			log.Fatalf("[!] Fetch failed: %v", err)
		}
		fmt.Printf("[+] Fetched %d script(s) to %s (manifest: %s/manifest.json)\n",
			manifest.SavedCount(), *fetchOut, *fetchOut)
		for _, f := range manifest.Files {
			if f.Error != "" {
				log.Printf("[!] Fetch warning for %s: %s", f.LocalFile, f.Error)
			}
		}
		*targetDir = *fetchOut
	}

	fmt.Printf("[*] Target Directory: %s\n", *targetDir)

	// 1. Build a package/version inventory table across discovered manifests.
	packageRecords, err := deps.CollectPackageRecords(*targetDir)
	advisoryMatches := make([]deps.AdvisoryFinding, 0)
	if err != nil {
		log.Printf("[!] Failed to collect package inventory: %v\n", err)
	} else {
		frameworks := deps.DetectFrameworks(packageRecords)
		advisoryDB, advisoryErr := deps.LoadAdvisories(*advisoriesDir)
		if advisoryErr != nil {
			log.Printf("[!] Failed to load dependency advisories: %v\n", advisoryErr)
		} else {
			advisoryMatches = deps.MatchAdvisories(packageRecords, advisoryDB)
		}
		if writeErr := deps.WritePackageTable(packageRecords, frameworks, *packagesOut); writeErr != nil {
			log.Printf("[!] Failed to write package inventory table: %v\n", writeErr)
		} else {
			fmt.Printf("[+] Package inventory written to %s (%d packages).\n", *packagesOut, len(packageRecords))
			if csvErr := deps.WritePackageCSV(packageRecords, *packagesCSVOut); csvErr != nil {
				log.Printf("[!] Failed to write package inventory CSV: %v\n", csvErr)
			} else {
				fmt.Printf("[+] Package CSV written to %s (%d packages).\n", *packagesCSVOut, len(packageRecords))
			}
			summary := deps.BuildSummaryStats(packageRecords, frameworks, advisoryMatches)
			if summaryErr := deps.WriteSummaryCSV(summary, *packagesSummaryCSVOut); summaryErr != nil {
				log.Printf("[!] Failed to write package summary CSV: %v\n", summaryErr)
			} else {
				fmt.Printf("[+] Package summary CSV written to %s.\n", *packagesSummaryCSVOut)
			}
			if len(frameworks) > 0 {
				fmt.Printf("[*] Detected frameworks: %v\n", frameworks)
			} else {
				fmt.Println("[*] Detected frameworks: none")
			}
			if len(advisoryMatches) == 0 {
				fmt.Println("[*] Matched advisories: none")
			} else {
				fmt.Printf("[*] Matched advisories: %d\n", len(advisoryMatches))
				for _, match := range advisoryMatches {
					fmt.Printf("   🚨 %-8s | %-18s | %s@%s | %s\n", match.Severity, match.AdvisoryID, match.Package, match.Version, match.ProjectPath)
				}
			}
		}
		fmt.Println()
	}

	compromisedFindings := make([]deps.CompromisedFinding, 0)
	advisoryFindings := make([]deps.AdvisoryFinding, 0)
	shouldFailForOSSVulns := false
	if len(packageRecords) > 0 {
		seedRules, ruleErr := deps.LoadCompromisedRules(*compromisedRules)
		if ruleErr != nil {
			log.Printf("[!] Failed to load compromised package rules: %v\n", ruleErr)
		}
		feedRules, feedErr := deps.FetchCompromisedRules(*compromisedFeedURL, deps.CompromisedFeedOptions{
			Timeout:   *compromisedFeedTimeout,
			UserAgent: *compromisedFeedUserAgent,
			MaxBytes:  *compromisedFeedMaxBytes,
		})
		if feedErr != nil {
			log.Printf("[!] Failed to fetch compromised package feed: %v\n", feedErr)
		}
		mergedCompromisedRules := deps.MergeCompromisedRules(seedRules, feedRules)
		if out := strings.TrimSpace(*compromisedGeneratedRulesOut); out != "" {
			if writeErr := deps.WriteCompromisedRulesYAML(out, mergedCompromisedRules); writeErr != nil {
				log.Printf("[!] Failed to write merged compromised package rules: %v\n", writeErr)
			} else {
				fmt.Printf("[+] Merged compromised package rules written to %s.\n", out)
			}
		}

		compromisedFindings = deps.MatchCompromisedPackages(packageRecords, mergedCompromisedRules)
		if len(compromisedFindings) == 0 {
			fmt.Println("[*] No compromised package matches detected.")
		} else {
			fmt.Println("[*] Compromised package matches:")
			for _, finding := range compromisedFindings {
				fmt.Printf("[!] %-8s | %-6s | %-30s | %s\n    %s\n", finding.Severity, finding.Ecosystem, finding.RuleID, finding.ManifestPath, deps.FormatIOCs(finding.IOCs))
			}
		}
		if jsonErr := reporter.WriteCompromisedJSON(compromisedFindings, *targetDir, *compromisedJSONOut); jsonErr != nil {
			log.Printf("[!] Failed to write compromised package JSON: %v\n", jsonErr)
		}
		if csvErr := reporter.WriteCompromisedCSV(compromisedFindings, *compromisedCSVOut); csvErr != nil {
			log.Printf("[!] Failed to write compromised package CSV: %v\n", csvErr)
		}

		seedAdvisories, advisoryErr := deps.LoadAdvisories(*advisoryRules)
		if advisoryErr != nil {
			log.Printf("[!] Failed to load package vulnerability advisories: %v\n", advisoryErr)
		}
		feedAdvisories, advisoryFeedErr := deps.FetchAdvisories(*advisoryFeedURL, deps.AdvisoryFeedOptions{
			Timeout:   *advisoryFeedTimeout,
			UserAgent: *advisoryFeedUserAgent,
			MaxBytes:  *advisoryFeedMaxBytes,
		})
		if advisoryFeedErr != nil {
			log.Printf("[!] Failed to fetch package vulnerability advisories: %v\n", advisoryFeedErr)
		}
		mergedAdvisories := deps.MergeAdvisories(seedAdvisories, feedAdvisories)
		if out := strings.TrimSpace(*advisoryGeneratedRulesOut); out != "" {
			if writeErr := deps.WriteAdvisoriesYAML(out, mergedAdvisories); writeErr != nil {
				log.Printf("[!] Failed to write merged package vulnerability advisories: %v\n", writeErr)
			} else {
				fmt.Printf("[+] Merged package vulnerability advisories written to %s.\n", out)
			}
		}

		advisoryFindings = deps.MatchAdvisories(packageRecords, mergedAdvisories)
		policy, policyErr := deps.LoadAdvisoryPolicy(*advisoryPolicyPath)
		if policyErr != nil {
			log.Printf("[!] Failed to load advisory policy: %v\n", policyErr)
		}
		filteredAdvisoryFindings, ignoredAdvisories := deps.ApplyAdvisoryPolicy(advisoryFindings, policy, time.Now().UTC())
		advisoryFindings = filteredAdvisoryFindings

		if len(advisoryFindings) == 0 {
			fmt.Println("[*] No OSS dependency vulnerabilities detected.")
		} else {
			fmt.Println("[*] OSS dependency vulnerabilities:")
			for _, finding := range advisoryFindings {
				fmt.Printf("[!] %-8s | %-6s | %-25s | %-10s | %s\n    %s\n", finding.Severity, finding.Ecosystem, deps.FormatIdentifiers(finding.AdvisoryID, finding.Aliases), finding.Relationship, finding.ManifestPath, finding.Remediation)
			}
		}
		if ignoredAdvisories > 0 {
			fmt.Printf("[*] Advisory policy suppressed %d OSS vulnerability finding(s).\n", ignoredAdvisories)
		}
		if jsonErr := reporter.WriteAdvisoryJSON(advisoryFindings, *targetDir, *advisoryJSONOut); jsonErr != nil {
			log.Printf("[!] Failed to write OSS vulnerability JSON: %v\n", jsonErr)
		}
		if csvErr := reporter.WriteAdvisoryCSV(advisoryFindings, *advisoryCSVOut); csvErr != nil {
			log.Printf("[!] Failed to write OSS vulnerability CSV: %v\n", csvErr)
		}
		if summaryErr := reporter.WriteAdvisorySummaryCSV(advisoryFindings, *advisorySummaryCSVOut); summaryErr != nil {
			log.Printf("[!] Failed to write OSS vulnerability summary CSV: %v\n", summaryErr)
		}

		minSeverityRank := severityRank[strings.ToUpper(strings.TrimSpace(*failOnOSSVulnSeverity))]
		if minSeverityRank > 0 {
			for _, finding := range advisoryFindings {
				if severityRank[strings.ToUpper(finding.Severity)] >= minSeverityRank {
					shouldFailForOSSVulns = true
					break
				}
			}
		}
		fmt.Println()
	}

	// 2. Load the external YAML rules
	fmt.Printf("[*] Loading signatures from %s...\n", *rulesDir)
	rules, err := engine.LoadRules(*rulesDir)
	if err != nil {
		log.Fatalf("[!] Fatal error loading rules: %v", err)
	}

	if len(rules) == 0 {
		log.Fatalf("[!] No valid rules found in %s. Exiting.", *rulesDir)
	}
	fmt.Printf("[+] Loaded %d rules.\n\n", len(rules))

	// 3. Initialize the scanning engine with the loaded rules
	scannerEngine := engine.New(rules)
	scannerEngine.IncludeTests = *includeTests
	scannerEngine.IncludeVendored = *includeVendored
	scannerEngine.EnableDependencyGating = *gateByDependency

	// Wire the project's package inventory into the engine so rules
	// can be gated by `requires_dependency`.
	if len(packageRecords) > 0 {
		names := make([]string, 0, len(packageRecords))
		for _, record := range packageRecords {
			names = append(names, record.Name)
		}
		scannerEngine.SetProjectDependencies(names)
	}
	scannerEngine.SetExcludedPaths([]string{*rulesDir, *compromisedRules})

	// Apply --include / --exclude glob filters (Semgrep-compatible).
	if globs := parseGlobList(*includeGlobs); len(globs) > 0 {
		scannerEngine.IncludeGlobs = globs
		fmt.Printf("[*] Include globs: %v\n", globs)
	}
	if globs := parseGlobList(*excludeGlobs); len(globs) > 0 {
		scannerEngine.ExcludeGlobs = globs
		fmt.Printf("[*] Exclude globs: %v\n", globs)
	}

	if changedPaths, err := readChangedFiles(*changedFilesPath, *targetDir); err != nil {
		log.Printf("[!] Failed to read changed-files list: %v\n", err)
	} else if len(changedPaths) > 0 {
		scannerEngine.SetChangedFiles(changedPaths)
		fmt.Printf("[*] Diff mode: scan restricted to %d changed file(s) from %s.\n", len(changedPaths), *changedFilesPath)
	}

	findingsChan := make(chan engine.Finding, 100)
	findings := make([]engine.Finding, 0)
	failCategorySet := parseCategoryGate(*failOnCategories)

	// Resolve the minimum severity/confidence gates once.
	minSevRank := severityRank[strings.ToUpper(*minSeverity)]
	minConfRank := confidenceRank[strings.ToUpper(*minConfidence)]

	// 4. Execute the scan in a goroutine and consume findings in the main flow.
	scanErrChan := make(chan error, 1)
	go func() {
		scanErrChan <- scannerEngine.ScanDirectory(*targetDir, findingsChan)
	}()

	for f := range findingsChan {
		if minSevRank > 0 && severityRank[strings.ToUpper(f.Severity)] < minSevRank {
			continue
		}
		if minConfRank > 0 && confidenceRank[strings.ToUpper(f.Confidence)] < minConfRank {
			continue
		}
		findings = append(findings, f)
		printFinding(f)
	}

	err = <-scanErrChan
	if err != nil {
		log.Printf("Scan encountered an error: %v\n", err)
	}

	for _, match := range advisoryMatches {
		f := advisoryMatchToFinding(match, *targetDir)
		if minSevRank > 0 && severityRank[strings.ToUpper(f.Severity)] < minSevRank {
			continue
		}
		if minConfRank > 0 && confidenceRank[strings.ToUpper(f.Confidence)] < minConfRank {
			continue
		}
		findings = append(findings, f)
		printFinding(f)
	}

	// Apply baseline filtering before report writers so all reports
	// agree on the set of "new" findings that the current run surfaces.
	if out := strings.TrimSpace(*baselineOut); out != "" {
		if err := baseline.Write(out, findings); err != nil {
			log.Printf("[!] Failed to write baseline: %v\n", err)
		} else {
			fmt.Printf("[+] Baseline written to %s (%d unique fingerprints).\n", out, countFingerprints(findings))
		}
	}
	baselineSet, err := baseline.Load(*baselinePath)
	if err != nil {
		log.Printf("[!] Failed to load baseline: %v\n", err)
	}
	suppressedByBaseline := 0
	if len(baselineSet) > 0 {
		kept, matched := baseline.Filter(findings, baselineSet)
		suppressedByBaseline = len(matched)
		findings = kept
		fmt.Printf("[*] Baseline filtered out %d known finding(s); %d remain.\n", suppressedByBaseline, len(findings))
	}

	if jsonErr := reporter.WriteJSON(findings, *targetDir, *findingsJSONOut); jsonErr != nil {
		log.Printf("[!] Failed to write findings JSON: %v\n", jsonErr)
	}
	if out := strings.TrimSpace(*findingsSARIFOut); out != "" {
		if sarifErr := reporter.WriteSARIF(findings, rules, *targetDir, out); sarifErr != nil {
			log.Printf("[!] Failed to write findings SARIF: %v\n", sarifErr)
		}
	}
	if out := strings.TrimSpace(*findingsSemgrepJSONOut); out != "" {
		if semgrepErr := reporter.WriteSemgrepJSON(findings, *targetDir, out); semgrepErr != nil {
			log.Printf("[!] Failed to write Semgrep JSON report: %v\n", semgrepErr)
		}
	}
	if summaryErr := reporter.WriteFrameworkSummaryCSV(findings, *findingsFrameworkCSVOut); summaryErr != nil {
		log.Printf("[!] Failed to write findings framework summary CSV: %v\n", summaryErr)
	}
	if findingsCSVErr := reporter.WriteFindingsCSV(findings, *findingsCSVOut); findingsCSVErr != nil {
		log.Printf("[!] Failed to write findings CSV: %v\n", findingsCSVErr)
	}

	// Phase 2: sensitive-data inventory pass. Runs independently of the
	// rule-based vulnerability scan so users can audit the categories
	// of sensitive data the codebase touches even when no rule fires.
	if *enableDataInventory {
		fmt.Println("[*] Running sensitive-data inventory pass...")
		inventoryOpts := dataclass.Options{
			IncludeTests:    *includeTests,
			IncludeVendored: *includeVendored,
		}
		if scannerEngine.ChangedFiles != nil {
			inventoryOpts.ChangedFiles = make(map[string]struct{}, len(scannerEngine.ChangedFiles))
			for p := range scannerEngine.ChangedFiles {
				inventoryOpts.ChangedFiles[p] = struct{}{}
			}
		}
		detections, invErr := dataclass.Scan(*targetDir, dataclass.BuiltinDetectors(), inventoryOpts)
		if invErr != nil {
			log.Printf("[!] Data inventory pass failed: %v\n", invErr)
		} else {
			reporter.PrintDataInventorySummary(detections, *targetDir)
			if out := strings.TrimSpace(*dataInventoryJSONOut); out != "" {
				if err := reporter.WriteDataInventoryJSON(detections, *targetDir, out); err != nil {
					log.Printf("[!] Failed to write data inventory JSON: %v\n", err)
				}
			}
			if out := strings.TrimSpace(*dataInventoryCSVOut); out != "" {
				if err := reporter.WriteDataInventoryCSV(detections, out); err != nil {
					log.Printf("[!] Failed to write data inventory CSV: %v\n", err)
				}
			}
			if out := strings.TrimSpace(*dataInventorySummaryCSVOut); out != "" {
				if err := reporter.WriteDataInventorySummaryCSV(detections, out); err != nil {
					log.Printf("[!] Failed to write data inventory summary CSV: %v\n", err)
				}
			}
		}
	}

	fmt.Println("[*] Scan complete.")
	if shouldFailForCategories(findings, failCategorySet) {
		log.Printf("[!] Failing because findings matched -fail-on-categories: %s.\n", strings.Join(sortedKeys(failCategorySet), ", "))
		os.Exit(1)
	}
	if shouldFailForOSSVulns {
		log.Printf("[!] Failing because OSS dependency vulnerabilities met the -fail-on-oss-vuln-severity threshold.\n")
		os.Exit(1)
	}
	if *failOnNewFindings && len(findings) > 0 {
		log.Printf("[!] Failing because -fail-on-new-findings is set and %d finding(s) remain after baseline filtering.\n", len(findings))
		os.Exit(1)
	}
	if *failOnFindings && len(findings) > 0 {
		log.Printf("[!] Failing because -fail-on-findings is set and %d finding(s) were detected.\n", len(findings))
		os.Exit(1)
	}
}

func printFinding(f engine.Finding) {
	dangerousCode := strings.TrimSpace(f.HighlightedSnippet)
	if dangerousCode == "" {
		dangerousCode = strings.TrimSpace(f.Snippet)
	}
	if dangerousCode == "" {
		dangerousCode = strings.TrimSpace(f.MatchedCode)
	}
	if dangerousCode == "" {
		dangerousCode = f.Description
	}
	fmt.Printf("[!] %-8s | %-6s | %-30s | %s:%d:%d\n    %s\n    %s\n",
		f.Severity, f.Framework, f.RuleID, f.File, f.Line, f.Column, dangerousCode, f.Description)
}

func advisoryMatchToFinding(match deps.AdvisoryFinding, targetDir string) engine.Finding {
	fixedVersions := make([]string, 0)
	if match.FixedVersion != "" {
		fixedVersions = append(fixedVersions, match.FixedVersion)
	}
	finding := engine.Finding{
		Kind:            "dependency",
		File:            match.ManifestPath,
		RuleID:          match.AdvisoryID,
		Severity:        match.Severity,
		Framework:       match.Ecosystem,
		Description:     match.Description,
		Confidence:      "HIGH",
		PackageName:     match.Package,
		DeclaredVersion: match.Version,
		FixedVersions:   fixedVersions,
		References:      match.References,
		CWE:             match.CWE,
		Remediation:     match.Remediation,
		ProjectPath:     match.ProjectPath,
	}
	// Dependency findings use package@version as the stable identity
	// instead of source code, so a version bump produces a fresh
	// fingerprint and a re-introduced advisory will not be silently
	// hidden by a baseline.
	advisoryIdentity := match.Package + "@" + match.Version
	finding.Fingerprint = engine.ComputeFingerprint(match.AdvisoryID, match.ManifestPath, targetDir, advisoryIdentity, nil)
	return finding
}

func parseCategoryGate(raw string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, entry := range strings.Split(raw, ",") {
		normalized := strings.ToUpper(strings.TrimSpace(entry))
		if normalized == "" {
			continue
		}
		out[normalized] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func shouldFailForCategories(findings []engine.Finding, blocked map[string]struct{}) bool {
	if len(blocked) == 0 {
		return false
	}
	for _, finding := range findings {
		category := strings.ToUpper(strings.TrimSpace(finding.Category))
		if category == "" {
			continue
		}
		if _, blockedCategory := blocked[category]; blockedCategory {
			return true
		}
	}
	return false
}

func sortedKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// readChangedFiles parses a newline-delimited file (the typical output
// of `git diff --name-only`) and returns an absolute, deduplicated list
// of file paths. Entries that look like comments (`# ...`) and blank
// lines are ignored. Relative entries are resolved against targetDir
// first; if that file does not exist, they fall back to the working
// directory so callers can supply paths in either form.
func readChangedFiles(path, targetDir string) ([]string, error) {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return nil, nil
	}

	f, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", clean, err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
	out := make([]string, 0)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		resolved := resolveChangedFile(entry, targetDir)
		if resolved == "" {
			continue
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("failed to read %s: %w", clean, scanErr)
	}
	return out, nil
}

func resolveChangedFile(entry, targetDir string) string {
	if filepath.IsAbs(entry) {
		abs, err := filepath.Abs(entry)
		if err != nil {
			return ""
		}
		return filepath.Clean(abs)
	}
	if td := strings.TrimSpace(targetDir); td != "" {
		candidate := filepath.Join(td, entry)
		if abs, err := filepath.Abs(candidate); err == nil {
			if _, statErr := os.Stat(abs); statErr == nil {
				return filepath.Clean(abs)
			}
		}
	}
	abs, err := filepath.Abs(entry)
	if err != nil {
		return ""
	}
	return filepath.Clean(abs)
}

// countFingerprints returns the number of unique non-empty fingerprints
// across the supplied findings, used purely for human-readable log
// messages.
func countFingerprints(findings []engine.Finding) int {
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		fp := strings.TrimSpace(finding.Fingerprint)
		if fp == "" {
			continue
		}
		seen[fp] = struct{}{}
	}
	return len(seen)
}

// parseGlobList splits a comma-separated list of glob patterns into a
// deduplicated, trimmed slice, discarding blank entries. This is the
// helper for --include and --exclude flag values.
func parseGlobList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
