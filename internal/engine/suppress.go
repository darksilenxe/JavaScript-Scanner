package engine

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Default path segments that indicate non-production code. Files whose path
// contains any of these segments are skipped unless the corresponding include
// flag is set on the Engine.
var defaultTestPathSegments = []string{
	"__tests__",
	"__mocks__",
	"cypress",
	"e2e",
	"playwright",
}

var defaultVendoredPathSegments = []string{
	"node_modules",
	"dist",
	"build",
	"out",
	"coverage",
	".next",
	"vendor",
}

// IsTestPath returns true when the given path looks like test code
// (test/spec file or one of the well-known test directories).
func IsTestPath(path string) bool {
	clean := filepath.ToSlash(path)
	base := strings.ToLower(filepath.Base(clean))

	// Match *.test.* and *.spec.* (covers .js, .jsx, .ts, .tsx, .mjs, .cjs).
	if strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") {
		return true
	}

	lowered := strings.ToLower(clean)
	for _, seg := range defaultTestPathSegments {
		needle := "/" + seg + "/"
		if strings.Contains(lowered, needle) || strings.HasPrefix(lowered, seg+"/") {
			return true
		}
	}

	return false
}

// IsVendoredPath returns true for files under build output, vendored, or
// generated directories, and for minified bundles or TypeScript declaration
// files.
func IsVendoredPath(path string) bool {
	clean := filepath.ToSlash(path)
	base := strings.ToLower(filepath.Base(clean))

	if strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".min.mjs") || strings.HasSuffix(base, ".min.cjs") {
		return true
	}
	if strings.HasSuffix(base, ".d.ts") {
		return true
	}

	lowered := strings.ToLower(clean)
	for _, seg := range defaultVendoredPathSegments {
		needle := "/" + seg + "/"
		if strings.Contains(lowered, needle) || strings.HasPrefix(lowered, seg+"/") {
			return true
		}
	}

	return false
}

// suppressionRegex matches `// scanner-disable-line` and
// `// scanner-disable-next-line`, optionally followed by a comma- or
// space-separated list of rule IDs that should be suppressed. When no
// rule IDs are listed, the directive suppresses all rules on that line.
//
// The directive name `scanner-expected` is treated as a semantic
// synonym of `scanner-disable-line`: it suppresses the same finding
// while documenting the intent that a finding here is expected (for
// example, in a fixture file or a known-vulnerable demo snippet).
//
// Examples:
//
//	// scanner-disable-line
//	// scanner-disable-next-line
//	// scanner-disable-line JS-EVAL-EXEC
//	// scanner-disable-next-line JS-EVAL-EXEC, DOM-XSS-INNERHTML-ASSIGN
//	// scanner-expected JS-EVAL-EXEC
//
// Block comments (/* ... */) carrying the same directive are also honored.
var suppressionRegex = regexp.MustCompile(`(?i)scanner-(disable-(line|next-line)|expected(?:-next-line)?)\b([^*\n\r]*)`)

// nosemgrepRegex matches Semgrep's inline suppression syntax:
//
//	# nosemgrep: RULE-ID
//	// nosemgrep: RULE-ID
//	// nosemgrep RULE-ID        (colon optional)
//	# nosemgrep                 (wildcard — suppresses all rules)
//
// The directive always applies to the same line it appears on.
var nosemgrepRegex = regexp.MustCompile(`(?i)nosemgrep\b:?\s*([^*\n\r]*)`)

// suppressionMap captures the set of rule IDs disabled for a given 1-based
// line number. An empty set means "all rules disabled on this line".
type suppressionMap map[uint32]map[string]struct{}

// buildSuppressionMap parses a source file and returns a map from
// 1-based line numbers to the set of rule IDs suppressed on that line.
//
// A directive on line N applies to:
//   - line N itself when "scanner-disable-line" is used
//   - line N+1 when "scanner-disable-next-line" is used
//   - line N itself when "nosemgrep" is used (Semgrep parity)
func buildSuppressionMap(sourceCode []byte) suppressionMap {
	result := make(suppressionMap)
	lines := strings.Split(string(sourceCode), "\n")

	for idx, line := range lines {
		// --- native scanner directives ---
		matches := suppressionRegex.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if !lineHasCommentBefore(line, "scanner-") {
				continue
			}
			directive := strings.ToLower(m[1])
			ids := parseRuleIDList(m[3])

			isNextLine := strings.Contains(directive, "next-line")
			targetLine := uint32(idx + 1)
			if isNextLine {
				targetLine = uint32(idx + 2)
			}

			addToSuppressionMap(result, targetLine, ids)
		}

		// --- Semgrep nosemgrep directive ---
		noSemgrepMatches := nosemgrepRegex.FindAllStringSubmatch(line, -1)
		for _, m := range noSemgrepMatches {
			if !lineHasCommentBefore(line, "nosemgrep") {
				continue
			}
			ids := parseRuleIDList(m[1])
			addToSuppressionMap(result, uint32(idx+1), ids)
		}
	}

	return result
}

// addToSuppressionMap merges ids into the suppression set at targetLine.
// An empty ids set means "wildcard – suppress all rules on this line".
func addToSuppressionMap(result suppressionMap, targetLine uint32, ids map[string]struct{}) {
	existing, present := result[targetLine]
	if len(ids) == 0 {
		// Wildcard suppression: replace with empty set sentinel.
		result[targetLine] = make(map[string]struct{})
		return
	}
	// If a wildcard directive already covers this line, keep it.
	if present && len(existing) == 0 {
		return
	}
	if !present {
		existing = make(map[string]struct{})
		result[targetLine] = existing
	}
	for id := range ids {
		existing[id] = struct{}{}
	}
}

// lineHasCommentBefore returns true when `marker` appears in `line`
// preceded by a supported comment opener (`//`, `#`, `/*`, or `*`).
func lineHasCommentBefore(line, marker string) bool {
	idx := strings.Index(strings.ToLower(line), strings.ToLower(marker))
	if idx < 0 {
		return false
	}
	prefix := line[:idx]
	if strings.Contains(prefix, "//") || strings.Contains(prefix, "#") {
		return true
	}
	if strings.Contains(prefix, "/*") {
		return true
	}
	// Block-comment continuation lines such as `  * scanner-disable-line`.
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "*" || strings.HasSuffix(trimmed, "*") {
		return true
	}
	return false
}

// parseRuleIDList splits a free-form list of rule IDs separated by
// commas, semicolons, or whitespace, and returns them as a set.
func parseRuleIDList(raw string) map[string]struct{} {
	out := make(map[string]struct{})
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" {
		return out
	}
	cleaned = strings.TrimRight(cleaned, "*/")
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		return out
	}

	fields := strings.FieldsFunc(cleaned, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\t':
			return true
		}
		return false
	})
	for _, f := range fields {
		token := strings.TrimSpace(f)
		if token == "" {
			continue
		}
		out[token] = struct{}{}
	}
	return out
}

// isSuppressed returns true when a finding for ruleID at line should be
// dropped because of an inline suppression directive.
func (m suppressionMap) isSuppressed(line uint32, ruleID string) bool {
	if m == nil {
		return false
	}
	ids, ok := m[line]
	if !ok {
		return false
	}
	if len(ids) == 0 {
		// Wildcard — suppress every rule on this line.
		return true
	}
	_, hit := ids[ruleID]
	return hit
}
