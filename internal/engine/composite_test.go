package engine

// Tests for the Semgrep-compatible composite operators added in the
// "Make matching patterns act like Semgrep" feature:
//
//   pattern_not        – drop matches whose finding node overlaps a must-not match
//   pattern_inside     – keep only matches whose finding node is inside a context match
//   pattern_not_inside – drop matches whose finding node is inside a forbidden context
//   focus_metavariable – change the reported finding node to a named capture
//   metavariable_regex – alias for require_if_matches (Semgrep-compatible name)
//   metavariable_pattern – sub-query that must match the captured sub-tree
//   must_match_queries – additional positive patterns (AND semantics)

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const primaryEvalQuery = `
(call_expression
  function: (identifier) @fn
  (#eq? @fn "eval")
  arguments: (arguments (_) @arg)
) @finding
`

func evalRuleWithPatternNot(t *testing.T, notQuery string) Rule {
	t.Helper()
	r := Rule{
		ID:         "TEST-PATTERN-NOT",
		Severity:   "HIGH",
		Query:      primaryEvalQuery,
		PatternNot: StringList{notQuery},
	}
	require.NoError(t, r.compile())
	return r
}

func evalRuleWithPatternInside(t *testing.T, insideQuery string) Rule {
	t.Helper()
	r := Rule{
		ID:            "TEST-PATTERN-INSIDE",
		Severity:      "HIGH",
		Query:         primaryEvalQuery,
		PatternInside: insideQuery,
	}
	require.NoError(t, r.compile())
	return r
}

func evalRuleWithPatternNotInside(t *testing.T, notInsideQuery string) Rule {
	t.Helper()
	r := Rule{
		ID:               "TEST-PATTERN-NOT-INSIDE",
		Severity:         "HIGH",
		Query:            primaryEvalQuery,
		PatternNotInside: notInsideQuery,
	}
	require.NoError(t, r.compile())
	return r
}

// writeBundleFile writes YAML content to a temp file in dir and returns its path.
func writeBundleFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

// --- pattern_not ---

func TestPatternNotDropsOverlappingMatch(t *testing.T) {
	const notQuery = `
(call_expression
  function: (identifier) @fn2
  (#eq? @fn2 "eval")
  arguments: (arguments (string) @lit)
) @safe_eval
`
	rule := evalRuleWithPatternNot(t, notQuery)

	got := scanContent(t, "eval(\"use strict\");\n", []Rule{rule}, nil)
	assert.Empty(t, got, "eval with string literal should be dropped by pattern_not")

	got = scanContent(t, "eval(userInput);\n", []Rule{rule}, nil)
	assert.Len(t, got, 1, "eval with identifier should still be reported")
}

func TestPatternNotDoesNotAffectUnrelatedMatches(t *testing.T) {
	const notQuery = `
(call_expression
  function: (identifier) @fn2
  (#eq? @fn2 "eval")
  arguments: (arguments (string) @lit)
) @safe_eval
`
	rule := evalRuleWithPatternNot(t, notQuery)

	src := "eval(\"safe\");\neval(userInput);\n"
	got := scanContent(t, src, []Rule{rule}, nil)
	require.Len(t, got, 1, "only the non-literal eval should be reported")
	assert.EqualValues(t, 2, got[0].Line, "finding should be on line 2 (the unsafe eval)")
}

// --- pattern_inside ---

func TestPatternInsideKeepsOnlyMatchesInContext(t *testing.T) {
	const insideQuery = `
(function_declaration
  body: (statement_block) @body
) @func
`
	rule := evalRuleWithPatternInside(t, insideQuery)

	got := scanContent(t, "function handler() {\n  eval(userInput);\n}\n", []Rule{rule}, nil)
	assert.Len(t, got, 1, "eval inside a function should be reported")

	got = scanContent(t, "eval(userInput);\n", []Rule{rule}, nil)
	assert.Empty(t, got, "eval at top-level should be filtered out by pattern_inside")
}

// --- pattern_not_inside ---

func TestPatternNotInsideDropsMatchesInContext(t *testing.T) {
	const notInsideQuery = `
(try_statement
  body: (statement_block) @try_body
) @try
`
	rule := evalRuleWithPatternNotInside(t, notInsideQuery)

	got := scanContent(t, "try {\n  eval(userInput);\n} catch (e) {}\n", []Rule{rule}, nil)
	assert.Empty(t, got, "eval inside try-catch should be dropped by pattern_not_inside")

	got = scanContent(t, "eval(userInput);\n", []Rule{rule}, nil)
	assert.Len(t, got, 1, "eval outside try-catch should still be reported")
}

// --- focus_metavariable ---

func TestFocusMetavariableChangesReportedNode(t *testing.T) {
	rule := Rule{
		ID:                "TEST-FOCUS-METAVAR",
		Severity:          "HIGH",
		Query:             primaryEvalQuery,
		FocusMetavariable: "arg",
	}
	require.NoError(t, rule.compile())

	defaultRule := testRule("TEST-NO-FOCUS", "HIGH", primaryEvalQuery)

	src := "eval(userInput);\n"
	gotFocused := scanContent(t, src, []Rule{rule}, nil)
	gotDefault := scanContent(t, src, []Rule{defaultRule}, nil)

	require.Len(t, gotFocused, 1)
	require.Len(t, gotDefault, 1)

	// The focused finding column should be >= the default column since
	// the argument starts after the function identifier.
	assert.GreaterOrEqual(t, gotFocused[0].Column, gotDefault[0].Column,
		"focused finding column should be at the argument, not the whole call expression")
}

// --- metavariable_regex ---

func TestMetavariableRegexKeepsOnlyMatchingCaptures(t *testing.T) {
	rule := Rule{
		ID:       "TEST-METAVAR-REGEX",
		Severity: "HIGH",
		Query: `
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method
    (#eq? @method "createHash")
  )
  arguments: (arguments (string) @algo)
) @finding
`,
		MetavariableRegex: map[string]string{
			"algo": `(?i)["'](md5|sha1)["']`,
		},
	}
	require.NoError(t, rule.compile())

	got := scanContent(t, "crypto.createHash(\"md5\");\n", []Rule{rule}, nil)
	assert.Len(t, got, 1, "md5 should match the metavariable_regex filter")

	got = scanContent(t, "crypto.createHash(\"sha256\");\n", []Rule{rule}, nil)
	assert.Empty(t, got, "sha256 should not match the metavariable_regex filter")
}

// --- metavariable_pattern ---

func TestMetavariablePatternKeepsOnlyMatchingSubtree(t *testing.T) {
	rule := Rule{
		ID:       "TEST-METAVAR-PATTERN",
		Severity: "HIGH",
		Query: `
(assignment_expression
  left: (member_expression
    property: (property_identifier) @prop
    (#eq? @prop "innerHTML")
  )
  right: (_) @rhs
) @finding
`,
		MetavariablePattern: map[string]string{
			"rhs": `(identifier) @id`,
		},
	}
	require.NoError(t, rule.compile())

	got := scanContent(t, "el.innerHTML = userInput;\n", []Rule{rule}, nil)
	assert.Len(t, got, 1, "assignment from identifier should be reported")

	got = scanContent(t, "el.innerHTML = \"safe text\";\n", []Rule{rule}, nil)
	assert.Empty(t, got, "assignment from string literal should be filtered by metavariable_pattern")
}

// --- must_match_queries ---

func TestMustMatchQueriesRequiresAllQueriesMatchFile(t *testing.T) {
	rule := Rule{
		ID:       "TEST-MUST-MATCH",
		Severity: "HIGH",
		Query:    primaryEvalQuery,
		MustMatchQueries: StringList{`
(call_expression
  function: (identifier) @req
  (#eq? @req "require")
  arguments: (arguments
    (string
      (string_fragment) @mod
      (#eq? @mod "child_process")
    )
  )
) @finding
`},
	}
	require.NoError(t, rule.compile())

	srcBoth := "const cp = require(\"child_process\");\neval(cmd);\n"
	got := scanContent(t, srcBoth, []Rule{rule}, nil)
	assert.Len(t, got, 1, "eval should be reported when must_match query also matches in the file")

	got = scanContent(t, "eval(cmd);\n", []Rule{rule}, nil)
	assert.Empty(t, got, "eval should be filtered when must_match query has no match in file")
}

// --- Semgrep bundle loading with composite operators ---

func TestSemgrepBundlePatternNot(t *testing.T) {
	content := `rules:
  - id: BUNDLE-PATTERN-NOT
    severity: ERROR
    message: Detect eval unless safe
    languages: [javascript]
    query: |
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")
        arguments: (arguments (_) @arg)
      ) @finding
    pattern-not: |
      (call_expression
        function: (identifier) @fn2
        (#eq? @fn2 "eval")
        arguments: (arguments (string) @lit)
      ) @safe_eval
`
	dir := t.TempDir()
	writeBundleFile(t, dir, "bundle.yaml", content)

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Len(t, rules[0].PatternNot, 1, "pattern-not should be loaded from bundle")

	got := scanContent(t, "eval(\"strict\");\n", rules, nil)
	assert.Empty(t, got, "safe eval should be dropped by pattern-not from bundle")

	got = scanContent(t, "eval(userInput);\n", rules, nil)
	assert.Len(t, got, 1, "dangerous eval should still be reported from bundle rule")
}

func TestSemgrepBundleFocusMetavariable(t *testing.T) {
	content := `rules:
  - id: BUNDLE-FOCUS
    severity: ERROR
    message: Detect eval, focus on argument
    languages: [javascript]
    focus-metavariable: "arg"
    query: |
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")
        arguments: (arguments (_) @arg)
      ) @finding
`
	dir := t.TempDir()
	writeBundleFile(t, dir, "focus.yaml", content)

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "arg", rules[0].FocusMetavariable, "focus-metavariable should be loaded from bundle")
}

func TestSemgrepBundleMetavariableRegex(t *testing.T) {
	content := `rules:
  - id: BUNDLE-METAVAR-REGEX
    severity: ERROR
    message: Weak hash algorithm
    languages: [javascript]
    query: |
      (call_expression
        function: (member_expression
          property: (property_identifier) @method
          (#eq? @method "createHash")
        )
        arguments: (arguments (string) @algo)
      ) @finding
    metavariable-regex:
      algo: "(?i)[\"'](md5|sha1)[\"']"
`
	dir := t.TempDir()
	writeBundleFile(t, dir, "metavar_regex.yaml", content)

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.NotEmpty(t, rules[0].MetavariableRegex, "metavariable-regex should be loaded from bundle")

	got := scanContent(t, "crypto.createHash(\"md5\");\n", rules, nil)
	assert.Len(t, got, 1, "md5 hash should be reported via bundle metavariable-regex")

	got = scanContent(t, "crypto.createHash(\"sha256\");\n", rules, nil)
	assert.Empty(t, got, "sha256 should not be reported via bundle metavariable-regex")
}

func TestSemgrepBundlePatternInside(t *testing.T) {
	content := `rules:
  - id: BUNDLE-PATTERN-INSIDE
    severity: ERROR
    message: eval inside function only
    languages: [javascript]
    query: |
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")
        arguments: (arguments (_) @arg)
      ) @finding
    pattern-inside: |
      (function_declaration
        body: (statement_block) @body
      ) @func
`
	dir := t.TempDir()
	writeBundleFile(t, dir, "inside.yaml", content)

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.NotEmpty(t, rules[0].PatternInside, "pattern-inside should be loaded from bundle")

	got := scanContent(t, "function f() { eval(x); }\n", rules, nil)
	assert.Len(t, got, 1, "eval inside function should be reported")

	got = scanContent(t, "eval(x);\n", rules, nil)
	assert.Empty(t, got, "eval outside function should be filtered by pattern-inside")
}
