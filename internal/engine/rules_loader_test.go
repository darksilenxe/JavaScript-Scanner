package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadRulesSemgrepFormat(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "semgrep.yaml")
	content := `rules:
  - id: SEMGREP-EVAL
    message: Detect eval usage from Semgrep rule format
    severity: ERROR
    languages: [javascript, typescript]
    query: |
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")
      ) @finding
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	assert.Equal(t, "SEMGREP-EVAL", rules[0].ID)
	assert.Equal(t, "HIGH", rules[0].Severity)
	assert.Equal(t, "JavaScript", rules[0].Framework)
	assert.Equal(t, "Detect eval usage from Semgrep rule format", rules[0].Description)
	assert.Contains(t, rules[0].Query, "(call_expression")
}

func TestLoadRulesMetadataFields(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "opengrep.yaml")
	content := `rules:
  - id: OPENGREP-INNERHTML
    message: Detect innerHTML assignment from OpenGrep-style bundle
    severity: WARNING
    languages: [javascript]
    metadata:
      framework: React
      confidence: HIGH
      tags: [xss, dom]
      references:
        - https://example.com/rules/opengrep-innerhtml
      cwe: CWE-79
      owasp:
        - A03:2021-Injection
      remediation: Avoid writing unsanitized HTML into the DOM.
      requires_dependency:
        - react
      category: Cross-Site Scripting
      taxonomy:
        - code-pattern/framework
      cwe:
        - CWE-79
      owasp:
        - A03:2021
      references:
        - https://example.com/react-xss
      remediation: Sanitize before rendering.
      confidence_rationale: React sink.
      # query is intentionally in metadata to validate OpenGrep/Semgrep bundle mapping.
      query: |
        (assignment_expression
          left: (member_expression
            property: (property_identifier) @prop (#eq? @prop "innerHTML")
          )
        ) @finding
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	assert.Equal(t, "OPENGREP-INNERHTML", rules[0].ID)
	assert.Equal(t, "MEDIUM", rules[0].Severity)
	assert.Equal(t, "React", rules[0].Framework)
	assert.Equal(t, "HIGH", rules[0].Confidence)
	assert.Equal(t, []string{"xss", "dom"}, []string(rules[0].Tags))
	assert.Equal(t, []string{"https://example.com/rules/opengrep-innerhtml"}, []string(rules[0].References))
	assert.Equal(t, []string{"CWE-79"}, []string(rules[0].CWE))
	assert.Equal(t, []string{"A03:2021-Injection"}, []string(rules[0].OWASP))
	assert.Equal(t, "Avoid writing unsanitized HTML into the DOM.", rules[0].Remediation)
	assert.Equal(t, []string{"react"}, rules[0].RequiresDependency)
	assert.Equal(t, "Cross-Site Scripting", rules[0].Metadata.Category)
	assert.Equal(t, []string{"code-pattern/framework"}, rules[0].Metadata.Taxonomy)
	assert.Equal(t, []string{"CWE-79"}, rules[0].Metadata.CWE)
	assert.Equal(t, []string{"A03:2021"}, rules[0].Metadata.OWASP)
	assert.Equal(t, []string{"https://example.com/react-xss"}, rules[0].Metadata.References)
	assert.Equal(t, "Sanitize before rendering.", rules[0].Metadata.Remediation)
	assert.Equal(t, "React sink.", rules[0].Metadata.ConfidenceRationale)
	assert.Contains(t, rules[0].Query, "innerHTML")
}

func TestLoadRulesNativeMetadataFields(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "native.yaml")
	content := `id: NATIVE-EVAL
severity: HIGH
framework: JavaScript
description: Detect eval usage from native format
message: Prefer safer parsers over eval.
tags:
  - injection
  - javascript
references: https://example.com/rules/native-eval
cwe:
  - CWE-95
owasp: A03:2021-Injection
remediation: Remove eval on attacker-controlled input.
query: |
  (call_expression
    function: (identifier) @fn
    (#eq? @fn "eval")
  ) @finding
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	assert.Equal(t, "NATIVE-EVAL", rules[0].ID)
	assert.Equal(t, "Prefer safer parsers over eval.", rules[0].Message)
	assert.Equal(t, []string{"injection", "javascript"}, []string(rules[0].Tags))
	assert.Equal(t, []string{"https://example.com/rules/native-eval"}, []string(rules[0].References))
	assert.Equal(t, []string{"CWE-95"}, []string(rules[0].CWE))
	assert.Equal(t, []string{"A03:2021-Injection"}, []string(rules[0].OWASP))
	assert.Equal(t, "Remove eval on attacker-controlled input.", rules[0].Remediation)
	assert.Equal(t, "Detect eval usage from native format", rules[0].EffectiveDescription())
}

func TestLoadRulesSkipsSemgrepPatternOnlyRules(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "pattern_only.yaml")
	content := `rules:
  - id: SEMGREP-PATTERN-ONLY
    severity: ERROR
    message: Pattern is semgrep syntax, not tree-sitter query
    pattern: eval($X)
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	assert.Len(t, rules, 0)
}

func TestLoadRulesSemgrepPathsFilter(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "paths_rule.yaml")
	content := `rules:
  - id: SEMGREP-PATHS-TEST
    severity: WARNING
    message: Rule with path filters
    languages: [javascript]
    paths:
      include:
        - "src/**/*.js"
      exclude:
        - "src/vendor/**"
    query: |
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")
      ) @finding
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	require.NotNil(t, rules[0].Paths, "Paths should be populated from the bundle")
	assert.Equal(t, []string{"src/**/*.js"}, []string(rules[0].Paths.Include))
	assert.Equal(t, []string{"src/vendor/**"}, []string(rules[0].Paths.Exclude))
}

func TestLoadRulesSemgrepPatternNotRegex(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "not_regex.yaml")
	content := `rules:
  - id: SEMGREP-NOT-REGEX
    severity: ERROR
    message: Detect eval unless it matches the safe pattern
    languages: [javascript]
    pattern-not-regex: "safe_eval"
    query: |
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")
      ) @finding
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	assert.Equal(t, "SEMGREP-NOT-REGEX", rules[0].ID)
	// pattern-not-regex should be mapped to ignore_if_matches on @finding
	assert.Equal(t, map[string]string{"finding": "safe_eval"}, rules[0].IgnoreIfMatches)
}

func TestLoadRulesSemgrepPatternRegex(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "regex.yaml")
	content := `rules:
  - id: SEMGREP-PATTERN-REGEX
    severity: WARNING
    message: Detect eval only when it contains dangerous patterns
    languages: [javascript]
    pattern-regex: "userInput|req\\.body"
    query: |
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")
      ) @finding
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	assert.Equal(t, "SEMGREP-PATTERN-REGEX", rules[0].ID)
	// pattern-regex should be mapped to require_if_matches on @finding
	assert.Equal(t, map[string]string{"finding": `userInput|req\.body`}, rules[0].RequireIfMatches)
}

