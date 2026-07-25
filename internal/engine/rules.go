package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"gopkg.in/yaml.v3"
)

// StringList accepts either a single YAML scalar or a string sequence.
type StringList []string

// UnmarshalYAML normalizes a scalar-or-sequence YAML node into a slice.
func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		trimmed := strings.TrimSpace(value.Value)
		if trimmed == "" {
			*s = nil
			return nil
		}
		*s = []string{trimmed}
		return nil
	case yaml.SequenceNode:
		out := make([]string, 0, len(value.Content))
		for _, child := range value.Content {
			if child.Kind != yaml.ScalarNode {
				return fmt.Errorf("expected string sequence item, got YAML kind %d", child.Kind)
			}
			trimmed := strings.TrimSpace(child.Value)
			if trimmed == "" {
				continue
			}
			out = append(out, trimmed)
		}
		*s = out
		return nil
	case 0:
		*s = nil
		return nil
	default:
		return fmt.Errorf("expected string or string sequence, got YAML kind %d", value.Kind)
	}
}

// TaintConfig declares how a rule wants intra-file taint analysis applied.
type TaintConfig struct {
	// SinkCapture is the @capture name whose argument should be analyzed.
	SinkCapture string `yaml:"sink_capture"`
	// RequireTainted drops the finding when the sink is provably a
	// constant or sanitized expression (i.e. not tainted).
	RequireTainted bool `yaml:"require_tainted"`
	// RequireProvenTainted keeps findings only when taint analysis can
	// prove the sink is tainted; sinks with unknown taint status are dropped.
	// This is only applied when RequireTainted is true.
	RequireProvenTainted bool `yaml:"require_proven_tainted"`
	// SinkArgIndex, when SinkCapture targets an `arguments` node, limits
	// taint analysis to a specific positional argument (0-based). When
	// omitted, all arguments are analyzed.
	SinkArgIndex *int `yaml:"sink_arg_index"`
}

type RuleMetadata struct {
	Category            string   `yaml:"category"`
	Taxonomy            []string `yaml:"taxonomy"`
	CWE                 []string `yaml:"cwe"`
	OWASP               []string `yaml:"owasp"`
	References          []string `yaml:"references"`
	Remediation         string   `yaml:"remediation"`
	ConfidenceRationale string   `yaml:"confidence_rationale"`
}

// RulePaths holds per-rule path inclusion and exclusion glob patterns,
// compatible with Semgrep's `paths:` field.
type RulePaths struct {
	Include StringList `yaml:"include"`
	Exclude StringList `yaml:"exclude"`
}

// Rule represents the structure of our YAML signature files.
// The tags (yaml:"...") tell the parser how to map the YAML keys to the struct fields.
//
// Beyond the original required fields (id/severity/framework/description/query),
// rules may opt into post-match heuristics that suppress likely false
// positives. All such fields are optional and additive — rules that omit
// them keep their previous behavior.
type Rule struct {
	ID          string     `yaml:"id"`
	Severity    string     `yaml:"severity"`
	Framework   string     `yaml:"framework"`
	Description string     `yaml:"description"`
	Query       string     `yaml:"query"`
	Language    string     `yaml:"language"`
	Message     string     `yaml:"message"`
	Tags        StringList `yaml:"tags"`
	References  StringList `yaml:"references"`
	CWE         StringList `yaml:"cwe"`
	OWASP       StringList `yaml:"owasp"`
	Remediation string     `yaml:"remediation"`

	// Confidence is reported alongside severity. Defaults to "MEDIUM".
	Confidence string `yaml:"confidence"`

	// IgnoreIfLiteral lists @capture names whose value, when a string,
	// number, regex, or non-interpolated template literal, suppresses
	// the finding (e.g. eval("use strict")).
	IgnoreIfLiteral []string `yaml:"ignore_if_literal"`

	// IgnoreIfMatches maps a @capture name to a regex; a match drops
	// the finding (e.g. URLs that start with a safe origin).
	IgnoreIfMatches map[string]string `yaml:"ignore_if_matches"`

	// RequireIfMatches maps a @capture name to a regex; the finding is
	// emitted only when the captured text matches the pattern (e.g.
	// crypto.createHash() only matters when the algorithm is md5/sha1).
	RequireIfMatches map[string]string `yaml:"require_if_matches"`

	// MinArgCount / MaxArgCount gate the rule on the number of
	// arguments passed to the matched call expression.
	MinArgCount *int `yaml:"min_arg_count"`
	MaxArgCount *int `yaml:"max_arg_count"`

	// RequiresDependency lists package names from package.json that
	// must be present for this rule to be evaluated. An empty list
	// means the rule runs on every project.
	RequiresDependency []string `yaml:"requires_dependency"`

	// Taint opts the rule into intra-file taint analysis.
	Taint *TaintConfig `yaml:"taint"`

	// Paths, when set, restricts the rule to files matching the include
	// glob patterns and excludes files matching the exclude patterns.
	// Compatible with Semgrep's `paths:` field.
	Paths *RulePaths `yaml:"paths"`

	Metadata RuleMetadata `yaml:"metadata"`

	compiled         *sitter.Query
	compiledLanguage string
	ignoreMatchers   map[string]*regexp.Regexp
	requireMatchers  map[string]*regexp.Regexp
	literalCaptures  map[string]struct{}
	captureNamesInit bool
}

type semgrepMetadata struct {
	Framework          string     `yaml:"framework"`
	Description        string     `yaml:"description"`
	Confidence         string     `yaml:"confidence"`
	Query              string     `yaml:"query"`
	RequiresDependency []string   `yaml:"requires_dependency"`
	Tags               StringList `yaml:"tags"`
	References         StringList `yaml:"references"`
	CWE                StringList `yaml:"cwe"`
	OWASP              StringList `yaml:"owasp"`
	Remediation        string     `yaml:"remediation"`
}

type semgrepRule struct {
	ID             string           `yaml:"id"`
	Severity       string           `yaml:"severity"`
	Message        string           `yaml:"message"`
	Query          string           `yaml:"query"`
	Pattern        string           `yaml:"pattern"`
	PatternEither  []semgrepPattern `yaml:"pattern-either"`
	Patterns       []semgrepPattern `yaml:"patterns"`
	PatternRegex   string           `yaml:"pattern-regex"`
	PatternNotRegex string          `yaml:"pattern-not-regex"`
	Languages      []string         `yaml:"languages"`
	Metadata       semgrepMetadata  `yaml:"metadata"`
	Paths          semgrepPaths     `yaml:"paths"`
}

type semgrepPattern struct {
	Pattern string `yaml:"pattern"`
}

type semgrepPaths struct {
	Include StringList `yaml:"include"`
	Exclude StringList `yaml:"exclude"`
}

type semgrepDocument struct {
	Rules []semgrepRule `yaml:"rules"`
}

func (r *Rule) compile() error {
	if r.Query == "" {
		return fmt.Errorf("rule %s has an empty query", r.ID)
	}

	spec, err := languageSpecForName(r.EffectiveLanguage())
	if err != nil {
		return fmt.Errorf("rule %s: %w", r.ID, err)
	}

	if r.compiled == nil || r.compiledLanguage != spec.key {
		compiled, err := sitter.NewQuery([]byte(r.Query), spec.language)
		if err != nil {
			return fmt.Errorf("failed to compile query for rule %s: %w", r.ID, err)
		}
		r.compiled = compiled
		r.compiledLanguage = spec.key
	}

	// Rebuild the post-match filter caches every call. Compilation is
	// cheap and this lets tests mutate Rule fields after construction
	// without having to clear `compiled` manually.
	r.ignoreMatchers = make(map[string]*regexp.Regexp, len(r.IgnoreIfMatches))
	for capture, pattern := range r.IgnoreIfMatches {
		re, reErr := regexp.Compile(pattern)
		if reErr != nil {
			return fmt.Errorf("rule %s ignore_if_matches[%s]: %w", r.ID, capture, reErr)
		}
		r.ignoreMatchers[capture] = re
	}

	r.requireMatchers = make(map[string]*regexp.Regexp, len(r.RequireIfMatches))
	for capture, pattern := range r.RequireIfMatches {
		re, reErr := regexp.Compile(pattern)
		if reErr != nil {
			return fmt.Errorf("rule %s require_if_matches[%s]: %w", r.ID, capture, reErr)
		}
		r.requireMatchers[capture] = re
	}

	r.literalCaptures = make(map[string]struct{}, len(r.IgnoreIfLiteral))
	for _, capture := range r.IgnoreIfLiteral {
		r.literalCaptures[capture] = struct{}{}
	}

	r.captureNamesInit = true
	return nil
}

// EffectiveLanguage returns the rule's normalized parser language.
func (r *Rule) EffectiveLanguage() string {
	if strings.TrimSpace(r.Language) == "" {
		return "javascript"
	}
	return normalizeLanguageName(r.Language)
}

// EffectiveConfidence returns the rule's confidence, defaulting to
// "MEDIUM" when the rule does not declare one.
func (r *Rule) EffectiveConfidence() string {
	if r.Confidence == "" {
		return "MEDIUM"
	}
	return strings.ToUpper(r.Confidence)
}

// EffectiveDescription returns the best available descriptive text.
func (r *Rule) EffectiveDescription() string {
	if strings.TrimSpace(r.Description) != "" {
		return strings.TrimSpace(r.Description)
	}
	if strings.TrimSpace(r.Message) != "" {
		return strings.TrimSpace(r.Message)
	}
	return fmt.Sprintf("Rule %s matched", strings.TrimSpace(r.ID))
}

// LoadRules scans a directory for .yaml files and parses them into a slice of Rule structs.
func LoadRules(rulesDir string) ([]Rule, error) {
	var rules []Rule

	err := filepath.WalkDir(rulesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" {
			fileData, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read rule file %s: %w", path, err)
			}

			var rule Rule
			if err := yaml.Unmarshal(fileData, &rule); err != nil {
				return fmt.Errorf("failed to parse YAML in %s: %w", path, err)
			}

			// Native rule format.
			if rule.ID != "" && rule.Query != "" {
				rules = append(rules, rule)
				return nil
			}

			// Semgrep/OpenGrep bundle format.
			var doc semgrepDocument
			if err := yaml.Unmarshal(fileData, &doc); err != nil {
				return fmt.Errorf("failed to parse YAML in %s: %w", path, err)
			}
			if len(doc.Rules) == 0 {
				fmt.Printf("[-] Warning: Skipping file %s (not a valid native rule or Semgrep/OpenGrep bundle)\n", path)
				return nil
			}

			for _, semgrep := range doc.Rules {
				converted, ok := semgrepToRule(semgrep)
				if !ok {
					fmt.Printf("[-] Warning: Skipping invalid Semgrep/OpenGrep rule in %s (%s, missing ID and/or Tree-sitter-compatible query)\n", path, semgrepRuleLabel(semgrep.ID))
					continue
				}
				rules = append(rules, converted)
			}
		}
		return nil
	})

	return rules, err
}

func semgrepToRule(in semgrepRule) (Rule, bool) {
	id := strings.TrimSpace(in.ID)
	query := ""

	description := strings.TrimSpace(in.Message)
	if description == "" {
		description = strings.TrimSpace(in.Metadata.Description)
	}
	if description == "" {
		description = fmt.Sprintf("Imported from Semgrep/OpenGrep rule %s", id)
	}

	language := normalizeSemgrepLanguage(in.Metadata.Framework, in.Languages)
	query = strings.TrimSpace(resolveSemgrepQuery(in, language))
	if id == "" || query == "" {
		return Rule{}, false
	}

	out := Rule{
		ID:                 id,
		Severity:           normalizeSemgrepSeverity(in.Severity),
		Framework:          normalizeSemgrepFramework(in.Metadata.Framework, in.Languages),
		Description:        description,
		Query:              query,
		Language:           language,
		Message:            strings.TrimSpace(in.Message),
		Confidence:         strings.TrimSpace(in.Metadata.Confidence),
		RequiresDependency: in.Metadata.RequiresDependency,
		Tags:               in.Metadata.Tags,
		References:         in.Metadata.References,
		CWE:                in.Metadata.CWE,
		OWASP:              in.Metadata.OWASP,
		Remediation:        strings.TrimSpace(in.Metadata.Remediation),
	}

	// Map pattern-not-regex → ignore_if_matches on the @finding capture.
	// Map pattern-regex → require_if_matches on the @finding capture.
	// These are approximate equivalents: Semgrep's pattern-*-regex operators
	// match the full matched code text, which @finding captures here.
	if r := strings.TrimSpace(in.PatternNotRegex); r != "" {
		if out.IgnoreIfMatches == nil {
			out.IgnoreIfMatches = make(map[string]string)
		}
		out.IgnoreIfMatches["finding"] = r
	}
	if r := strings.TrimSpace(in.PatternRegex); r != "" {
		if out.RequireIfMatches == nil {
			out.RequireIfMatches = make(map[string]string)
		}
		out.RequireIfMatches["finding"] = r
	}

	// Map Semgrep paths: include/exclude → per-rule path filters.
	if len(in.Paths.Include) > 0 || len(in.Paths.Exclude) > 0 {
		out.Paths = &RulePaths{
			Include: in.Paths.Include,
			Exclude: in.Paths.Exclude,
		}
	}

	return out, true
}

func resolveSemgrepQuery(in semgrepRule, language string) string {
	candidates := []string{
		strings.TrimSpace(in.Query),
		strings.TrimSpace(in.Metadata.Query),
	}

	for _, p := range in.PatternEither {
		candidates = append(candidates, strings.TrimSpace(p.Pattern))
	}
	for _, p := range in.Patterns {
		candidates = append(candidates, strings.TrimSpace(p.Pattern))
	}

	spec, err := languageSpecForName(language)
	if err != nil {
		return ""
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, err := sitter.NewQuery([]byte(candidate), spec.language); err == nil {
			return candidate
		}
	}
	return ""
}

func semgrepRuleLabel(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "id=<empty>"
	}
	return "id=" + id
}

func normalizeSemgrepSeverity(in string) string {
	sev := strings.ToUpper(strings.TrimSpace(in))
	switch sev {
	case "ERROR":
		return "HIGH"
	case "WARNING":
		return "MEDIUM"
	case "INFO":
		return "LOW"
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return sev
	default:
		return "MEDIUM"
	}
}

func normalizeSemgrepFramework(explicit string, languages []string) string {
	if framework := strings.TrimSpace(explicit); framework != "" {
		return framework
	}

	for _, language := range languages {
		switch strings.ToLower(strings.TrimSpace(language)) {
		case "javascript", "js", "typescript", "ts", "jsx", "tsx":
			return "JavaScript"
		case "react":
			return "React"
		case "angular":
			return "Angular"
		case "vue":
			return "Vue"
		case "node", "nodejs", "node.js":
			return "Node.js"
		case "express":
			return "Express"
		case "next", "nextjs", "next.js":
			return "Next.js"
		}
	}

	return "JavaScript"
}

func normalizeSemgrepLanguage(explicit string, languages []string) string {
	if language := normalizeLanguageName(explicit); language != "javascript" || strings.TrimSpace(explicit) != "" {
		if _, ok := languageSpecs[language]; ok {
			return languageSpecs[language].displayName
		}
	}

	for _, language := range languages {
		normalized := normalizeLanguageName(language)
		if spec, ok := languageSpecs[normalized]; ok {
			return spec.displayName
		}
	}

	return "JavaScript"
}
