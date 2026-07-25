package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
)

// Finding represents a discovered vulnerability
type Finding struct {
	Kind                string   `json:"kind,omitempty"`
	File                string   `json:"file,omitempty"`
	Line                uint32   `json:"line,omitempty"`
	Column              uint32   `json:"column,omitempty"`
	EndLine             uint32   `json:"end_line,omitempty"`
	EndColumn           uint32   `json:"end_column,omitempty"`
	RuleID              string   `json:"rule_id"`
	Severity            string   `json:"severity"`
	Framework           string   `json:"framework"`
	Snippet             string   `json:"snippet,omitempty"`
	MatchedCode         string   `json:"matched_code,omitempty"`
	HighlightedSnippet  string   `json:"highlighted_snippet,omitempty"`
	Confidence          string   `json:"confidence,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	Description         string   `json:"description,omitempty"`
	Category            string   `json:"category,omitempty"`
	Taxonomy            []string `json:"taxonomy,omitempty"`
	CWE                 []string `json:"cwe,omitempty"`
	OWASP               []string `json:"owasp,omitempty"`
	References          []string `json:"references,omitempty"`
	Remediation         string   `json:"remediation,omitempty"`
	ConfidenceRationale string   `json:"confidence_rationale,omitempty"`
	PackageName         string   `json:"package_name,omitempty"`
	DeclaredVersion     string   `json:"declared_version,omitempty"`
	ResolvedVersion     string   `json:"resolved_version,omitempty"`
	VersionSource       string   `json:"version_source,omitempty"`
	FixedVersions       []string `json:"fixed_versions,omitempty"`
	ProjectPath         string   `json:"project_path,omitempty"`
	// Fingerprint is a deterministic, location-independent identifier
	// used to compare findings across runs (baselines, diffs). It is
	// derived from rule ID, the relative file path, the matched code,
	// and normalized neighbor-line context — never raw line numbers.
	Fingerprint string `json:"fingerprint,omitempty"`
}

const maxSnippetLen = 120

// extractSnippet returns the trimmed text of the source line at the given
// zero-based row index, capped at 120 characters.
func extractSnippet(sourceCode []byte, row uint32) string {
	lines := bytes.Split(sourceCode, []byte("\n"))
	if int(row) >= len(lines) {
		return ""
	}
	line := strings.TrimSpace(string(lines[row]))
	if len(line) > maxSnippetLen {
		return line[:maxSnippetLen] + "..."
	}
	return line
}

func extractFindingContext(sourceCode []byte, row uint32, node *sitter.Node) (snippet string, matchedCode string, highlighted string) {
	snippet = extractSnippet(sourceCode, row)
	highlighted = snippet
	if node == nil {
		return snippet, "", highlighted
	}

	matchedCode = strings.TrimSpace(node.Content(sourceCode))
	if matchedCode == "" {
		return snippet, "", highlighted
	}

	lines := bytes.Split(sourceCode, []byte("\n"))
	startPoint := node.StartPoint()
	endPoint := node.EndPoint()
	if int(startPoint.Row) >= len(lines) || int(endPoint.Row) >= len(lines) || startPoint.Row != endPoint.Row {
		firstLine := ""
		if int(startPoint.Row) < len(lines) {
			firstLine = strings.TrimSpace(string(lines[startPoint.Row]))
		}
		if firstLine == "" {
			firstLine = truncateSnippet(matchedCode)
		}
		highlighted = fmt.Sprintf(
			"[[DANGEROUS]]%s[[/DANGEROUS]] (lines %d-%d)",
			truncateSnippet(firstLine),
			startPoint.Row+1,
			endPoint.Row+1,
		)
		return snippet, matchedCode, highlighted
	}

	line := string(lines[startPoint.Row])
	startColumn := int(startPoint.Column)
	endColumn := int(endPoint.Column)
	if startColumn < 0 {
		startColumn = 0
	}
	if endColumn > len(line) {
		endColumn = len(line)
	}
	if startColumn > endColumn {
		startColumn = endColumn
	}

	highlightedLine := line[:startColumn] + "[[DANGEROUS]]" + line[startColumn:endColumn] + "[[/DANGEROUS]]" + line[endColumn:]
	highlighted = truncateSnippet(strings.TrimSpace(highlightedLine))
	return snippet, matchedCode, highlighted
}

func truncateSnippet(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > maxSnippetLen {
		return trimmed[:maxSnippetLen] + "..."
	}
	return trimmed
}

// VariableState tracks the lifecycle of a specific variable
type VariableState struct {
	Name        string
	IsTainted   bool
	IsSanitized bool // The "firewall" flag
}

// SymbolTable holds the state of all variables in the current execution scope
type SymbolTable struct {
	Variables map[string]*VariableState
}

// Engine holds the configuration for the scanning process
type Engine struct {
	Rules []Rule

	// IncludeTests, when true, scans test/spec files (off by default).
	IncludeTests bool
	// IncludeVendored, when true, scans vendored / build-output files
	// (off by default).
	IncludeVendored bool

	// ProjectDependencies enumerates package names declared in the
	// scanned project's package.json. When non-empty it is used to
	// gate rules that declare a `requires_dependency` list.
	ProjectDependencies map[string]struct{}

	// EnableDependencyGating, when true, suppresses framework-specific
	// rules that declare a `requires_dependency` list when none of those
	// packages appear in the scanned project's inventory. Off by default
	// so existing scan baselines are preserved.
	EnableDependencyGating bool

	// ExcludedPaths are absolute paths that should not be scanned. Entries
	// may be files or directories.
	ExcludedPaths []string

	// TargetDir is the directory passed to ScanDirectory; it is used to
	// derive relative paths for fingerprint computation so the same
	// finding produces the same identifier across different CI
	// environments.
	TargetDir string

	// ChangedFiles, when non-nil, restricts scanning to the listed
	// absolute file paths. This implements the diff-mode workflow where
	// callers pass `git diff --name-only` to scope a scan to changed
	// files while still loading the full project dependency context.
	ChangedFiles map[string]struct{}

	// IncludeGlobs, when non-empty, restricts scanning to files whose
	// path matches at least one glob pattern. Patterns without a "/"
	// are matched against the file's base name. Supports "**" wildcards.
	// Compatible with Semgrep's --include flag.
	IncludeGlobs []string

	// ExcludeGlobs, when non-empty, skips files whose path matches at
	// least one glob pattern. Applied after IncludeGlobs.
	// Compatible with Semgrep's --exclude flag.
	ExcludeGlobs []string
}

// New constructs an Engine with default (false-positive-conservative)
// path filters: tests and vendored files are excluded from scans.
func New(rules []Rule) *Engine {
	return &Engine{
		Rules:           rules,
		IncludeTests:    false,
		IncludeVendored: false,
	}
}

// SetProjectDependencies records the package names available to the
// scanned project so dependency-gated rules can be filtered out.
func (e *Engine) SetProjectDependencies(names []string) {
	if len(names) == 0 {
		e.ProjectDependencies = nil
		return
	}
	e.ProjectDependencies = make(map[string]struct{}, len(names))
	for _, n := range names {
		e.ProjectDependencies[n] = struct{}{}
	}
}

// shouldScanFile returns false when path-based filters mean the file
// should be skipped given the engine's include flags.
func (e *Engine) shouldScanFile(path string) bool {
	if e.isExcludedPath(path) {
		return false
	}
	if !e.IncludeVendored && IsVendoredPath(path) {
		return false
	}
	if !e.IncludeTests && IsTestPath(path) {
		return false
	}
	if !e.isChangedFile(path) {
		return false
	}

	// Engine-level glob filters (--include / --exclude).
	slashPath := filepath.ToSlash(path)
	if len(e.IncludeGlobs) > 0 && !matchesAnyGlob(e.IncludeGlobs, slashPath) {
		return false
	}
	if len(e.ExcludeGlobs) > 0 && matchesAnyGlob(e.ExcludeGlobs, slashPath) {
		return false
	}

	return true
}

// SetChangedFiles records the set of files that diff-mode scans should
// be restricted to. Entries are normalized to absolute, cleaned paths.
// A nil or empty argument disables diff mode (scan everything).
func (e *Engine) SetChangedFiles(paths []string) {
	if len(paths) == 0 {
		e.ChangedFiles = nil
		return
	}
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		abs, err := filepath.Abs(trimmed)
		if err != nil {
			continue
		}
		set[filepath.Clean(abs)] = struct{}{}
	}
	if len(set) == 0 {
		e.ChangedFiles = nil
		return
	}
	e.ChangedFiles = set
}

// isChangedFile returns true when diff mode is disabled or the given
// file is part of the configured changed-files set.
func (e *Engine) isChangedFile(path string) bool {
	if len(e.ChangedFiles) == 0 {
		return true
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	_, ok := e.ChangedFiles[filepath.Clean(abs)]
	return ok
}

// SetExcludedPaths records files/directories that should not be scanned.
func (e *Engine) SetExcludedPaths(paths []string) {
	if len(paths) == 0 {
		e.ExcludedPaths = nil
		return
	}

	seen := make(map[string]struct{}, len(paths))
	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		abs, err := filepath.Abs(trimmed)
		if err != nil {
			continue
		}
		clean := filepath.Clean(abs)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		normalized = append(normalized, clean)
	}

	e.ExcludedPaths = normalized
}

func (e *Engine) isExcludedPath(path string) bool {
	if len(e.ExcludedPaths) == 0 {
		return false
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	clean := filepath.Clean(abs)

	for _, excluded := range e.ExcludedPaths {
		if clean == excluded {
			return true
		}
		rel, err := filepath.Rel(excluded, clean)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

// ruleAppliesToProject returns false when the rule declares a
// `requires_dependency` list, dependency gating is enabled, and none
// of those packages are present in the scanned project.
//
// Dependency gating is opt-in: it only kicks in when EnableDependencyGating
// is true and the project inventory has been populated. This preserves
// existing scan baselines for users who do not enable the flag.
func (e *Engine) ruleAppliesToProject(rule Rule) bool {
	if !e.EnableDependencyGating {
		return true
	}
	if len(rule.RequiresDependency) == 0 {
		return true
	}
	if e.ProjectDependencies == nil {
		// No inventory available — fall back to running the rule
		// rather than silently dropping signal.
		return true
	}
	for _, dep := range rule.RequiresDependency {
		if _, ok := e.ProjectDependencies[dep]; ok {
			return true
		}
	}
	return false
}

func findingNodeForMatch(rule Rule, match *sitter.QueryMatch) *sitter.Node {
	var widestNode *sitter.Node
	var widestSpan uint32

	for _, capture := range match.Captures {
		if capture.Node == nil {
			continue
		}

		if rule.compiled.CaptureNameForId(capture.Index) == "finding" {
			return capture.Node
		}

		span := capture.Node.EndByte() - capture.Node.StartByte()
		if widestNode == nil || span > widestSpan {
			widestNode = capture.Node
			widestSpan = span
		}
	}

	return widestNode
}

// captureMap returns the matched nodes keyed by their capture name.
// When a capture name appears multiple times the last node wins; this
// matches Tree-sitter's general behavior for repeated names.
func captureMap(rule Rule, match *sitter.QueryMatch) map[string]*sitter.Node {
	out := make(map[string]*sitter.Node, len(match.Captures))
	for _, capture := range match.Captures {
		if capture.Node == nil {
			continue
		}
		name := rule.compiled.CaptureNameForId(capture.Index)
		out[name] = capture.Node
	}
	return out
}

// passesFilters applies all configured post-match heuristics for a rule
// and returns true when the finding should be emitted.
func (e *Engine) passesFilters(rule Rule, captures map[string]*sitter.Node, source []byte, taint *fileTaintModel) bool {
	// ignore_if_literal — drop when the named capture is a literal
	// expression at the AST level (string, number, regex, or template
	// string with no `${...}` substitutions). This is intentionally
	// conservative: identifiers that *resolve* to constants via the
	// per-file model are NOT suppressed here — that decision belongs
	// to opt-in `taint:` analysis.
	for capture := range rule.literalCaptures {
		node, ok := captures[capture]
		if !ok || node == nil {
			continue
		}
		if classifyExpression(node, source, nil) == taintConstant {
			return false
		}
	}

	// ignore_if_matches — drop when the captured text matches the
	// safe pattern.
	for capture, re := range rule.ignoreMatchers {
		node, ok := captures[capture]
		if !ok || node == nil {
			continue
		}
		if re.MatchString(node.Content(source)) {
			return false
		}
	}

	// require_if_matches — keep only when the captured text matches
	// the risky pattern.
	for capture, re := range rule.requireMatchers {
		node, ok := captures[capture]
		if !ok || node == nil {
			return false
		}
		if !re.MatchString(node.Content(source)) {
			return false
		}
	}

	// min_arg_count / max_arg_count — gate on the call expression's
	// arguments list when one of the captured nodes (or an ancestor)
	// is a call.
	if rule.MinArgCount != nil || rule.MaxArgCount != nil {
		argCount, ok := argumentCountFromCaptures(captures)
		if ok {
			if rule.MinArgCount != nil && argCount < *rule.MinArgCount {
				return false
			}
			if rule.MaxArgCount != nil && argCount > *rule.MaxArgCount {
				return false
			}
		}
	}

	// taint — when a rule opts in, drop the finding if the sink
	// capture resolves to a constant or sanitized expression.
	if rule.Taint != nil && rule.Taint.RequireTainted && taint != nil {
		node, ok := captures[rule.Taint.SinkCapture]
		if !ok || node == nil {
			if rule.Taint.RequireProvenTainted {
				return false
			}
		} else {
			flavor := taint.resolveCapture(node, source, rule.Taint)
			if rule.Taint.RequireProvenTainted {
				return flavor == taintTainted
			}
			if flavor == taintConstant || flavor == taintSanitized {
				return false
			}
		}
	}

	return true
}

// argumentCountFromCaptures looks for an arguments list among the
// captured nodes (or as a child of a captured call expression) and
// returns its named-child count.
func argumentCountFromCaptures(captures map[string]*sitter.Node) (int, bool) {
	for _, node := range captures {
		if node == nil {
			continue
		}
		if node.Type() == "arguments" {
			return int(node.NamedChildCount()), true
		}
		if node.Type() == "call_expression" {
			args := node.ChildByFieldName("arguments")
			if args != nil {
				return int(args.NamedChildCount()), true
			}
		}
		// Walk up briefly to find an enclosing call.
		parent := node.Parent()
		for hops := 0; parent != nil && hops < 3; hops++ {
			if parent.Type() == "call_expression" {
				args := parent.ChildByFieldName("arguments")
				if args != nil {
					return int(args.NamedChildCount()), true
				}
			}
			parent = parent.Parent()
		}
	}
	return 0, false
}

// ruleMatchesPath returns false when the rule's `paths:` filter is set
// and the file path does not satisfy the include/exclude conditions.
// When the rule has no path filters, it always returns true.
//
// Include patterns are checked first: if any include patterns are set
// the path must match at least one. Exclude patterns are then checked:
// if any exclude patterns match the file is skipped.
func ruleMatchesPath(rule Rule, slashPath string) bool {
	if rule.Paths == nil {
		return true
	}
	if len(rule.Paths.Include) > 0 {
		if !matchesAnyGlob([]string(rule.Paths.Include), slashPath) {
			return false
		}
	}
	if len(rule.Paths.Exclude) > 0 {
		if matchesAnyGlob([]string(rule.Paths.Exclude), slashPath) {
			return false
		}
	}
	return true
}

func (e *Engine) matchRules(tree *sitter.Tree, sourceCode []byte, path string, languageKey string, findings chan<- Finding, suppress suppressionMap, taint *fileTaintModel) {
	slashPath := filepath.ToSlash(path)
	for _, rule := range e.Rules {
		if !e.ruleAppliesToProject(rule) {
			continue
		}
		if normalizeLanguageName(rule.EffectiveLanguage()) != languageKey {
			continue
		}
		if !ruleMatchesPath(rule, slashPath) {
			continue
		}

		if err := rule.compile(); err != nil {
			fmt.Printf("[-] Warning: %v\n", err)
			continue
		}

		cursor := sitter.NewQueryCursor()
		cursor.Exec(rule.compiled, tree.RootNode())

		for {
			match, ok := cursor.NextMatch()
			if !ok {
				break
			}

			filteredMatch := cursor.FilterPredicates(match, sourceCode)
			if len(filteredMatch.Captures) == 0 {
				continue
			}

			captures := captureMap(rule, filteredMatch)
			if !e.passesFilters(rule, captures, sourceCode, taint) {
				continue
			}

			root := tree.RootNode()
			row := root.StartPoint().Row
			col := root.StartPoint().Column
			endRow := row
			endCol := col
			findingNode := findingNodeForMatch(rule, filteredMatch)
			if findingNode != nil {
				row = findingNode.StartPoint().Row
				col = findingNode.StartPoint().Column
				endRow = findingNode.EndPoint().Row
				endCol = findingNode.EndPoint().Column
			}

			line := uint32(row + 1)
			if suppress.isSuppressed(line, rule.ID) {
				continue
			}
			snippet, matchedCode, highlightedSnippet := extractFindingContext(sourceCode, uint32(row), findingNode)

			fingerprint := ComputeFingerprint(rule.ID, path, e.TargetDir, fingerprintMatchedCode(matchedCode, snippet), neighborLines(sourceCode, uint32(row)))

			findings <- Finding{
				Kind:                "code",
				File:                path,
				Line:                line,
				Column:              uint32(col + 1),
				EndLine:             uint32(endRow + 1),
				EndColumn:           uint32(endCol + 1),
				RuleID:              rule.ID,
				Severity:            rule.Severity,
				Framework:           normalizeFramework(rule.Framework),
				Snippet:             snippet,
				MatchedCode:         matchedCode,
				HighlightedSnippet:  highlightedSnippet,
				Confidence:          rule.EffectiveConfidence(),
				Tags:                append([]string(nil), []string(rule.Tags)...),
				Description:         rule.Description,
				Category:            rule.Metadata.Category,
				Taxonomy:            append([]string(nil), rule.Metadata.Taxonomy...),
				CWE:                 append([]string(nil), rule.Metadata.CWE...),
				OWASP:               append([]string(nil), rule.Metadata.OWASP...),
				References:          append([]string(nil), rule.Metadata.References...),
				Remediation:         rule.Metadata.Remediation,
				ConfidenceRationale: rule.Metadata.ConfidenceRationale,
				Fingerprint:         fingerprint,
			}
		}

		cursor.Close()
	}
}

func (e *Engine) ScanDirectory(targetDir string, findings chan<- Finding) error {
	var wg sync.WaitGroup
	e.TargetDir = targetDir

	err := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Prune obvious non-source directories early so we do not
			// waste time walking into them. CLI overrides re-enable
			// these via IncludeTests / IncludeVendored.
			if !e.IncludeVendored {
				name := d.Name()
				if name == "node_modules" || name == ".git" || name == "dist" ||
					name == "build" || name == "out" || name == "coverage" ||
					name == ".next" || name == "vendor" {
					return filepath.SkipDir
				}
			}
			if !e.IncludeTests {
				name := d.Name()
				if name == "__tests__" || name == "__mocks__" ||
					name == "cypress" || name == "e2e" || name == "playwright" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if _, ok := languageSpecForPath(path); !ok {
			return nil
		}
		if !e.shouldScanFile(path) {
			return nil
		}

		wg.Add(1)
		go e.scanFile(path, &wg, findings)
		return nil
	})

	go func() {
		wg.Wait()
		close(findings)
	}()

	return err
}

// scanFile parses the code and kicks off the AST walker
func (e *Engine) scanFile(path string, wg *sync.WaitGroup, findings chan<- Finding) {
	defer wg.Done()

	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	spec, ok := languageSpecForPath(path)
	if !ok {
		return
	}

	parser := sitter.NewParser()
	parser.SetLanguage(spec.language)

	tree, _ := parser.ParseCtx(context.Background(), nil, content)
	if tree == nil {
		return
	}

	suppress := buildSuppressionMap(content)
	var taint *fileTaintModel
	if spec.supportsTaint {
		taint = buildFileTaintModel(tree.RootNode(), content)
	}

	e.matchRules(tree, content, path, spec.key, findings, suppress, taint)

	// Initialize our state tracker for this specific file
	symTable := &SymbolTable{
		Variables: make(map[string]*VariableState),
	}

	// Start walking the tree from the root node
	e.walkNode(tree.RootNode(), content, symTable, path, findings, suppress)
}

// walkNode recursively traverses the AST, functioning as a state machine
func (e *Engine) walkNode(node *sitter.Node, sourceCode []byte, symTable *SymbolTable, path string, findings chan<- Finding, suppress suppressionMap) {
	if node == nil {
		return
	}

	// --- 1. THE SOURCES (Data Entry) ---
	if node.Type() == "variable_declarator" {
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			varName := nameNode.Content(sourceCode)

			// For our prototype: if it's named "payload" or comes from a loop variable, taint it.
			isTainted := (varName == "payload" || varName == "key")

			symTable.Variables[varName] = &VariableState{
				Name:        varName,
				IsTainted:   isTainted,
				IsSanitized: false,
			}
		}
	}

	// --- 2. THE SANITIZERS (The Firewall Check) ---
	if node.Type() == "if_statement" {
		conditionNode := node.ChildByFieldName("condition")

		if conditionNode != nil && conditionNode.NamedChildCount() > 0 {
			exprNode := conditionNode.NamedChild(0)

			if exprNode.Type() == "binary_expression" {
				left := exprNode.ChildByFieldName("left")
				right := exprNode.ChildByFieldName("right")

				if left != nil && right != nil {
					leftContent := left.Content(sourceCode)
					rightContent := right.Content(sourceCode)

					if rightContent == "'__proto__'" || rightContent == "\"__proto__\"" {
						if state, exists := symTable.Variables[leftContent]; exists {
							state.IsSanitized = true
						}
					}
				}
			}
		}
	}

	// --- 3. THE SINKS (Vulnerability Execution) ---
	if node.Type() == "assignment_expression" {
		leftNode := node.ChildByFieldName("left")

		if leftNode != nil && leftNode.Type() == "subscript_expression" {
			indexNode := leftNode.ChildByFieldName("index")

			if indexNode != nil {
				keyName := indexNode.Content(sourceCode)

				if state, exists := symTable.Variables[keyName]; exists {
					if state.IsTainted && !state.IsSanitized {
						row := node.StartPoint().Row
						line := uint32(row + 1)
						if !suppress.isSuppressed(line, "proto-assignment") {
							snippet, matchedCode, highlightedSnippet := extractFindingContext(sourceCode, uint32(row), node)
							fingerprint := ComputeFingerprint("proto-assignment", path, e.TargetDir, fingerprintMatchedCode(matchedCode, snippet), neighborLines(sourceCode, uint32(row)))
							findings <- Finding{
								Kind:               "code",
								File:               path,
								Line:               line,
								Column:             uint32(node.StartPoint().Column + 1),
								EndLine:            uint32(node.EndPoint().Row + 1),
								EndColumn:          uint32(node.EndPoint().Column + 1),
								RuleID:             "proto-assignment",
								Severity:           "HIGH",
								Framework:          "JavaScript",
								Snippet:            snippet,
								MatchedCode:        matchedCode,
								HighlightedSnippet: highlightedSnippet,
								Confidence:         "HIGH",
								Description:        "Detects tainted prototype key assignment that can enable prototype pollution.",
								Category:           "Prototype Pollution",
								CWE:                []string{"CWE-1321"},
								OWASP:              []string{"A03:2021"},
								Remediation:        "Reject special keys like __proto__, constructor, and prototype before merging attacker-controlled input.",
								Fingerprint:        fingerprint,
							}
						}
					}
				}
			}
		}
	}

	// --- 4. RECURSION ---
	for i := 0; i < int(node.ChildCount()); i++ {
		e.walkNode(node.Child(i), sourceCode, symTable, path, findings, suppress)
	}
}

// fingerprintMatchedCode picks the most stable text fragment available
// for fingerprint computation. The AST-matched code is preferred; the
// snippet line is used only as a fallback (for findings emitted from
// hand-rolled walkers that lack a Tree-sitter node).
func fingerprintMatchedCode(matched, snippet string) string {
	if strings.TrimSpace(matched) != "" {
		return matched
	}
	return snippet
}

func normalizeFramework(framework string) string {
	if framework == "" {
		return "JavaScript"
	}
	return framework
}
