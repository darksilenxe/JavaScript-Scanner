// Package triage implements an opt-in, whole-codebase reachability review
// that runs after the rule engine has produced findings. Where the rule
// engine and its taint tracker (internal/engine/taint.go) only reason
// about a single file at a time, this package builds a lightweight,
// project-wide model of function declarations, HTTP/CLI entry points, and
// name-based call edges, then uses it to judge whether the code
// surrounding a finding is actually reachable from a real entry point.
//
// The review is intentionally conservative and additive: it never drops
// or reorders findings, and it only annotates engine.Finding with the
// TriageVerdict/TriageRationale fields. Callers opt in explicitly (see
// the -enable-holistic-review flag in cmd/scanner/main.go); all existing
// output schemas are unchanged when the feature is disabled.
package triage

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"javascript-security-scanner/internal/engine"
)

// Verdict values reported on engine.Finding.TriageVerdict.
const (
	// VerdictReachable means a call path was found from a detected entry
	// point (or the code runs at module/package load time) to the
	// function enclosing the finding.
	VerdictReachable = "REACHABLE"
	// VerdictLikelyUnreachable means entry points were found elsewhere in
	// the project, but no call path reaches the function enclosing the
	// finding. Findings are never dropped based on this verdict; it is
	// informational so a human (or the optional LLM triage stage) can
	// prioritize review.
	VerdictLikelyUnreachable = "LIKELY_UNREACHABLE"
	// VerdictUnknown means the review could not establish enough of the
	// project's entry points or call graph to make a determination (for
	// example, an unsupported language, or a project with no detected
	// entry points at all).
	VerdictUnknown = "UNKNOWN"
)

// Options controls how Build walks the target directory. Fields mirror
// the engine's own scan-scope flags so callers can reuse the same CLI
// inputs across both pipelines.
type Options struct {
	// IncludeTests, when true, includes test/spec files in the model.
	IncludeTests bool
	// IncludeVendored, when true, includes vendored/build-output files.
	IncludeVendored bool
	// MaxFileBytes caps the size of files considered. Zero uses the
	// default cap (5 MiB).
	MaxFileBytes int64
}

const defaultMaxFileBytes = 5 * 1024 * 1024

// function describes one parsed function/method declaration.
type function struct {
	name      string
	file      string
	startLine int // 1-based, inclusive
	endLine   int // 1-based, inclusive
	isEntry   bool
}

// Project is the whole-codebase model built by Build. It is built once
// per scan run and reused across all findings.
type Project struct {
	functions []function
	// byFile maps a file path to indexes into functions, sorted by
	// startLine, for enclosing-function lookups.
	byFile map[string][]int
	// callers maps a caller function name to the set of callee names
	// referenced anywhere in its body. Matching is name-based (not fully
	// qualified) to stay resilient to the simplified, regex-based
	// parsing used here instead of a full per-language AST call graph.
	callers map[string]map[string]struct{}
	// reachable is the set of function names reachable from any entry
	// point, computed once by Build.
	reachable map[string]struct{}
	// hasEntryPoints records whether any entry point was detected
	// anywhere in the project.
	hasEntryPoints bool
	// modelledFiles records every file this package parsed (JS/TS, Go,
	// Python), regardless of whether it contained any functions, so
	// top-level-only files are still distinguished from files in
	// unmodelled languages.
	modelledFiles map[string]struct{}
}

var (
	jsFuncDeclRe  = regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s+([A-Za-z_$][\w$]*)\s*\(`)
	jsConstFuncRe = regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*(?::[^=]*)?=>\s*\{`)
	jsRouteRe     = regexp.MustCompile(`\b(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|all|use)\s*\(\s*['"\x60][^'"\x60]*['"\x60]\s*,\s*([A-Za-z_$][\w$]*)\s*\)`)

	goFuncDeclRe = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(`)
	goRouteRe    = regexp.MustCompile(`\.(?:HandleFunc|Handle)\s*\(\s*"[^"]*"\s*,\s*([A-Za-z_][\w.]*)\s*\)`)

	pyFuncDeclRe  = regexp.MustCompile(`^(\s*)def\s+([A-Za-z_]\w*)\s*\(`)
	pyRouteDecoRe = regexp.MustCompile(`^\s*@[\w.]*\.(?:route|get|post|put|delete|patch)\s*\(`)
	pyMainGuardRe = regexp.MustCompile(`^\s*if\s+__name__\s*==\s*['"]__main__['"]\s*:`)

	callExprRe = regexp.MustCompile(`\b([A-Za-z_][\w.]*)\s*\(`)
)

// Build walks targetDir, parses function declarations and best-effort
// entry points for JavaScript/TypeScript, Python, and Go source, builds a
// name-based call graph, and computes reachability from every detected
// entry point. Files in other supported languages are still scanned for
// findings by the rule engine, but are not modelled here; findings in
// those files receive VerdictUnknown.
func Build(targetDir string, opts Options) (*Project, error) {
	maxBytes := opts.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxFileBytes
	}

	p := &Project{byFile: map[string][]int{}, callers: map[string]map[string]struct{}{}, modelledFiles: map[string]struct{}{}}

	walkErr := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if !opts.IncludeVendored && engine.IsVendoredPath(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !engine.IsSupportedSourcePath(path) {
			return nil
		}
		if !opts.IncludeVendored && engine.IsVendoredPath(path) {
			return nil
		}
		if !opts.IncludeTests && engine.IsTestPath(path) {
			return nil
		}
		info, statErr := d.Info()
		if statErr == nil && info.Size() > maxBytes {
			return nil
		}

		abs, absErr := filepath.Abs(path)
		if absErr != nil {
			abs = path
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		p.parseFile(abs, data)
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("triage: failed to walk %s: %w", targetDir, walkErr)
	}

	p.sortByFile()
	p.computeReachability()
	return p, nil
}

// parseFile dispatches to a language-specific parser based on extension.
func (p *Project) parseFile(path string, data []byte) {
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		p.modelledFiles[path] = struct{}{}
		p.parseCurlyBraceFile(path, data, jsDeclName, jsRouteRe)
	case ".go":
		p.modelledFiles[path] = struct{}{}
		p.parseCurlyBraceFile(path, data, goDeclName, goRouteRe)
	case ".py":
		p.modelledFiles[path] = struct{}{}
		p.parsePythonFile(path, data)
	}
}

// jsDeclName returns the declared function name for a line, if any.
func jsDeclName(line string) (string, bool) {
	if m := jsFuncDeclRe.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	if m := jsConstFuncRe.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", false
}

// goDeclName returns the declared function/method name for a line, if any.
func goDeclName(line string) (string, bool) {
	if m := goFuncDeclRe.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", false
}

// parseCurlyBraceFile handles brace-delimited languages (JS/TS, Go). It
// tracks brace depth to find each function's closing line, and records
// route-registration entry points (e.g. app.get('/x', handlerName)).
func (p *Project) parseCurlyBraceFile(path string, data []byte, declName func(string) (string, bool), routeRe *regexp.Regexp) {
	lines := strings.Split(string(data), "\n")

	type openFunc struct {
		name  string
		depth int
		start int
	}
	var stack []openFunc
	depth := 0
	entryNames := map[string]struct{}{}

	for i, line := range lines {
		lineNo := i + 1

		if routeRe != nil {
			if m := routeRe.FindStringSubmatch(line); m != nil {
				name := m[1]
				if idx := strings.LastIndex(name, "."); idx >= 0 {
					name = name[idx+1:]
				}
				entryNames[name] = struct{}{}
			}
		}

		if name, ok := declName(line); ok {
			stack = append(stack, openFunc{name: name, depth: depth, start: lineNo})
		}

		// Record call edges for whichever function body we're currently
		// inside (innermost enclosing function on the stack).
		if len(stack) > 0 {
			caller := stack[len(stack)-1].name
			for _, m := range callExprRe.FindAllStringSubmatch(line, -1) {
				callee := m[1]
				if callee == caller {
					continue
				}
				if p.callers[caller] == nil {
					p.callers[caller] = map[string]struct{}{}
				}
				p.callers[caller][callee] = struct{}{}
			}
		}

		depth += strings.Count(line, "{") - strings.Count(line, "}")

		// Close any function frames whose opening depth we've returned to.
		for len(stack) > 0 && depth <= stack[len(stack)-1].depth {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			p.functions = append(p.functions, function{
				name:      top.name,
				file:      path,
				startLine: top.start,
				endLine:   lineNo,
			})
		}
	}
	// Close any still-open frames at EOF (malformed/truncated files).
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		p.functions = append(p.functions, function{name: top.name, file: path, startLine: top.start, endLine: len(lines)})
	}

	if filepath.Base(path) == "main.go" {
		entryNames["main"] = struct{}{}
	}
	p.markEntries(path, entryNames)
}

// parsePythonFile handles Python's indentation-delimited functions. It
// tracks the indentation of each `def` line to find where the function
// body ends, and records route-decorated functions plus calls made
// inside an `if __name__ == "__main__":` guard as entry points.
func (p *Project) parsePythonFile(path string, data []byte) {
	lines := strings.Split(string(data), "\n")

	type openFunc struct {
		name   string
		indent int
		start  int
	}
	var stack []openFunc
	entryNames := map[string]struct{}{}
	pendingRouteDecorator := false
	mainGuardIndent := -1

	indentOf := func(line string) int {
		return len(line) - len(strings.TrimLeft(line, " \t"))
	}

	for i, line := range lines {
		lineNo := i + 1
		trimmed := strings.TrimRight(line, "\r")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		indent := indentOf(trimmed)

		// Close any function frames we've dedented past.
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			p.functions = append(p.functions, function{name: top.name, file: path, startLine: top.start, endLine: lineNo - 1})
		}
		if mainGuardIndent >= 0 && indent <= mainGuardIndent {
			mainGuardIndent = -1
		}

		if pyRouteDecoRe.MatchString(trimmed) {
			pendingRouteDecorator = true
			continue
		}
		if pyMainGuardRe.MatchString(trimmed) {
			mainGuardIndent = indent
		}

		if m := pyFuncDeclRe.FindStringSubmatch(trimmed); m != nil {
			name := m[2]
			if pendingRouteDecorator {
				entryNames[name] = struct{}{}
			}
			stack = append(stack, openFunc{name: name, indent: indent, start: lineNo})
			pendingRouteDecorator = false
			continue
		}
		pendingRouteDecorator = false

		if len(stack) > 0 {
			caller := stack[len(stack)-1].name
			for _, m := range callExprRe.FindAllStringSubmatch(trimmed, -1) {
				callee := m[1]
				if callee == caller {
					continue
				}
				if p.callers[caller] == nil {
					p.callers[caller] = map[string]struct{}{}
				}
				p.callers[caller][callee] = struct{}{}
			}
		} else if mainGuardIndent >= 0 {
			// Calls made directly under `if __name__ == "__main__":` are
			// themselves entry points into whatever they invoke.
			for _, m := range callExprRe.FindAllStringSubmatch(trimmed, -1) {
				entryNames[m[1]] = struct{}{}
			}
		}
	}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		p.functions = append(p.functions, function{name: top.name, file: path, startLine: top.start, endLine: len(lines)})
	}

	p.markEntries(path, entryNames)
}

// markEntries flags the parsed functions in path whose name is in
// entryNames as entry points.
func (p *Project) markEntries(path string, entryNames map[string]struct{}) {
	if len(entryNames) == 0 {
		return
	}
	for i := range p.functions {
		if p.functions[i].file != path {
			continue
		}
		if _, ok := entryNames[p.functions[i].name]; ok {
			p.functions[i].isEntry = true
			p.hasEntryPoints = true
		}
	}
}

func (p *Project) sortByFile() {
	for i, fn := range p.functions {
		p.byFile[fn.file] = append(p.byFile[fn.file], i)
	}
	for file := range p.byFile {
		idxs := p.byFile[file]
		sort.Slice(idxs, func(a, b int) bool { return p.functions[idxs[a]].startLine < p.functions[idxs[b]].startLine })
		p.byFile[file] = idxs
	}
}

// computeReachability runs a BFS over the name-based call graph starting
// from every function flagged as an entry point.
func (p *Project) computeReachability() {
	p.reachable = map[string]struct{}{}
	var queue []string
	for _, fn := range p.functions {
		if fn.isEntry {
			if _, seen := p.reachable[fn.name]; !seen {
				p.reachable[fn.name] = struct{}{}
				queue = append(queue, fn.name)
			}
		}
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		for callee := range p.callers[name] {
			// Match qualified calls (e.g. pkg.Handler) by their trailing
			// identifier so cross-file, package-qualified calls resolve.
			short := callee
			if idx := strings.LastIndex(callee, "."); idx >= 0 {
				short = callee[idx+1:]
			}
			for _, candidate := range []string{callee, short} {
				if _, seen := p.reachable[candidate]; seen {
					continue
				}
				if !p.functionExists(candidate) {
					continue
				}
				p.reachable[candidate] = struct{}{}
				queue = append(queue, candidate)
			}
		}
	}
}

func (p *Project) functionExists(name string) bool {
	for _, fn := range p.functions {
		if fn.name == name {
			return true
		}
	}
	return false
}

// enclosingFunction returns the innermost parsed function in file that
// contains the given 1-based line, if any.
func (p *Project) enclosingFunction(file string, line uint32) (function, bool) {
	idxs, ok := p.byFile[file]
	if !ok {
		return function{}, false
	}
	var best function
	found := false
	for _, idx := range idxs {
		fn := p.functions[idx]
		if int(line) < fn.startLine || int(line) > fn.endLine {
			continue
		}
		// Prefer the smallest (innermost) enclosing range.
		if !found || (fn.endLine-fn.startLine) < (best.endLine-best.startLine) {
			best = fn
			found = true
		}
	}
	return best, found
}

// Review annotates each finding in place with a best-effort
// TriageVerdict and TriageRationale based on the whole-codebase model.
// It never removes, reorders, or otherwise changes any other field on a
// finding.
func (p *Project) Review(findings []engine.Finding) {
	for i := range findings {
		p.reviewOne(&findings[i])
	}
}

func (p *Project) reviewOne(f *engine.Finding) {
	if f.File == "" {
		return
	}
	abs, err := filepath.Abs(f.File)
	if err != nil {
		abs = f.File
	}
	fn, ok := p.enclosingFunction(abs, f.Line)
	if !ok {
		// No parsed enclosing function: either the finding sits at
		// module/package top level (which runs on load/import/require),
		// or the file's language isn't modelled here.
		if _, modelled := p.modelledFiles[abs]; modelled {
			f.TriageVerdict = VerdictReachable
			f.TriageRationale = "Finding is at module/top-level scope, which executes on load."
		} else {
			f.TriageVerdict = VerdictUnknown
			f.TriageRationale = "Whole-codebase review does not model this file's language; reachability could not be determined."
		}
		return
	}

	if _, reach := p.reachable[fn.name]; reach {
		f.TriageVerdict = VerdictReachable
		f.TriageRationale = fmt.Sprintf("A call path was found from a detected entry point to enclosing function %q.", fn.name)
		return
	}

	if !p.hasEntryPoints {
		f.TriageVerdict = VerdictUnknown
		f.TriageRationale = "No entry points (HTTP routes, main, __main__) were detected anywhere in the project, so reachability could not be established."
		return
	}

	f.TriageVerdict = VerdictLikelyUnreachable
	f.TriageRationale = fmt.Sprintf("No call path was found from any detected entry point to enclosing function %q; this finding may be dead or test-only code, but is not suppressed.", fn.name)
}
