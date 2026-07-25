package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScannerExpectedSuppression ensures the `scanner-expected`
// directive suppresses findings on the same line, mirroring the
// behavior of `scanner-disable-line`.
func TestScannerExpectedSuppression(t *testing.T) {
	src := "eval(userInput); // scanner-expected JS-EVAL-EXEC\n"
	path := writeTemp(t, src)

	findings := scanFile(t, path, []Rule{evalRule})
	assert.Empty(t, findings, "scanner-expected should suppress the JS-EVAL-EXEC finding")
}

// TestScannerExpectedNextLineSuppression ensures the `next-line`
// variant suppresses the finding on the following line.
func TestScannerExpectedNextLineSuppression(t *testing.T) {
	src := "// scanner-expected-next-line JS-EVAL-EXEC\neval(userInput);\n"
	path := writeTemp(t, src)

	findings := scanFile(t, path, []Rule{evalRule})
	assert.Empty(t, findings, "scanner-expected-next-line should suppress the next-line finding")
}

// TestScannerExpectedWithoutIDIsWildcard ensures an ID-less directive
// suppresses any rule on that line, like the disable variant.
func TestScannerExpectedWithoutIDIsWildcard(t *testing.T) {
	src := "eval(userInput); // scanner-expected\n"
	path := writeTemp(t, src)
	findings := scanFile(t, path, []Rule{evalRule})
	assert.Empty(t, findings, "bare scanner-expected should act as a wildcard suppression")
}

// TestScannerDisableLineStillWorks regresses the original directive.
func TestScannerDisableLineStillWorks(t *testing.T) {
	src := "eval(userInput); // scanner-disable-line JS-EVAL-EXEC\n"
	path := writeTemp(t, src)
	findings := scanFile(t, path, []Rule{evalRule})
	assert.Empty(t, findings, "scanner-disable-line must still suppress findings after the refactor")
}

// TestChangedFilesScopesScan ensures the diff-mode set restricts the
// scan to listed files while preserving findings inside that set.
func TestChangedFilesScopesScan(t *testing.T) {
	dir := t.TempDir()
	kept := filepath.Join(dir, "kept.js")
	skipped := filepath.Join(dir, "skipped.js")
	require.NoError(t, os.WriteFile(kept, []byte("eval(a);\n"), 0o644))
	require.NoError(t, os.WriteFile(skipped, []byte("eval(b);\n"), 0o644))

	e := New([]Rule{evalRule})
	e.SetChangedFiles([]string{kept})

	findings := make(chan Finding, 16)
	go func() { _ = e.ScanDirectory(dir, findings) }()

	var got []Finding
	for f := range findings {
		got = append(got, f)
	}
	require.Len(t, got, 1, "only files in the changed set should be scanned")
	assert.Equal(t, kept, got[0].File)
}

// TestSetChangedFilesNilDisablesDiffMode ensures clearing the set
// restores full-scan behavior.
func TestSetChangedFilesNilDisablesDiffMode(t *testing.T) {
	e := New(nil)
	e.SetChangedFiles([]string{"some.js"})
	require.NotNil(t, e.ChangedFiles)
	e.SetChangedFiles(nil)
	assert.Nil(t, e.ChangedFiles)
}

// --- Semgrep nosemgrep suppression ---

// TestNosemgrepSameLineSuppressesRule verifies that a `# nosemgrep: RULE-ID`
// comment on the same line suppresses the named finding.
func TestNosemgrepSameLineSuppressesRule(t *testing.T) {
	src := "eval(userInput); // nosemgrep: JS-EVAL-EXEC\n"
	path := writeTemp(t, src)
	findings := scanFile(t, path, []Rule{evalRule})
	assert.Empty(t, findings, "nosemgrep: RULE-ID should suppress the finding on the same line")
}

// TestNosemgrepHashStyleSuppresses verifies the Python-style `# nosemgrep: ID`
// comment is honored.
func TestNosemgrepHashStyleSuppresses(t *testing.T) {
	src := "eval(userInput) # nosemgrep: JS-EVAL-EXEC\n"
	// The scanner parses JS files; the hash # will just be treated as code but
	// lineHasCommentBefore recognizes # as a comment opener.
	path := writeTemp(t, src)
	findings := scanFile(t, path, []Rule{evalRule})
	assert.Empty(t, findings, "# nosemgrep: RULE-ID should suppress the finding")
}

// TestNosemgrepWithColonAndSpaceSuppresses verifies `nosemgrep: ID` format.
func TestNosemgrepWithColonAndSpaceSuppresses(t *testing.T) {
	src := "eval(userInput); // nosemgrep: JS-EVAL-EXEC\n"
	path := writeTemp(t, src)
	findings := scanFile(t, path, []Rule{evalRule})
	assert.Empty(t, findings, "nosemgrep: format should suppress the finding")
}

// TestNosemgrepWithoutColonSuppresses verifies `nosemgrep RULE-ID` (no colon).
func TestNosemgrepWithoutColonSuppresses(t *testing.T) {
	src := "eval(userInput); // nosemgrep JS-EVAL-EXEC\n"
	path := writeTemp(t, src)
	findings := scanFile(t, path, []Rule{evalRule})
	assert.Empty(t, findings, "nosemgrep RULE-ID (no colon) should suppress the finding")
}

// TestNosemgrepWildcardSuppresses verifies bare `// nosemgrep` suppresses all rules.
func TestNosemgrepWildcardSuppresses(t *testing.T) {
	src := "eval(userInput); // nosemgrep\n"
	path := writeTemp(t, src)
	findings := scanFile(t, path, []Rule{evalRule})
	assert.Empty(t, findings, "bare nosemgrep should act as a wildcard suppressor")
}

// TestNosemgrepDifferentRuleDoesNotSuppress verifies that a nosemgrep comment
// for a different rule ID does not suppress the current rule.
func TestNosemgrepDifferentRuleDoesNotSuppress(t *testing.T) {
	src := "eval(userInput); // nosemgrep: SOME-OTHER-RULE\n"
	path := writeTemp(t, src)
	findings := scanFile(t, path, []Rule{evalRule})
	assert.Len(t, findings, 1, "nosemgrep for a different rule should not suppress this rule")
}

