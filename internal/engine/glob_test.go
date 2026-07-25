package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchGlobBaseName(t *testing.T) {
	assert.True(t, matchGlob("*.js", "src/app.js"))
	assert.True(t, matchGlob("*.js", "app.js"))
	assert.False(t, matchGlob("*.js", "src/app.ts"))
	assert.False(t, matchGlob("*.js", "app.ts"))
}

func TestMatchGlobDoubleStarAnywhere(t *testing.T) {
	assert.True(t, matchGlob("src/**/*.js", "src/a/b.js"))
	assert.True(t, matchGlob("src/**/*.js", "src/a/b/c/d.js"))
	assert.True(t, matchGlob("tests/**", "tests/unit/x.js"))
	assert.True(t, matchGlob("tests/**", "tests/x.js"))
	assert.False(t, matchGlob("src/**/*.js", "lib/a/b.js"))
}

func TestMatchGlobDoubleStarEmpty(t *testing.T) {
	// ** should match zero path segments.
	assert.True(t, matchGlob("src/**/app.js", "src/app.js"))
	assert.True(t, matchGlob("src/**/app.js", "src/a/app.js"))
}

func TestMatchGlobExactSegment(t *testing.T) {
	assert.True(t, matchGlob("vendor/*.js", "vendor/lib.js"))
	assert.False(t, matchGlob("vendor/*.js", "src/vendor/lib.js"))
}

func TestMatchGlobEmptyPattern(t *testing.T) {
	assert.False(t, matchGlob("", "src/app.js"))
	assert.False(t, matchGlob("  ", "src/app.js"))
}

func TestMatchesAnyGlob(t *testing.T) {
	patterns := []string{"*.py", "tests/**"}
	assert.True(t, matchesAnyGlob(patterns, "script.py"))
	assert.True(t, matchesAnyGlob(patterns, "tests/unit/foo.js"))
	assert.False(t, matchesAnyGlob(patterns, "src/app.js"))
}
