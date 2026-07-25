package engine

import (
	"path/filepath"
	"strings"
)

// matchGlob returns true when path matches the glob pattern.
// It extends filepath.Match to support the "**" double-star wildcard,
// which matches zero or more path components (including separators).
//
// Matching is performed against the slash-normalized form of path.
// A pattern without any "/" is matched against the file's base name
// only (e.g. "*.js" matches any .js file regardless of directory).
//
// Examples:
//
//	matchGlob("*.js", "src/app.js")         → true   (base-name match)
//	matchGlob("src/**/*.js", "src/a/b.js")  → true
//	matchGlob("tests/**", "tests/unit/x.js")→ true
//	matchGlob("vendor", "vendor/lib/a.js")  → false  (exact segment)
func matchGlob(pattern, path string) bool {
	pattern = filepath.ToSlash(strings.TrimSpace(pattern))
	path = filepath.ToSlash(strings.TrimSpace(path))

	if pattern == "" {
		return false
	}

	// A pattern with no path separator is matched against the base name only.
	if !strings.Contains(pattern, "/") {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		return err == nil && matched
	}

	// Split both into segments for recursive matching.
	patParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")
	return matchGlobSegments(patParts, pathParts)
}

// matchGlobSegments recursively matches pattern segments against path segments.
func matchGlobSegments(pat, path []string) bool {
	for {
		if len(pat) == 0 {
			return len(path) == 0
		}
		if len(path) == 0 {
			// Allow trailing ** to match empty suffix.
			for _, p := range pat {
				if p != "**" {
					return false
				}
			}
			return true
		}

		seg := pat[0]
		if seg == "**" {
			// ** consumes zero or more path segments.
			rest := pat[1:]
			for i := 0; i <= len(path); i++ {
				if matchGlobSegments(rest, path[i:]) {
					return true
				}
			}
			return false
		}

		matched, err := filepath.Match(seg, path[0])
		if err != nil || !matched {
			return false
		}
		pat = pat[1:]
		path = path[1:]
	}
}

// matchesAnyGlob returns true when path matches at least one of the patterns.
func matchesAnyGlob(patterns []string, path string) bool {
	for _, p := range patterns {
		if matchGlob(p, path) {
			return true
		}
	}
	return false
}
