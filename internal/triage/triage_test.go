package triage

import (
	"os"
	"path/filepath"
	"testing"

	"javascript-security-scanner/internal/engine"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func TestReview_JSRouteReachable(t *testing.T) {
	dir := t.TempDir()
	src := "" +
		"const express = require('express');\n" +
		"const app = express();\n" +
		"\n" +
		"function handler(req, res) {\n" +
		"  doWork(req);\n" +
		"}\n" +
		"\n" +
		"function doWork(req) {\n" +
		"  const q = req.query.q;\n" + // vulnerable line
		"  db.exec(q);\n" +
		"}\n" +
		"\n" +
		"app.get('/x', handler);\n"
	path := writeFile(t, dir, "server.js", src)

	project, err := Build(dir, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	findings := []engine.Finding{{File: path, Line: 9}}
	project.Review(findings)

	if got := findings[0].TriageVerdict; got != VerdictReachable {
		t.Fatalf("expected %s, got %s (%s)", VerdictReachable, got, findings[0].TriageRationale)
	}
}

func TestReview_LikelyUnreachableWhenNoCallPath(t *testing.T) {
	dir := t.TempDir()
	src := "" +
		"const express = require('express');\n" +
		"const app = express();\n" +
		"\n" +
		"function handler(req, res) {\n" +
		"  res.send('ok');\n" +
		"}\n" +
		"\n" +
		"function deadCode(req) {\n" +
		"  const q = req.query.q;\n" + // vulnerable line but never called
		"  db.exec(q);\n" +
		"}\n" +
		"\n" +
		"app.get('/x', handler);\n"
	path := writeFile(t, dir, "server.js", src)

	project, err := Build(dir, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	findings := []engine.Finding{{File: path, Line: 9}}
	project.Review(findings)

	if got := findings[0].TriageVerdict; got != VerdictLikelyUnreachable {
		t.Fatalf("expected %s, got %s (%s)", VerdictLikelyUnreachable, got, findings[0].TriageRationale)
	}
	// Findings must never be dropped by the review.
	if len(findings) != 1 {
		t.Fatalf("expected finding to remain present, got %d findings", len(findings))
	}
}

func TestReview_UnknownWhenNoEntryPointsDetected(t *testing.T) {
	dir := t.TempDir()
	src := "" +
		"function helper(req) {\n" +
		"  const q = req.query.q;\n" +
		"  db.exec(q);\n" +
		"}\n"
	path := writeFile(t, dir, "lib.js", src)

	project, err := Build(dir, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	findings := []engine.Finding{{File: path, Line: 2}}
	project.Review(findings)

	if got := findings[0].TriageVerdict; got != VerdictUnknown {
		t.Fatalf("expected %s, got %s (%s)", VerdictUnknown, got, findings[0].TriageRationale)
	}
}

func TestReview_TopLevelCodeIsReachable(t *testing.T) {
	dir := t.TempDir()
	src := "" +
		"const q = req.query.q;\n" +
		"db.exec(q);\n"
	path := writeFile(t, dir, "index.js", src)

	project, err := Build(dir, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	findings := []engine.Finding{{File: path, Line: 2}}
	project.Review(findings)

	if got := findings[0].TriageVerdict; got != VerdictReachable {
		t.Fatalf("expected %s, got %s (%s)", VerdictReachable, got, findings[0].TriageRationale)
	}
}

func TestReview_PythonRouteReachable(t *testing.T) {
	dir := t.TempDir()
	src := "" +
		"from flask import Flask, request\n" +
		"app = Flask(__name__)\n" +
		"\n" +
		"@app.route('/x')\n" +
		"def handler():\n" +
		"    q = request.args.get('q')\n" +
		"    run(q)\n" +
		"\n" +
		"def run(q):\n" +
		"    db.execute(q)\n" // vulnerable line 10
	path := writeFile(t, dir, "app.py", src)

	project, err := Build(dir, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	findings := []engine.Finding{{File: path, Line: 10}}
	project.Review(findings)

	if got := findings[0].TriageVerdict; got != VerdictReachable {
		t.Fatalf("expected %s, got %s (%s)", VerdictReachable, got, findings[0].TriageRationale)
	}
}

func TestReview_GoMainReachable(t *testing.T) {
	dir := t.TempDir()
	src := "" +
		"package main\n" +
		"\n" +
		"func main() {\n" +
		"    doWork()\n" +
		"}\n" +
		"\n" +
		"func doWork() {\n" +
		"    q := os.Getenv(\"Q\")\n" + // vulnerable line 8
		"    exec.Command(q)\n" +
		"}\n"
	path := writeFile(t, dir, "main.go", src)

	project, err := Build(dir, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	findings := []engine.Finding{{File: path, Line: 8}}
	project.Review(findings)

	if got := findings[0].TriageVerdict; got != VerdictReachable {
		t.Fatalf("expected %s, got %s (%s)", VerdictReachable, got, findings[0].TriageRationale)
	}
}

func TestReview_EmptyFileNeverPanics(t *testing.T) {
	dir := t.TempDir()
	project, err := Build(dir, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	findings := []engine.Finding{{File: filepath.Join(dir, "missing.js"), Line: 1}}
	project.Review(findings)
	if findings[0].TriageVerdict != VerdictUnknown {
		t.Fatalf("expected %s for unmodelled file, got %s", VerdictUnknown, findings[0].TriageVerdict)
	}
}
