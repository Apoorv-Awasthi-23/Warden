package rulestore

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func TestLoad_ValidPerServerFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "github.yaml", `
rules:
  - id: block-delete
    cel_expression: tool == "delete_file"
    action: hard_stop
`)
	writeFile(t, dir, "aws.yaml", `
rules:
  - id: require-approval-terminate
    cel_expression: tool == "terminate_instance"
    action: require_approval
`)

	store, failures, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	all := store.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(all))
	}

	var gotGithub, gotAWS bool
	for _, r := range all {
		switch r.ID {
		case "github__block-delete":
			gotGithub = true
			if r.ServerScope != "github" {
				t.Errorf("github rule scope = %q, want %q", r.ServerScope, "github")
			}
		case "aws__require-approval-terminate":
			gotAWS = true
			if r.ServerScope != "aws" {
				t.Errorf("aws rule scope = %q, want %q", r.ServerScope, "aws")
			}
		}
	}
	if !gotGithub || !gotAWS {
		t.Fatalf("missing expected qualified rule ids, got %+v", all)
	}
}

func TestLoad_GlobalFileGetsWildcardScope(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "_global.yaml", `
rules:
  - id: require-approval-anything-destructive
    cel_expression: tool.contains("delete")
    action: require_approval
`)

	store, failures, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	all := store.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(all))
	}
	if all[0].ID != "global__require-approval-anything-destructive" {
		t.Errorf("id = %q, want global__ prefix", all[0].ID)
	}
	if all[0].ServerScope != "*" {
		t.Errorf("ServerScope = %q, want \"*\"", all[0].ServerScope)
	}
}

func TestLoad_SameLocalIDAcrossServersIsFine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "github.yaml", `
rules:
  - id: block-delete
    cel_expression: tool == "delete_file"
    action: hard_stop
`)
	writeFile(t, dir, "aws.yaml", `
rules:
  - id: block-delete
    cel_expression: tool == "terminate_instance"
    action: hard_stop
`)

	store, failures, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	if len(store.All()) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(store.All()))
	}
}

func TestLoad_DuplicateLocalIDWithinFileFails(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "github.yaml", `
rules:
  - id: dup
    cel_expression: tool == "a"
    action: hard_stop
  - id: dup
    cel_expression: tool == "b"
    action: hard_stop
`)

	store, failures, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(store.All()) != 0 {
		t.Fatalf("expected 0 loaded rules on failure, got %d", len(store.All()))
	}
	if _, ok := failures["github"]; !ok {
		t.Fatalf("expected a load failure for server 'github', got %v", failures)
	}
}

func TestLoad_MissingDirectoryIsNotAnError(t *testing.T) {
	store, failures, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	if len(store.All()) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(store.All()))
	}
}

func TestLoad_BrokenFileIsolatedToItsServer(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "github.yaml", `
rules:
  - id: ok
    cel_expression: tool == "delete_file"
    action: hard_stop
`)
	writeFile(t, dir, "aws.yaml", `not: [valid: yaml`)

	store, failures, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := failures["aws"]; !ok {
		t.Fatalf("expected a load failure for 'aws', got %v", failures)
	}
	all := store.All()
	if len(all) != 1 || all[0].ID != "github__ok" {
		t.Fatalf("expected github's rule to still load despite aws.yaml being broken, got %+v", all)
	}
}

func TestForServer_IncludesWildcards(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "github.yaml", `
rules:
  - id: only-github
    cel_expression: "true"
    action: hard_stop
`)
	writeFile(t, dir, "_global.yaml", `
rules:
  - id: everywhere
    cel_expression: "true"
    action: hard_stop
`)

	store, _, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	forGithub := store.ForServer("github")
	if len(forGithub) != 2 {
		t.Fatalf("expected 2 rules for github (scoped + wildcard), got %d: %+v", len(forGithub), forGithub)
	}

	forAWS := store.ForServer("aws")
	if len(forAWS) != 1 {
		t.Fatalf("expected 1 rule for aws (wildcard only), got %d: %+v", len(forAWS), forAWS)
	}
}
