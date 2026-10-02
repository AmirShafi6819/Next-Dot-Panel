package sshprovider

import (
	"testing"

	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"":                "''",
		"abc":             "abc",
		"a-b_c.d/e:f,g":   "a-b_c.d/e:f,g",
		"hello world":     "'hello world'",
		"it's":            `'it'\''s'`,
		"$(rm -rf /)":     "'$(rm -rf /)'",
		"`id`":            "'`id`'",
		"a;b":             "'a;b'",
		"line1\nline2":    "'line1\nline2'",
		"--flag=value":    "--flag=value",
		"foo*bar":         "'foo*bar'",
		"quote'and\"dq\"": `'quote'\''and"dq"'`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildCommand(t *testing.T) {
	got := buildCommand(provider.Command{Path: "echo", Args: []string{"hello world", "$HOME"}})
	want := "echo 'hello world' '$HOME'"
	if got != want {
		t.Fatalf("buildCommand = %q, want %q", got, want)
	}
}
