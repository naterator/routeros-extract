// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/naterator/routeros-extract/internal/extract"
	"github.com/spf13/cobra"
)

func TestHelpFits72Columns(t *testing.T) {
	// Discover Cobra's generated commands as well as the application's.
	root := New("test-version")
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	routes := [][]string{{}, {"help"}}
	var walk func(*cobra.Command, []string)
	walk = func(cmd *cobra.Command, path []string) {
		routes = append(routes, append(slices.Clone(path), "--help"))
		if len(path) > 0 {
			routes = append(routes, append([]string{"help"}, path...))
			if cmd.HasAvailableSubCommands() {
				routes = append(routes, path)
			}
		}
		for _, child := range cmd.Commands() {
			if child.IsAvailableCommand() || child.Name() == "help" {
				walk(child, append(slices.Clone(path), child.Name()))
			}
		}
	}
	walk(root, nil)
	for _, defaultNoSymlinks := range []string{"false", "true"} {
		t.Run("no-symlinks="+defaultNoSymlinks, func(t *testing.T) {
			for _, args := range routes {
				t.Run(strings.Join(append([]string{"routeros-extract"}, args...), " "), func(t *testing.T) {
					cmd := New("test-version")
					// Windows displays a different default for this flag.
					cmd.PersistentFlags().Lookup("no-symlinks").DefValue = defaultNoSymlinks
					var out bytes.Buffer
					cmd.SetOut(&out)
					cmd.SetErr(&out)
					cmd.SetArgs(args)
					if err := cmd.Execute(); err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(out.String(), "Usage:") {
						t.Fatalf("missing help output: %q", out.String())
					}
					for i, line := range strings.Split(out.String(), "\n") {
						if width := utf8.RuneCountInString(line); width > 72 {
							t.Errorf("line %d is %d columns: %s", i+1, width, line)
						}
					}
				})
			}
		})
	}
}

func TestRootHelpGroupsAndDefaults(t *testing.T) {
	root := New("test-version")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, group := range []struct {
		heading  string
		commands []string
	}{
		{"RouterOS commands:", []string{"analyze", "compare", "extract", "firmware", "inspect", "kernel", "squashfs", "verify"}},
		{"Utility commands:", []string{"completion", "help", "license", "update"}},
	} {
		_, section, ok := strings.Cut(out.String(), group.heading+"\n")
		if !ok {
			t.Fatalf("missing %q", group.heading)
		}
		section, _, _ = strings.Cut(section, "\n\n")
		var names []string
		for _, line := range strings.Split(section, "\n") {
			if fields := strings.Fields(line); len(fields) > 0 {
				names = append(names, fields[0])
			}
		}
		if !slices.Equal(names, group.commands) {
			t.Errorf("%s got %v, want %v", group.heading, names, group.commands)
		}
	}
	if !strings.Contains(out.String(), "(default 512 MiB)") {
		t.Fatal("help should show a readable byte limit")
	}
	if value, err := root.PersistentFlags().GetInt64("max-bytes"); err != nil || value != extract.DefaultMaxBytes {
		t.Fatalf("help changed the byte limit: %d, %v", value, err)
	}
}

func TestCompletionStillWritesScripts(t *testing.T) {
	for _, shell := range []struct {
		name   string
		marker string
	}{
		{"bash", "# bash completion V2 for routeros-extract"},
		{"zsh", "#compdef routeros-extract"},
		{"fish", "# fish completion for routeros-extract"},
		{"powershell", "Register-ArgumentCompleter -CommandName 'routeros-extract'"},
	} {
		t.Run(shell.name, func(t *testing.T) {
			root := New("test-version")
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetArgs([]string{"completion", shell.name})
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), shell.marker) {
				t.Fatalf("expected a completion script on the configured output: %q", out.String())
			}
		})
	}
}

func TestIncompleteCommandsShowHelp(t *testing.T) {
	var cases [][]string
	for _, name := range []string{"analyze", "compare", "extract", "firmware", "inspect", "kernel", "squashfs", "verify"} {
		cases = append(cases, []string{name})
	}
	cases = append(cases,
		[]string{"compare", "before"},
		[]string{"compare", "before", "after"},
		[]string{"firmware", "image.fwf"},
		[]string{"kernel", "image.bin"},
		[]string{"squashfs", "image.squashfs"},
		[]string{"extract", "package.npk", "--out"},
	)
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := New("test-version")
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(args)
			if err := root.Execute(); err == nil {
				t.Fatal("incomplete command should return an error")
			}
			if strings.Count(out.String(), "Usage:") != 1 || !strings.Contains(out.String(), "Usage:\n  routeros-extract "+args[0]+" ") {
				t.Fatalf("expected help for %s exactly once:\n%s", args[0], out.String())
			}
		})
	}
}

func TestRuntimeErrorsDoNotShowHelp(t *testing.T) {
	root := New("test-version")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"inspect", filepath.Join(t.TempDir(), "missing.npk")})
	if err := root.Execute(); err == nil {
		t.Fatal("missing input should return an error")
	}
	if strings.Contains(out.String(), "Usage:") {
		t.Fatalf("runtime error should not print help:\n%s", out.String())
	}
}
