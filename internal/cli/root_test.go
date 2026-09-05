// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootUsesCobraSubcommands(t *testing.T) {
	root := New("test-version")
	want := map[string]bool{
		"inspect":  true,
		"extract":  true,
		"kernel":   true,
		"firmware": true,
		"squashfs": true,
		"analyze":  true,
		"compare":  true,
		"verify":   true,
		"update":   true,
		"license":  true,
	}
	for _, command := range root.Commands() {
		if want[command.Name()] {
			delete(want, command.Name())
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing Cobra subcommands: %v", want)
	}

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"inspect", "extract", "kernel", "firmware", "compare", "verify", "update"} {
		if !strings.Contains(out.String(), text) {
			t.Errorf("help does not mention %q:\n%s", text, out.String())
		}
	}
}

func TestRootValidatesPersistentLimitsBeforeRunningSubcommand(t *testing.T) {
	root := New("test-version")
	root.SetArgs([]string{"--max-bytes", "0", "inspect", "missing.npk"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "--max-bytes") {
		t.Fatalf("invalid max-bytes error = %v", err)
	}
}
