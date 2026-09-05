// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsoleFileDiscovery(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"1073741824.mem", "1077936128.mem", "1073741824 2.mem", "unrelated.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, skipped, err := consoleFiles([]string{root, filepath.Join(root, "1073741824.mem")})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || len(skipped) != 1 || files[0].base != 0x40000000 {
		t.Fatalf("files=%+v skipped=%v", files, skipped)
	}
	if err := os.WriteFile(filepath.Join(root, "01073741824.mem"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := consoleFiles([]string{root}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate base: %v", err)
	}
}

func TestConsoleDiscoveryDoesNotFollowDirectorySymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "1073741824.mem"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "1077936128.mem"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("host cannot create symlinks: %v", err)
	}
	files, _, err := consoleFiles([]string{root})
	if err != nil || len(files) != 1 {
		t.Fatalf("followed link: %+v, %v", files, err)
	}
}

func TestAnalyzeUnsupportedConsoleKeepsOriginal(t *testing.T) {
	for _, withParser := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing parser", true: "unsupported parser"}[withParser], func(t *testing.T) {
			data := []byte("unrecognized console data")
			files := map[string][]byte{"nova/lib/console/1073741824.mem": data}
			if withParser {
				files["nova/bin/parser"] = []byte("unknown parser")
			}
			var records []byte
			for name, content := range files {
				records = append(records, testFileRecord(name, content, [4]byte{})...)
			}
			source := filepath.Join(t.TempDir(), "source.npk")
			if err := os.WriteFile(source, testNPK(testNPKSection{kind: 4, body: testZlib(records)}), 0600); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "extracted")
			if _, err := Extract(source, dir, Options{NoDerived: true}); err != nil {
				t.Fatal(err)
			}
			summary, err := Analyze(dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if summary.ConsoleFiles != 0 || summary.ConsoleNodes != 0 {
				t.Fatalf("wrong decoded count: %+v", summary)
			}
			if !strings.Contains(strings.Join(summary.Notes, "\n"), "Console files/nova/lib/console/1073741824.mem:") {
				t.Fatalf("missing diagnostic: %v", summary.Notes)
			}
			got, err := os.ReadFile(filepath.Join(dir, "files/nova/lib/console/1073741824.mem"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("source changed")
			}
			if _, err := os.Stat(filepath.Join(dir, "derived/console/manifest.json")); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(dir, ""); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConsoleFailureDoesNotCreateOutput(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "1073741824.mem")
	parser := filepath.Join(dir, "parser")
	out := filepath.Join(dir, "out")
	for _, name := range []string{source, parser} {
		if err := os.WriteFile(name, []byte("unrecognized"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Console([]string{source}, parser, out, Options{}); err == nil {
		t.Fatal("accepted unsupported parser")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("created output before input validation: %v", err)
	}
	if _, err := Console([]string{source}, parser, out, Options{MaxBytes: 1}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("ignored byte limit: %v", err)
	}
}
