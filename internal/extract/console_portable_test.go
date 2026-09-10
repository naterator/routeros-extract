// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/naterator/routeros-extract/internal/testutil"
)

func TestConsoleAutomaticAndAddonAnalysis(t *testing.T) {
	for _, parserName := range []string{"nova/bin/parser", "nova/bin/console", "external"} {
		t.Run(parserName, func(t *testing.T) {
			image, parser := testutil.ConsoleFixture(t, elf.EM_MIPS, binary.BigEndian)
			records := testFileRecord("nova/lib/console/1073741824.mem", image, [4]byte{})
			opt := Options{NoDerived: true}
			if parserName == "external" {
				opt.ConsoleParser = filepath.Join(t.TempDir(), "parser")
				if err := os.WriteFile(opt.ConsoleParser, parser, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				records = append(records, testFileRecord(parserName, parser, [4]byte{})...)
			}
			dir := t.TempDir()
			source := filepath.Join(dir, "addon.npk")
			out := filepath.Join(dir, "extracted")
			if err := os.WriteFile(source, testNPK(testNPKSection{kind: 4, body: testZlib(records)}), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Extract(source, out, opt); err != nil {
				t.Fatal(err)
			}
			got, err := Analyze(out, opt)
			if err != nil {
				t.Fatal(err)
			}
			if got.ConsoleFiles != 1 || got.ConsoleNodes != 5 {
				t.Fatalf("console skipped: %+v", got)
			}
			raw, err := os.ReadFile(filepath.Join(out, "derived/console/manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest []consoleAnalysis
			if err = json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			if len(manifest) != 1 || !manifest[0].Decoded || manifest[0].Metadata.ByteOrder != "big" {
				t.Fatalf("bad console manifest: %s", raw)
			}
			if _, err = Verify(out, source); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConsoleCollectionChecksCompatibility(t *testing.T) {
	image, parser := testutil.ConsoleFixture(t, elf.EM_ARM, binary.LittleEndian)
	dir := t.TempDir()
	a := filepath.Join(dir, "1073741824.mem")
	b := filepath.Join(dir, "1077936128.mem")
	p := filepath.Join(dir, "parser")
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(a, image, 0600); err != nil {
		t.Fatal(err)
	}
	// Relocate every image pointer, then change only the compatibility word.
	for offset := 0; offset+4 <= len(image); offset += 4 {
		v := binary.LittleEndian.Uint32(image[offset:])
		if v >= 0x40000000 && v < 0x40001000 {
			binary.LittleEndian.PutUint32(image[offset:], v+0x400000)
		}
	}
	binary.LittleEndian.PutUint32(image, 123)
	if err := os.WriteFile(b, image, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, parser, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Console([]string{a, b}, p, out, Options{}); err == nil || !strings.Contains(err.Error(), "compatibility") {
		t.Fatalf("mixed builds: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("output created before collection validation: %v", err)
	}
}
