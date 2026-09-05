// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"path"
	"strings"
	"testing"
	"unicode/utf8"
)

func assertPortableComponent(t *testing.T, name string) {
	t.Helper()
	if !utf8.ValidString(name) {
		t.Fatalf("portable component is not valid UTF-8: %q", name)
	}
	if len(name) > portableComponentMax {
		t.Fatalf("portable component is too long (%d bytes): %q", len(name), name)
	}
	if strings.TrimRight(name, " .") != name {
		t.Fatalf("portable component has a trailing dot or space: %q", name)
	}
	if windowsReservedComponent(name) {
		t.Fatalf("portable component is a Windows device name: %q", name)
	}
	for _, r := range name {
		if r > 0x7f || r < 0x20 || r == 0x7f || strings.ContainsRune(`<>:"/\\|?*`, r) {
			t.Fatalf("portable component contains a host-forbidden character %q: %q", r, name)
		}
	}
}

func TestPortableComponentAliasesHostUnsafeNames(t *testing.T) {
	long := strings.Repeat("x", 300)
	for _, test := range []struct {
		name  string
		alias bool
	}{
		{name: "ordinary.txt"},
		{name: strings.Repeat("a", portableComponentMax)},
		{name: strings.Repeat("a", portableComponentMax+1), alias: true},
		{name: long, alias: true},
		{name: "CON", alias: true},
		{name: "nul.txt", alias: true},
		{name: "COM1.log", alias: true},
		{name: "LPT9", alias: true},
		{name: "clock$.txt", alias: true},
		{name: "CONIN$", alias: true},
		{name: "CONOUT$.log", alias: true},
		{name: "bad<name>", alias: true},
		{name: "trailing.", alias: true},
		{name: "trailing ", alias: true},
		{name: "control\x01name", alias: true},
		{name: "café.txt", alias: true},
		{name: "cafe\u0301.txt", alias: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := portableComponent(test.name)
			assertPortableComponent(t, got)
			if (got != test.name) != test.alias {
				t.Fatalf("portableComponent(%q) = %q, alias=%v", test.name, got, test.alias)
			}
			if test.alias && !strings.HasSuffix(got, digest([]byte(test.name))[:portableHashLength]) {
				t.Fatalf("alias %q does not end with the source hash", got)
			}
			if again := portableComponent(test.name); again != got {
				t.Fatalf("portableComponent(%q) is not deterministic: %q then %q", test.name, got, again)
			}
			for _, suffix := range []string{".txt", ".parts", ".strings.txt"} {
				if len(got+suffix) > 255 {
					t.Fatalf("alias %q leaves no room for %q", got, suffix)
				}
			}
		})
	}
}

func TestPlanPathsPortableAliasesPropagateAndPreserveOriginals(t *testing.T) {
	longParent := strings.Repeat("parent", 50)
	entries := []Entry{
		{Path: longParent + "/CON/file.txt", Type: "file", ArchivePath: longParent + "/CON/file.txt"},
		{Path: longParent + "/NUL.parts", Type: "file", ArchivePath: longParent + "/NUL.parts"},
		{Path: "café/name", Type: "file", ArchivePath: "café/name"},
		{Path: "cafe\u0301/name", Type: "file", ArchivePath: "cafe\u0301/name"},
	}

	planned, err := planPaths(entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(planned) != len(entries) {
		t.Fatalf("planned %d entries, want %d", len(planned), len(entries))
	}

	seen := map[string]string{}
	for _, entry := range planned {
		if entry.Path != entry.ArchivePath {
			t.Errorf("original path changed: %+v", entry)
		}
		if err := safePath(entry.StoredPath); err != nil {
			t.Errorf("stored path %q is unsafe: %v", entry.StoredPath, err)
		}
		key := portablePathKey(entry.StoredPath)
		if previous, ok := seen[key]; ok {
			t.Errorf("stored paths collide: %q and %q", previous, entry.Path)
		}
		seen[key] = entry.Path
		for _, component := range strings.Split(entry.StoredPath, "/") {
			assertPortableComponent(t, component)
		}
	}

	byPath := make(map[string]Entry, len(planned))
	for _, entry := range planned {
		byPath[entry.Path] = entry
	}
	parentAlias := portableComponent(longParent)
	for _, original := range []string{longParent + "/CON/file.txt", longParent + "/NUL.parts"} {
		if got := path.Dir(byPath[original].StoredPath); !strings.HasPrefix(got, parentAlias) {
			t.Fatalf("parent alias did not propagate for %q: %q (want prefix %q)", original, got, parentAlias)
		}
	}
	if byPath["café/name"].StoredPath == byPath["cafe\u0301/name"].StoredPath {
		t.Fatal("Unicode-normalization variants received the same stored path")
	}
}

func TestPlanPathsAliasesRemainDistinctFromOriginalNames(t *testing.T) {
	long := strings.Repeat("collision", 40)
	alias := portableComponent(long)
	planned, err := planPaths([]Entry{{Path: alias, Type: "file"}, {Path: long, Type: "file"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(planned) != 2 || planned[0].StoredPath == planned[1].StoredPath {
		t.Fatalf("portable alias collision was not resolved: %+v", planned)
	}
	for _, entry := range planned {
		assertPortableComponent(t, path.Base(entry.StoredPath))
	}
	if !strings.Contains(planned[1].StoredPath, ".__case_") {
		t.Fatalf("collision alias lacks deterministic case suffix: %+v", planned)
	}
}
