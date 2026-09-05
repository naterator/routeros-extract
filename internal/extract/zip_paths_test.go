// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestZIPPackageDirectoriesRemainPortable(t *testing.T) {
	long := strings.Repeat("p", 300) + ".npk"
	members := []testZIPMember{}
	for _, name := range []string{"one/" + long, "two/" + long, "NUL.npk", "é.npk"} {
		members = append(members, testZIPMember{name: name, data: testZIPNPK(name)})
	}
	source := writeTestZIP(t, members...)
	destination := filepath.Join(t.TempDir(), "extracted")
	packages, err := ExtractZIP(source, destination, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != len(members) {
		t.Fatalf("got %d packages, want %d", len(packages), len(members))
	}
	if _, err := Verify(destination, source); err != nil {
		t.Fatal(err)
	}
}
