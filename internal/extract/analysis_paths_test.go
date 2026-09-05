// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirmwareDerivedNamesRemainPortable(t *testing.T) {
	long := strings.Repeat("a", 240) + ".fwf"
	var records []byte
	for _, name := range []string{"one/" + long, "two/" + long, "three/NUL.fwf", "four/é.fwf"} {
		records = append(records, testFileRecord(name, syntheticLegacyFWF("0339", "7.24.2", []byte("payload")), [4]byte{})...)
	}
	source := filepath.Join(t.TempDir(), "source.npk")
	if err := os.WriteFile(source, testNPK(testNPKSection{kind: 4, body: testZlib(records)}), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "extracted")
	if _, err := Extract(source, output, Options{NoSymlinks: true}); err != nil {
		t.Fatal(err)
	}
	d, err := openDisk(output)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	images, err := readJSON[[]FirmwareInfo](d, "derived/routerboot/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 4 {
		t.Fatalf("got %d images, want 4", len(images))
	}
	seen := map[string]bool{}
	for _, image := range images {
		key := strings.ToLower(image.File)
		if len(image.File) > 255 || windowsReservedComponent(image.File) || seen[key] {
			t.Fatalf("nonportable or duplicate firmware output %q", image.File)
		}
		seen[key] = true
	}
	if _, err := Verify(output, source); err != nil {
		t.Fatal(err)
	}
}
