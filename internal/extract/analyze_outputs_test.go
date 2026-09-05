// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAnalyzeInventoriesAndDecodedWebFig(t *testing.T) {
	web := []byte("RouterOS WebFig definition\n")
	module := append(syntheticELF64(), []byte("\x00name=test\x00license=BSD\x00depends=\x00vermagic=sample\x00description=fixture\x00unrelated=omit\x00")...)
	dir := writeAnalysisFixture(t, map[string][]byte{
		"bin/example":         syntheticELF64(),
		"lib/modules/test.ko": module,
		"webfig/example.gz":   testGzip(t, web),
		"nova/bin/login":      []byte("\x00Login prompt\x00Password prompt\x00"),
	})
	summary, err := Analyze(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.WebfigDecodedFiles != 1 || summary.KernelModules != 1 || !reflect.DeepEqual(summary.ELFCounts, map[string]int{"64-bit x86-64 executable": 2}) {
		t.Fatalf("summary = %+v", summary)
	}
	d, err := openDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	webs, err := readJSON[[]WebInfo](d, "derived/webfig/manifest.json")
	if err != nil || len(webs) != 1 {
		t.Fatalf("WebFig inventory = %+v, %v", webs, err)
	}
	if webs[0].Source != "webfig/example.gz" || webs[0].Size != len(web) || webs[0].SHA256 != digest(web) {
		t.Fatalf("WebFig metadata = %+v", webs[0])
	}
	if got, err := d.read("derived/"+webs[0].File, DefaultMaxBytes); err != nil || !bytes.Equal(got, web) {
		t.Fatalf("decoded WebFig = %q, %v", got, err)
	}
	modules, err := readJSON[[]ModuleInfo](d, "derived/kernel-modules.json")
	wantFields := []string{"name=test", "license=BSD", "depends=", "vermagic=sample", "description=fixture"}
	if err != nil || len(modules) != 1 || modules[0].Path != "lib/modules/test.ko" || !reflect.DeepEqual(modules[0].Metadata, wantFields) {
		t.Fatalf("module inventory = %+v, %v", modules, err)
	}
	elves, err := readJSON[[]ELFInfo](d, "derived/elf-inventory.json")
	if err != nil || len(elves) != 2 {
		t.Fatalf("ELF inventory = %+v, %v", elves, err)
	}
	for _, entry := range elves {
		if entry.Bits != 64 || entry.Machine != "x86-64" || entry.Type != "executable" {
			t.Errorf("ELF metadata = %+v", entry)
		}
		report, err := d.read("derived/elf/rootfs/"+entry.Path+".txt", DefaultMaxBytes)
		if err != nil || !strings.Contains(string(report), "Path: "+entry.Path+"\n") || !strings.Contains(string(report), "Machine: EM_X86_64") {
			t.Errorf("ELF report = %q, %v", report, err)
		}
	}
	if got, err := d.read("derived/strings/login.txt", DefaultMaxBytes); err != nil || string(got) != "Login prompt\nPassword prompt\n" {
		t.Fatalf("login strings = %q, %v", got, err)
	}
}

func TestAnalyzeExistingNPKWithRepeatedNestedPayloads(t *testing.T) {
	var sections []testNPKSection
	for _, label := range []string{"first", "second"} {
		records := testFileRecord("boot/kernel", testGzip(t, testGzip(t, testCPIOHardlinks())), [4]byte{})
		records = append(records, testFileRecord("webfig/definition.gz", testGzip(t, []byte(label)), [4]byte{})...)
		records = append(records, testFileRecord("etc/test-7.24.2.fwf", syntheticLegacyFWF("0339", "7.24.2", []byte(label)), [4]byte{})...)
		sections = append(sections, testNPKSection{kind: 4, body: testZlib(records)})
	}
	source := filepath.Join(t.TempDir(), "test.npk")
	if err := os.WriteFile(source, testNPK(sections...), 0644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "extracted")
	if _, err := Extract(source, dir, Options{NoDerived: true}); err != nil {
		t.Fatal(err)
	}
	before, err := Verify(dir, source)
	if err != nil || !before.Verified {
		t.Fatalf("before analysis = %+v, %v", before, err)
	}
	summary, err := Analyze(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Kernels != 2 || summary.KernelStreams != 4 || summary.RouterBOOTImages != 2 || summary.WebfigDecodedFiles != 2 {
		t.Fatalf("nested payload counts = %+v", summary)
	}
	d, err := openDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for i, label := range []string{"first", "second"} {
		folder := folderName("files", i+1)
		got, err := d.read("derived/webfig/"+folder+"/webfig/definition", DefaultMaxBytes)
		if err != nil || string(got) != label {
			t.Fatalf("WebFig from %s = %q, %v", folder, got, err)
		}
		kernel := folderName("kernel", i+1)
		for _, name := range []string{"foo", "bar"} {
			got, err := d.read("derived/"+kernel+"/stream-0.bin.parts/initramfs/"+name, DefaultMaxBytes)
			if err != nil || string(got) != "abc" {
				t.Fatalf("nested initramfs %s/%s = %q, %v", kernel, name, got, err)
			}
		}
	}
	boots, err := readJSON[[]FirmwareInfo](d, "derived/routerboot/manifest.json")
	if err != nil || len(boots) != 2 {
		t.Fatalf("RouterBOOT manifest = %+v, %v", boots, err)
	}
	for i, label := range []string{"first", "second"} {
		got, err := d.read("derived/routerboot/"+boots[i].File, DefaultMaxBytes)
		if err != nil || string(got) != label {
			t.Fatalf("RouterBOOT %d = %q, %v", i, got, err)
		}
	}
	after, err := Verify(dir, source)
	if err != nil || !after.Verified || !after.SourceVerified || !after.SectionRoundtrip || after.Artifacts <= before.Artifacts {
		t.Fatalf("after analysis = %+v, %v; before artifacts = %d", after, err, before.Artifacts)
	}
	if _, err := Analyze(dir, Options{}); err == nil || !strings.Contains(err.Error(), "derived output must not exist") {
		t.Fatalf("repeat analysis error = %v", err)
	}
}

func TestDescribeELFArchitectures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bits    int
		machine elf.Machine
		order   binary.ByteOrder
	}{
		{"ARM", 32, elf.EM_ARM, binary.LittleEndian},
		{"AArch64", 64, elf.EM_AARCH64, binary.LittleEndian},
		{"x86", 32, elf.EM_386, binary.LittleEndian},
		{"x86-64", 64, elf.EM_X86_64, binary.LittleEndian},
		{"MIPS", 32, elf.EM_MIPS, binary.BigEndian},
		{"MIPS", 32, elf.EM_MIPS, binary.LittleEndian},
		{"PowerPC", 32, elf.EM_PPC, binary.BigEndian},
		{"PowerPC64", 64, elf.EM_PPC64, binary.BigEndian},
		{"TILE-Gx", 64, elf.EM_TILEGX, binary.LittleEndian},
	} {
		t.Run(tc.name+"/"+tc.order.String(), func(t *testing.T) {
			for kind, wantType := range map[elf.Type]string{elf.ET_EXEC: "executable", elf.ET_REL: "relocatable", elf.ET_DYN: "shared_object"} {
				b := make([]byte, 64)
				copy(b, "\x7fELF")
				b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
				if tc.order == binary.BigEndian {
					b[5] = byte(elf.ELFDATA2MSB)
				}
				tc.order.PutUint16(b[16:], uint16(kind))
				tc.order.PutUint16(b[18:], uint16(tc.machine))
				tc.order.PutUint32(b[20:], 1)
				if tc.bits == 32 {
					b = b[:52]
					b[4] = byte(elf.ELFCLASS32)
					tc.order.PutUint16(b[40:], 52)
				} else {
					tc.order.PutUint16(b[52:], 64)
				}
				info, _, err := describeELF(b, "bin/test")
				want := ELFInfo{Path: "bin/test", Bits: tc.bits, Machine: tc.name, Type: wantType}
				if err != nil || info != want {
					t.Fatalf("describeELF(%s) = %+v, %v; want %+v", kind, info, err, want)
				}
			}
		})
	}
}
