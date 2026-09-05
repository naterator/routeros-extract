// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/naterator/routeros-extract/internal/extract"
)

type cliNPKSection struct {
	kind uint16
	body []byte
}

func writeCLINPK(t *testing.T, name string, sections ...cliNPKSection) string {
	t.Helper()
	var b bytes.Buffer
	b.Write([]byte{0x1e, 0xf1, 0xd0, 0xba})
	b.Write(make([]byte, 4))
	for _, section := range sections {
		var header [6]byte
		binary.LittleEndian.PutUint16(header[:2], section.kind)
		binary.LittleEndian.PutUint32(header[2:], uint32(len(section.body)))
		b.Write(header[:])
		b.Write(section.body)
	}
	data := b.Bytes()
	binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)-8))
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func executeCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := New("test-version")
	var out, logs bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&logs)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), logs.String(), err
}

func TestInspectCommandJSONOutput(t *testing.T) {
	first := writeCLINPK(t, "first.npk", cliNPKSection{kind: 0x10, body: []byte("arm64")})
	second := writeCLINPK(t, "second.npk", cliNPKSection{kind: 0x18, body: []byte("stable")})

	stdout, stderr, err := executeCLI(t, "inspect", "--json", first, second)
	if err != nil {
		t.Fatal(err)
	}
	if stderr != "" {
		t.Fatalf("inspect wrote unexpected stderr: %q", stderr)
	}
	var got []extract.Metadata
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("inspect JSON: %v\n%s", err, stdout)
	}
	if len(got) != 2 {
		t.Fatalf("got %d package records, want 2", len(got))
	}
	if got[0].Source != "first.npk" || len(got[0].Sections) != 1 || got[0].Sections[0].Label != "architecture_or_trailer" {
		t.Fatalf("first inspect record = %+v", got[0])
	}
	if got[1].Source != "second.npk" {
		t.Fatalf("second inspect record = %+v", got[1])
	}
	if len(got[1].Sections) != 1 || got[1].Sections[0].Label != "channel" || got[1].Sections[0].Text != "stable" {
		t.Fatalf("second inspect sections = %+v", got[1].Sections)
	}
}

func TestExtractVerifyAnalyzeAndCompareCommands(t *testing.T) {
	before := writeCLINPK(t, "before.npk", cliNPKSection{kind: 0x10, body: []byte("arm64")})
	after := writeCLINPK(t, "after.npk", cliNPKSection{kind: 0x10, body: []byte("arm64-new")})
	extractParent := filepath.Join(t.TempDir(), "extracted")

	stdout, stderr, err := executeCLI(t, "extract", "--no-derived", "--out", extractParent, before, after)
	if err != nil {
		t.Fatalf("extract: %v\nstderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, "before: 1 sections extracted and verified") || !strings.Contains(stdout, "after: 1 sections extracted and verified") {
		t.Fatalf("extract output = %q", stdout)
	}
	if !strings.Contains(stderr, "Extracting ") {
		t.Fatalf("extract did not report progress on stderr: %q", stderr)
	}
	beforeDir := filepath.Join(extractParent, "before")
	afterDir := filepath.Join(extractParent, "after")
	for _, dir := range []string{beforeDir, afterDir} {
		for _, file := range []string{"metadata.json", "integrity.json"} {
			if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
				t.Fatalf("missing extraction output %s: %v", filepath.Join(dir, file), err)
			}
		}
	}

	stdout, stderr, err = executeCLI(t, "verify", "--source", before, beforeDir)
	if err != nil {
		t.Fatalf("verify: %v\nstderr=%s", err, stderr)
	}
	var verification extract.Verification
	if err := json.Unmarshal([]byte(stdout), &verification); err != nil {
		t.Fatalf("verify JSON: %v\n%s", err, stdout)
	}
	if !verification.Verified || !verification.SectionRoundtrip || !verification.SourceVerified || verification.Artifacts == 0 {
		t.Fatalf("verification = %+v", verification)
	}

	stdout, stderr, err = executeCLI(t, "analyze", beforeDir)
	if err != nil {
		t.Fatalf("analyze: %v\nstderr=%s", err, stderr)
	}
	var analysis extract.Analysis
	if err := json.Unmarshal([]byte(stdout), &analysis); err != nil {
		t.Fatalf("analyze JSON: %v\n%s", err, stdout)
	}
	if analysis.Kernels != 0 || len(analysis.Notes) == 0 {
		t.Fatalf("analysis = %+v", analysis)
	}
	if _, err := os.Stat(filepath.Join(beforeDir, "derived", "summary.json")); err != nil {
		t.Fatalf("analyze summary missing: %v", err)
	}

	reportDir := filepath.Join(t.TempDir(), "comparison")
	stdout, stderr, err = executeCLI(t, "compare", "--out", reportDir, beforeDir, afterDir)
	if err != nil {
		t.Fatalf("compare: %v\nstderr=%s", err, stderr)
	}
	var comparison extract.Comparison
	if err := json.Unmarshal([]byte(stdout), &comparison); err != nil {
		t.Fatalf("compare JSON: %v\n%s", err, stdout)
	}
	if comparison.Before != "before" || comparison.After != "after" || comparison.Comparison == "" {
		t.Fatalf("comparison = %+v", comparison)
	}
	for _, file := range []string{"summary.json", "rootfs-diff.json", "file-container-diff.csv", "README.md", "integrity.json"} {
		if _, err := os.Stat(filepath.Join(reportDir, file)); err != nil {
			t.Fatalf("compare output %s missing: %v", file, err)
		}
	}
	verifyCLIOutput(t, reportDir)
}

func verifyCLIOutput(t *testing.T, directory string) extract.Verification {
	t.Helper()
	stdout, stderr, err := executeCLI(t, "verify", directory)
	if err != nil {
		t.Fatalf("verify %s: %v\nstderr=%s", directory, err, stderr)
	}
	var verification extract.Verification
	if err := json.Unmarshal([]byte(stdout), &verification); err != nil {
		t.Fatalf("verify %s JSON: %v\n%s", directory, err, stdout)
	}
	if !verification.Verified || verification.Artifacts == 0 {
		t.Fatalf("verification for %s = %+v", directory, verification)
	}
	return verification
}

func TestExtractZIPCommandOutput(t *testing.T) {
	npk := writeCLINPK(t, "feature.npk", cliNPKSection{kind: 0x10, body: []byte("arm64")})
	npkBytes, err := os.ReadFile(npk)
	if err != nil {
		t.Fatal(err)
	}
	zipSource := filepath.Join(t.TempDir(), "all_packages.zip")
	f, err := os.Create(zipSource)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(f)
	member, err := archive.Create("feature.npk")
	if err == nil {
		_, err = member.Write(npkBytes)
	}
	if err == nil {
		_, err = archive.Create("README.txt")
	}
	if closeErr := archive.Close(); err == nil {
		err = closeErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	destinationParent := filepath.Join(t.TempDir(), "collections")
	stdout, stderr, err := executeCLI(t, "extract", "--no-derived", "--out", destinationParent, zipSource)
	if err != nil {
		t.Fatalf("extract ZIP: %v\nstderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, "all_packages: 1 NPK packages extracted and verified") {
		t.Fatalf("extract ZIP output = %q", stdout)
	}
	output := filepath.Join(destinationParent, "all_packages")
	for _, file := range []string{
		"zip-metadata.json",
		"integrity.json",
		"npk/feature.npk",
		"packages/feature/metadata.json",
	} {
		if _, err := os.Stat(filepath.Join(output, file)); err != nil {
			t.Fatalf("extract ZIP output %s missing: %v", file, err)
		}
	}
	zipVerification := verifyCLIOutput(t, output)
	if !zipVerification.SectionRoundtrip || zipVerification.Packages != 1 {
		t.Fatalf("ZIP verification = %+v", zipVerification)
	}
}

func writeCLIGzip(t *testing.T, name string, payload []byte) string {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKernelCommandJSONOutput(t *testing.T) {
	source := writeCLIGzip(t, "kernel.bin", []byte("synthetic kernel payload"))
	destination := filepath.Join(t.TempDir(), "kernel-output")
	stdout, stderr, err := executeCLI(t, "kernel", "--out", destination, source)
	if err != nil {
		t.Fatalf("kernel: %v\nstderr=%s", err, stderr)
	}
	var report extract.KernelReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("kernel JSON: %v\n%s", err, stdout)
	}
	if report.InputFormat != "gzip stream" || len(report.Streams) != 1 {
		t.Fatalf("kernel report = %+v", report)
	}
	stream := report.Streams[0]
	if stream.Compression != "gzip" || stream.DecodedSize != len([]byte("synthetic kernel payload")) || stream.Offset != 0 {
		t.Fatalf("kernel stream = %+v", stream)
	}
	decoded, err := os.ReadFile(filepath.Join(destination, "kernel", stream.File))
	if err != nil {
		t.Fatalf("read decoded kernel payload: %v", err)
	}
	if !bytes.Equal(decoded, []byte("synthetic kernel payload")) {
		t.Fatalf("decoded kernel payload = %q", decoded)
	}
	if _, err := os.Stat(filepath.Join(destination, "integrity.json")); err != nil {
		t.Fatalf("kernel integrity ledger missing: %v", err)
	}
	verifyCLIOutput(t, destination)
}

func TestFirmwareCommandJSONOutput(t *testing.T) {
	data := make([]byte, 32+len("routerboot payload"))
	copy(data[:4], []byte("0017"))
	copy(data[12:32], []byte("1.2"))
	copy(data[32:], []byte("routerboot payload"))
	source := filepath.Join(t.TempDir(), "routerboot.fwf")
	if err := os.WriteFile(source, data, 0644); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "firmware-output")
	stdout, stderr, err := executeCLI(t, "firmware", "--out", destination, source)
	if err != nil {
		t.Fatalf("firmware: %v\nstderr=%s", err, stderr)
	}
	var info extract.FirmwareInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		t.Fatalf("firmware JSON: %v\n%s", err, stdout)
	}
	if info.Format != "routerboot-legacy-raw" || info.Version != "1.2" || info.DecodedSize != len("routerboot payload") {
		t.Fatalf("firmware info = %+v", info)
	}
	for _, file := range []string{"source.fwf", "routerboot.bin", "routerboot.strings.txt", "manifest.json", "integrity.json"} {
		if _, err := os.Stat(filepath.Join(destination, file)); err != nil {
			t.Fatalf("firmware output %s missing: %v", file, err)
		}
	}
	original, err := os.ReadFile(filepath.Join(destination, "source.fwf"))
	if err != nil {
		t.Fatalf("read retained FWF: %v", err)
	}
	if !bytes.Equal(original, data) {
		t.Fatal("retained FWF does not match source")
	}
	decoded, err := os.ReadFile(filepath.Join(destination, "routerboot.bin"))
	if err != nil {
		t.Fatalf("read decoded firmware: %v", err)
	}
	if !bytes.Equal(decoded, []byte("routerboot payload")) {
		t.Fatalf("decoded firmware = %q", decoded)
	}
	verifyCLIOutput(t, destination)
}

func TestSquashFSCommandOutput(t *testing.T) {
	fixture := filepath.Join("..", "extract", "testdata", "empty-file.squashfs")
	image, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read SquashFS fixture: %v", err)
	}
	source := filepath.Join(t.TempDir(), "filesystem.squashfs")
	if err := os.WriteFile(source, image, 0644); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "squashfs-output")
	stdout, stderr, err := executeCLI(t, "squashfs", "--out", destination, source)
	if err != nil {
		t.Fatalf("squashfs: %v\nstderr=%s", err, stderr)
	}
	if strings.TrimSpace(stdout) != destination {
		t.Fatalf("squashfs output = %q, want %q", stdout, destination)
	}
	for _, file := range []string{
		"image.squashfs",
		"rootfs/empty",
		"rootfs/nonempty",
		"rootfs-manifest.json",
		"rootfs.tar.gz",
		"integrity.json",
	} {
		if _, err := os.Stat(filepath.Join(destination, file)); err != nil {
			t.Fatalf("squashfs output %s missing: %v", file, err)
		}
	}
	empty, err := os.ReadFile(filepath.Join(destination, "rootfs", "empty"))
	if err != nil {
		t.Fatalf("read empty SquashFS file: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty SquashFS file has %d bytes", len(empty))
	}
	nonempty, err := os.ReadFile(filepath.Join(destination, "rootfs", "nonempty"))
	if err != nil {
		t.Fatalf("read nonempty SquashFS file: %v", err)
	}
	if !bytes.Equal(nonempty, []byte("routeros squashfs fixture\n")) {
		t.Fatalf("nonempty SquashFS file = %q", nonempty)
	}
	verifyCLIOutput(t, destination)
}
