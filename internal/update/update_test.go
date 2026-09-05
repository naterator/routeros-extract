// SPDX-License-Identifier: BSD-3-Clause
package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Build a real release executable once. Tests serve it locally and only replace
// temporary files; they never contact GitHub or overwrite the installed CLI.
var fixture struct {
	sync.Once
	data []byte
	err  error
}

func releaseBinary(t *testing.T) []byte {
	t.Helper()
	fixture.Do(func() {
		var dir string
		dir, fixture.err = os.MkdirTemp("", "routeros-update-fixture-*")
		if fixture.err != nil {
			return
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, "routeros-extract.exe")
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w -X main.version=v1.10.0", "-o", path, "./cmd/routeros-extract")
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
		if output, err := cmd.CombinedOutput(); err != nil {
			fixture.err = fmt.Errorf("build fixture: %w\n%s", err, output)
			return
		}
		fixture.data, fixture.err = os.ReadFile(path)
	})
	if fixture.err != nil {
		t.Fatal(fixture.err)
	}
	return fixture.data
}

type releaseServer struct {
	u                updater
	metadata         release
	body             []byte
	checksum         string
	metadataOverride string
	status           int
	assetStatus      int
	requests         []string
}

func serveRelease(t *testing.T, body []byte) *releaseServer {
	t.Helper()
	name, err := assetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	digest := sha256.Sum256(body)
	f := &releaseServer{body: body, checksum: hex.EncodeToString(digest[:]) + "\n"}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.URL.Path)
		if r.Header.Get("User-Agent") != "routeros-extract updater" {
			t.Error("missing updater user agent")
		}
		if r.URL.Path == "/latest" {
			if f.status != 0 {
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.WriteHeader(f.status)
			} else if f.metadataOverride != "" {
				fmt.Fprint(w, f.metadataOverride)
			} else {
				json.NewEncoder(w).Encode(f.metadata)
			}
		} else if f.assetStatus != 0 {
			w.WriteHeader(f.assetStatus)
		} else if r.URL.Path == "/checksum" {
			fmt.Fprint(w, f.checksum)
		} else if r.URL.Path == "/binary" {
			w.Write(f.body)
		} else {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = secureRedirect
	f.u = updater{client: client, endpoint: srv.URL + "/latest", goos: runtime.GOOS, goarch: runtime.GOARCH}
	f.metadata = release{Tag: "v1.10.0", Assets: []asset{
		{Name: name, URL: srv.URL + "/binary", Size: int64(len(body)), State: "uploaded"},
		{Name: name + ".sha256", URL: srv.URL + "/checksum", State: "uploaded"},
	}}
	return f
}

func TestVersionComparison(t *testing.T) {
	for _, tt := range []struct {
		current, latest string
		available       bool
		bad             bool
	}{
		{"v1.9.0", "v1.10.0", true, false},
		{"1.9.0", "1.10.0", true, false},
		{"v2.0.0", "v1.10.0", false, false},
		{"v1.10.0", "v1.10.0", false, false},
		{"v1.10.0+local", "v1.10.0+release", false, false},
		{"v1.10.0-rc.1", "v1.10.0", true, false},
		{"dev", "v1.10.0", true, false},
		{"(devel)", "v1.10.0", true, false},
		{"", "v1.10.0", true, false},
		{"abcd123", "v1.10.0", false, true},
		{"v1.9.0", "latest", false, true},
		{"v1.9.0", "v1.10.0-rc.1", false, true},
	} {
		t.Run(tt.current+"_to_"+tt.latest, func(t *testing.T) {
			got, err := newer(tt.current, tt.latest)
			if got != tt.available || (err != nil) != tt.bad {
				t.Fatalf("newer = %v, %v", got, err)
			}
		})
	}
}

func TestAssetPlatforms(t *testing.T) {
	for _, goos := range []string{"darwin", "freebsd", "linux", "netbsd", "openbsd", "windows"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			want := "routeros-extract-" + goos + "-" + goarch
			if goos == "windows" {
				want += ".exe"
			}
			if got, err := assetName(goos, goarch); err != nil || got != want {
				t.Fatalf("assetName(%s, %s) = %q, %v", goos, goarch, got, err)
			}
		}
	}
	for _, platform := range [][2]string{{"plan9", "amd64"}, {"linux", "386"}, {"linux", "arm"}} {
		if _, err := assetName(platform[0], platform[1]); err == nil {
			t.Fatal("unsupported platform accepted:", platform)
		}
	}
}

func TestCheckAndCurrentVersionDoNotTouchExecutable(t *testing.T) {
	for _, tt := range []struct {
		version   string
		checkOnly bool
		available bool
	}{{"v1.9.0", true, true}, {"v1.10.0", false, false}, {"v2.0.0", false, false}} {
		t.Run(tt.version, func(t *testing.T) {
			f := serveRelease(t, []byte("not downloaded"))
			f.u.executable = func() (string, error) {
				t.Fatal("executable looked up during version check")
				return "", nil
			}
			result, err := f.u.run(context.Background(), tt.version, tt.checkOnly)
			if err != nil || result.Available != tt.available || result.Updated {
				t.Fatalf("run = %+v, %v", result, err)
			}
			if strings.Join(f.requests, ",") != "/latest" {
				t.Fatal("unexpected asset download:", f.requests)
			}
		})
	}
}

func TestInstallRelease(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(fmt.Sprintf("symlink=%v", symlink), func(t *testing.T) {
			f := serveRelease(t, releaseBinary(t))
			dir := t.TempDir()
			target := filepath.Join(dir, "routeros-extract.exe")
			if err := os.WriteFile(target, []byte("old executable"), 0751); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			invoked := target
			if symlink {
				invoked = filepath.Join(dir, "link.exe")
				if err := os.Symlink(target, invoked); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			f.u.executable = func() (string, error) { return invoked, nil }
			result, err := f.u.run(context.Background(), "v1.9.0", false)
			if err != nil || !result.Updated || !result.Available {
				t.Fatalf("run = %+v, %v", result, err)
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, f.body) {
				t.Fatalf("replacement differs from release: %v", err)
			}
			after, err := os.Stat(target)
			if err != nil || before.Mode() != after.Mode() {
				t.Fatalf("executable permissions changed: %v", err)
			}
			if symlink {
				info, err := os.Lstat(invoked)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("symlink was replaced: %v", err)
				}
			}
			assertNoStagingFiles(t, dir)
		})
	}
}

func TestFailedUpdatePreservesExecutable(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*releaseServer)
		want string
	}{
		{"no release", func(f *releaseServer) { f.status = 404 }, "no public stable release"},
		{"rate limit", func(f *releaseServer) { f.status = 403 }, "rate limit"},
		{"server error", func(f *releaseServer) { f.status = 502 }, "HTTP 502"},
		{"bad JSON", func(f *releaseServer) { f.metadataOverride = "{" }, "invalid release metadata"},
		{"oversized JSON", func(f *releaseServer) { f.metadataOverride = strings.Repeat(" ", maxMetadataBytes+1) }, "size limit"},
		{"prerelease", func(f *releaseServer) { f.metadata.Prerelease = true }, "stable published"},
		{"draft", func(f *releaseServer) { f.metadata.Draft = true }, "stable published"},
		{"missing checksum", func(f *releaseServer) { f.metadata.Assets = f.metadata.Assets[:1] }, ".sha256 asset"},
		{"missing binary", func(f *releaseServer) { f.metadata.Assets = f.metadata.Assets[1:] }, "one uploaded"},
		{"duplicate asset", func(f *releaseServer) { f.metadata.Assets = append(f.metadata.Assets, f.metadata.Assets[0]) }, "one uploaded"},
		{"unfinished upload", func(f *releaseServer) { f.metadata.Assets[0].State = "new" }, "one uploaded"},
		{"oversized binary", func(f *releaseServer) { f.metadata.Assets[0].Size = maxBinaryBytes + 1 }, "size is outside"},
		{"zero binary", func(f *releaseServer) { f.metadata.Assets[0].Size = 0 }, "size is outside"},
		{"short binary", func(f *releaseServer) { f.metadata.Assets[0].Size++ }, "binary size"},
		{"long binary", func(f *releaseServer) { f.metadata.Assets[0].Size-- }, "binary size"},
		{"asset error", func(f *releaseServer) { f.assetStatus = 404 }, "HTTP 404"},
		{"insecure asset", func(f *releaseServer) { f.metadata.Assets[0].URL = "http://example.com/binary" }, "must use HTTPS"},
		{"bad checksum", func(f *releaseServer) { f.checksum = strings.Repeat("0", 64) }, "SHA-256 verification"},
		{"malformed checksum", func(f *releaseServer) { f.checksum = "bogus" }, "invalid SHA-256"},
		{"oversized checksum", func(f *releaseServer) { f.checksum = strings.Repeat("a", 1025) }, "size limit"},
		{"wrong program", func(f *releaseServer) {}, "not a Go executable"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := serveRelease(t, []byte("downloaded payload"))
			tt.edit(f)
			dir := t.TempDir()
			target := filepath.Join(dir, "routeros-extract.exe")
			before := []byte("original executable must survive")
			if err := os.WriteFile(target, before, 0755); err != nil {
				t.Fatal(err)
			}
			f.u.executable = func() (string, error) { return target, nil }
			result, err := f.u.run(context.Background(), "v1.9.0", false)
			if err == nil || !strings.Contains(err.Error(), tt.want) || result.Updated {
				t.Fatalf("run = %+v, %v; wanted error containing %q", result, err, tt.want)
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, before) {
				t.Fatalf("failed update changed the original: %v", err)
			}
			assertNoStagingFiles(t, dir)
		})
	}
}

func assertNoStagingFiles(t *testing.T, dir string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, ".routeros-extract-update-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("staging files not cleaned up: %v, %v", files, err)
	}
}

func TestChecksumFormats(t *testing.T) {
	digest := sha256.Sum256([]byte("binary"))
	hash := hex.EncodeToString(digest[:])
	for _, value := range []string{hash + "\n", hash + "  binary\n", hash + " *binary\r\n", strings.ToUpper(hash)} {
		got, err := parseChecksum([]byte(value), "binary")
		if err != nil || !bytes.Equal(got, digest[:]) {
			t.Fatalf("parseChecksum(%q) = %x, %v", value, got, err)
		}
	}
	for _, value := range []string{"", hash + " other-binary", hash + " binary extra", "zz", hash[:62]} {
		if _, err := parseChecksum([]byte(value), "binary"); err == nil {
			t.Errorf("bad checksum accepted: %q", value)
		}
	}
}

func TestBinaryValidation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "release")
	if err := os.WriteFile(target, releaseBinary(t), 0755); err != nil {
		t.Fatal(err)
	}
	if err := validateBinary(target, runtime.GOOS, runtime.GOARCH); err != nil {
		t.Fatal(err)
	}
	if err := validateBinary(target, "wrong-os", runtime.GOARCH); err == nil {
		t.Fatal("wrong platform accepted")
	}
	if err := validateBinary(target, runtime.GOOS, "wrong-arch"); err == nil {
		t.Fatal("wrong architecture accepted")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBinary(self, runtime.GOOS, runtime.GOARCH); err == nil || !strings.Contains(err.Error(), "not a routeros-extract") {
		t.Fatalf("different Go program accepted: %v", err)
	}
}

func TestHTTPSAndCancellation(t *testing.T) {
	f := serveRelease(t, []byte("body"))
	for _, address := range []string{"http://example.com", "https://user:password@example.com", "https:///missing-host", "://bad"} {
		if _, err := f.u.get(context.Background(), address, ""); err == nil {
			t.Errorf("unsafe URL accepted: %s", address)
		}
	}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/binary", http.StatusFound)
	}))
	defer redirect.Close()
	f.u.client = redirect.Client()
	f.u.client.CheckRedirect = secureRedirect
	if _, err := f.u.get(context.Background(), redirect.URL, ""); err == nil || !strings.Contains(err.Error(), "insecure download redirect") {
		t.Fatalf("insecure redirect accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.u.run(ctx, "v1.0.0", false); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("canceled update ran: %v", err)
	}
}

func TestReadOnlyInstallDirectory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("requires an unprivileged Unix process and Unix mode bits")
	}
	f := serveRelease(t, []byte("not downloaded"))
	dir := t.TempDir()
	target := filepath.Join(dir, "routeros-extract")
	if err := os.WriteFile(target, []byte("original"), 0755); err != nil {
		t.Fatal(err)
	}
	f.u.executable = func() (string, error) { return target, nil }
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0755)
	result, err := f.u.run(context.Background(), "v1.0.0", false)
	if !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "sudo routeros-extract update") || result.Updated {
		t.Fatalf("read-only directory: %+v, %v", result, err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "original" {
		t.Fatalf("original changed: %q, %v", got, err)
	}
	assertNoStagingFiles(t, dir)
}
