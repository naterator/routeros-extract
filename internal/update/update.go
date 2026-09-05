// SPDX-License-Identifier: BSD-3-Clause
package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	repository       = "github.com/naterator/routeros-extract"
	latestURL        = "https://api.github.com/repos/naterator/routeros-extract/releases/latest"
	maxMetadataBytes = 2 << 20
	maxBinaryBytes   = 128 << 20
)

// Result describes either a version check or a completed installation.
type Result struct {
	Current   string
	Latest    string
	Available bool
	Updated   bool
	Path      string
	Backup    string
}

type release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []asset `json:"assets"`
}

type asset struct {
	Name  string `json:"name"`
	URL   string `json:"browser_download_url"`
	Size  int64  `json:"size"`
	State string `json:"state"`
}

type updater struct {
	client     *http.Client
	endpoint   string
	goos       string
	goarch     string
	executable func() (string, error)
}

// Run checks the latest stable GitHub release and, unless checkOnly is set,
// installs a newer binary over the executable that is currently running.
func Run(ctx context.Context, current string, checkOnly bool) (Result, error) {
	u := updater{
		client:   &http.Client{Timeout: 2 * time.Minute, CheckRedirect: secureRedirect},
		endpoint: latestURL,
		goos:     runtime.GOOS, goarch: runtime.GOARCH,
		executable: os.Executable,
	}
	return u.run(ctx, current, checkOnly)
}

func secureRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errors.New("refusing an insecure download redirect")
	}
	if len(via) >= 10 {
		return errors.New("too many download redirects")
	}
	return nil
}

func assetName(goos, goarch string) (string, error) {
	switch goos {
	case "darwin", "linux", "freebsd", "netbsd", "openbsd", "windows":
	default:
		return "", fmt.Errorf("no release binaries for %s/%s", goos, goarch)
	}
	if goarch != "amd64" && goarch != "arm64" {
		return "", fmt.Errorf("no release binaries for %s/%s", goos, goarch)
	}
	name := "routeros-extract-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name, nil
}

func canonicalVersion(version string) string {
	return semver.Canonical("v" + strings.TrimPrefix(strings.TrimSpace(version), "v"))
}

func newer(current, latest string) (bool, error) {
	target := canonicalVersion(latest)
	if target == "" || semver.Prerelease(target) != "" {
		return false, fmt.Errorf("latest release tag %q is not a stable semantic version", latest)
	}
	switch current {
	case "", "dev", "(devel)":
		return true, nil
	}
	installed := canonicalVersion(current)
	if installed == "" {
		return false, fmt.Errorf("installed version %q is not a semantic version; reinstall from the release page", current)
	}
	return semver.Compare(target, installed) > 0, nil
}

func (u updater) get(ctx context.Context, address, accept string) (*http.Response, error) {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("release download URL must use HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "routeros-extract updater")
	req.Header.Set("Accept", accept)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound && address == u.endpoint {
			return nil, fmt.Errorf("no public stable release is available at %s/releases", repository)
		}
		if resp.StatusCode == http.StatusTooManyRequests ||
			(resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0") {
			return nil, errors.New("GitHub rate limit reached; try the update again later")
		}
		return nil, fmt.Errorf("release request returned HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("release response exceeds the size limit")
	}
	return data, nil
}

func (u updater) findRelease(ctx context.Context) (release, error) {
	var result release
	resp, err := u.get(ctx, u.endpoint, "application/vnd.github+json")
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	data, err := readLimited(resp.Body, maxMetadataBytes)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return result, fmt.Errorf("invalid release metadata: %w", err)
	}
	if result.Draft || result.Prerelease {
		return result, errors.New("GitHub did not return a stable published release")
	}
	return result, nil
}

func (r release) findAsset(name string) (asset, error) {
	var matches []asset
	for _, a := range r.Assets {
		if a.Name == name && a.State == "uploaded" {
			matches = append(matches, a)
		}
	}
	if len(matches) != 1 {
		return asset{}, fmt.Errorf("release %s must contain one uploaded %s asset; release builds may still be running", r.Tag, name)
	}
	return matches[0], nil
}

func parseChecksum(data []byte, name string) ([]byte, error) {
	fields := strings.Fields(string(data))
	if len(fields) != 1 && (len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name) {
		return nil, errors.New("invalid release checksum file")
	}
	hash, err := hex.DecodeString(fields[0])
	if err != nil || len(hash) != sha256.Size {
		return nil, errors.New("invalid SHA-256 release checksum")
	}
	return hash, nil
}

func (u updater) run(ctx context.Context, current string, checkOnly bool) (Result, error) {
	result := Result{Current: current}
	name, err := assetName(u.goos, u.goarch)
	if err != nil {
		return result, err
	}
	r, err := u.findRelease(ctx)
	if err != nil {
		return result, err
	}
	result.Latest = r.Tag
	result.Available, err = newer(current, r.Tag)
	if err != nil || !result.Available {
		return result, err
	}
	binary, err := r.findAsset(name)
	if err != nil {
		return result, err
	}
	checksum, err := r.findAsset(name + ".sha256")
	if err != nil {
		return result, err
	}
	if binary.Size < 1 || binary.Size > maxBinaryBytes {
		return result, errors.New("release binary size is outside the supported limit")
	}
	if checkOnly {
		return result, nil
	}
	target, err := u.executable()
	if err != nil {
		return result, fmt.Errorf("locate current executable: %w", err)
	}
	target, err = filepath.EvalSymlinks(target)
	if err != nil {
		return result, fmt.Errorf("resolve executable path: %w", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		return result, fmt.Errorf("stat executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, fmt.Errorf("executable is not a regular file: %s", target)
	}
	result.Path = target
	staged, err := os.CreateTemp(filepath.Dir(target), ".routeros-extract-update-*")
	if err != nil {
		return result, installationError(target, err)
	}
	defer os.Remove(staged.Name())
	defer staged.Close()

	resp, err := u.get(ctx, checksum.URL, "application/octet-stream")
	if err != nil {
		return result, fmt.Errorf("download checksum: %w", err)
	}
	data, readErr := readLimited(resp.Body, 1024)
	resp.Body.Close()
	if readErr != nil {
		return result, fmt.Errorf("read checksum: %w", readErr)
	}
	wantHash, err := parseChecksum(data, name)
	if err != nil {
		return result, err
	}
	resp, err = u.get(ctx, binary.URL, "application/octet-stream")
	if err != nil {
		return result, fmt.Errorf("download binary: %w", err)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(staged, hash), io.LimitReader(resp.Body, binary.Size+1))
	resp.Body.Close()
	if copyErr != nil {
		return result, fmt.Errorf("download binary: %w", copyErr)
	}
	if size != binary.Size {
		return result, fmt.Errorf("downloaded binary size is %d; expected %d", size, binary.Size)
	}
	if !bytes.Equal(hash.Sum(nil), wantHash) {
		return result, errors.New("downloaded binary failed SHA-256 verification; current executable was not replaced")
	}
	if err := staged.Chmod(info.Mode().Perm()); err != nil {
		return result, installationError(target, err)
	}
	if err := staged.Sync(); err != nil {
		return result, fmt.Errorf("sync downloaded binary: %w", err)
	}
	if err := staged.Close(); err != nil {
		return result, fmt.Errorf("close downloaded binary: %w", err)
	}
	if err := validateBinary(staged.Name(), u.goos, u.goarch); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.Backup, err = replaceExecutable(staged.Name(), target)
	if err != nil {
		return result, installationError(target, err)
	}
	result.Updated = true
	return result, nil
}

func validateBinary(path, goos, goarch string) error {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("download is not a Go executable: %w", err)
	}
	if info.Path != repository+"/cmd/routeros-extract" || info.Main.Path != repository {
		return errors.New("download is not a routeros-extract executable")
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != goos || settings["GOARCH"] != goarch {
		return fmt.Errorf("downloaded executable does not match %s/%s", goos, goarch)
	}
	return nil
}

func installationError(path string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		if runtime.GOOS == "windows" {
			return fmt.Errorf("cannot replace %s: %w; run with write access to its directory", path, err)
		}
		return fmt.Errorf("cannot replace %s: %w; rerun with write access, for example sudo routeros-extract update", path, err)
	}
	return fmt.Errorf("cannot replace %s: %w", path, err)
}
