// SPDX-License-Identifier: BSD-3-Clause
package update

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBackupReplacementAndRollback(t *testing.T) {
	for _, failAt := range []int{0, 1, 2, 3} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			dir := t.TempDir()
			target, staged := filepath.Join(dir, "program"), filepath.Join(dir, "new")
			if err := os.WriteFile(target, []byte("old"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(staged, []byte("new"), 0755); err != nil {
				t.Fatal(err)
			}
			calls := 0
			_, err := replaceWithBackup(staged, target, func(from, to string) error {
				calls++
				if calls == failAt || (failAt == 3 && calls == 2) {
					return os.ErrPermission
				}
				return os.Rename(from, to)
			})
			if (err != nil) != (failAt != 0) {
				t.Fatalf("replacement error = %v", err)
			}
			want, survivingPath := "old", target
			if failAt == 0 {
				want = "new"
			} else if failAt == 3 {
				survivingPath += ".old"
				if !strings.Contains(err.Error(), survivingPath) {
					t.Fatal("recovery error does not locate original binary:", err)
				}
			}
			got, readErr := os.ReadFile(survivingPath)
			if readErr != nil || string(got) != want {
				t.Fatalf("surviving executable = %q, %v", got, readErr)
			}
		})
	}
}

func TestBackupDoesNotRemoveUnrelatedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "program")
	if err := os.WriteFile(target+".old", []byte("unrelated file"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := replaceWithBackup("unused", target, func(string, string) error {
		t.Fatal("attempted to replace an unrelated backup")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "move it aside") {
		t.Fatal("unexpected error:", err)
	}
	got, err := os.ReadFile(target + ".old")
	if err != nil || string(got) != "unrelated file" {
		t.Fatalf("unrelated backup modified: %q, %v", got, err)
	}
}

func TestBackupCleansPreviousRelease(t *testing.T) {
	dir := t.TempDir()
	target, staged := filepath.Join(dir, "program"), filepath.Join(dir, "new")
	for path, data := range map[string][]byte{target + ".old": releaseBinary(t), target: []byte("old"), staged: []byte("new")} {
		if err := os.WriteFile(path, data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := replaceWithBackup(staged, target, os.Rename); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target + ".old"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("previous backup not removed: %v", err)
	}
}

// A subprocess runs a copy of this test executable and replaces itself. This
// exercises Windows image locking as well as Unix replacement while running.
func TestReplaceRunningExecutable(t *testing.T) {
	dir := t.TempDir()
	target, staged := filepath.Join(dir, "running.exe"), filepath.Join(dir, "new.exe")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0755); err != nil {
		t.Fatal(err)
	}
	replacement := []byte("replacement installed by the running process")
	if err := os.WriteFile(staged, replacement, 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(target, "-test.run=^TestReplaceRunningHelper$")
	cmd.Env = append(os.Environ(), "ROUTEROS_UPDATE_HELPER="+staged)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("running replacement: %v\n%s", err, output)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("running executable was not replaced: %v", err)
	}
	if runtime.GOOS == "windows" {
		if err := os.Remove(target + ".old"); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("backup remains locked after exit: %v", err)
		}
	}
}

func TestReplaceRunningHelper(t *testing.T) {
	staged := os.Getenv("ROUTEROS_UPDATE_HELPER")
	if staged == "" {
		t.Skip("subprocess helper")
	}
	target, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replaceExecutable(staged, target); err != nil {
		t.Fatal(err)
	}
}
