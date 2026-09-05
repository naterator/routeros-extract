// SPDX-License-Identifier: BSD-3-Clause
package update

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

func replaceExecutable(staged, target string) (string, error) {
	if runtime.GOOS != "windows" {
		// The staging file is in the executable's directory, on the same
		// filesystem, so Unix readers see either the old or the new binary.
		return "", os.Rename(staged, target)
	}
	return replaceWithBackup(staged, target, os.Rename)
}

func replaceWithBackup(staged, target string, rename func(string, string) error) (string, error) {
	backup := target + ".old"
	if _, err := os.Lstat(backup); err == nil {
		// Only remove a previous backup of this program, never an unrelated
		// file that happened to occupy the reserved backup name.
		if err := validateBinary(backup, runtime.GOOS, runtime.GOARCH); err != nil {
			return "", fmt.Errorf("backup path already exists: %s; move it aside before updating", backup)
		}
		if err := os.Remove(backup); err != nil {
			return "", fmt.Errorf("remove previous backup %s: %w", backup, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// Windows can rename a running executable but cannot overwrite it.
	if err := rename(target, backup); err != nil {
		return "", err
	}
	if err := rename(staged, target); err != nil {
		if restoreErr := rename(backup, target); restoreErr != nil {
			return "", fmt.Errorf("install failed: %v; restore failed: %w; original executable remains at %s", err, restoreErr, backup)
		}
		return "", fmt.Errorf("install failed; original executable restored: %w", err)
	}
	if err := os.Remove(backup); err != nil {
		// Windows normally keeps the old image locked until this process
		// exits. A subsequent update can remove this one retained backup.
		return backup, nil
	}
	return "", nil
}
