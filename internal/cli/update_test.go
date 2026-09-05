// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/naterator/routeros-extract/internal/license"
	"github.com/naterator/routeros-extract/internal/update"
)

func TestUpdateCommand(t *testing.T) {
	for _, tt := range []struct {
		name   string
		args   []string
		result update.Result
		err    error
		want   string
	}{
		{name: "check", args: []string{"--check"}, result: update.Result{Available: true}, want: "Update available"},
		{name: "updated", result: update.Result{Updated: true, Path: "/test/binary"}, want: "Updated v1.0.0 to v1.1.0: /test/binary"},
		{name: "backup", result: update.Result{Updated: true, Backup: "program.exe.old"}, want: "Previous executable retained at program.exe.old"},
		{name: "current", want: "No newer release available"},
		{name: "error", err: errors.New("download failed"), want: "download failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := false
			cmd := newUpdateCommand("v1.0.0", func(gotCtx context.Context, version string, checkOnly bool) (update.Result, error) {
				called = true
				if gotCtx != ctx || version != "v1.0.0" || checkOnly != (tt.name == "check") {
					t.Fatalf("runner got wrong inputs: %v %s %v", gotCtx, version, checkOnly)
				}
				result := tt.result
				result.Current, result.Latest = version, "v1.1.0"
				return result, tt.err
			})
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(tt.args)
			err := cmd.ExecuteContext(ctx)
			if !called || !errors.Is(err, tt.err) || !strings.Contains(out.String(), tt.want) {
				t.Fatalf("command = %v, called=%v, output=%q", err, called, out.String())
			}
		})
	}
}

func TestUpdateRejectsArgumentsBeforeNetwork(t *testing.T) {
	cmd := newUpdateCommand("v1.0.0", func(context.Context, string, bool) (update.Result, error) {
		t.Fatal("runner called with invalid arguments")
		return update.Result{}, nil
	})
	cmd.SetArgs([]string{"unexpected"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("unexpected positional argument accepted")
	}
}

func TestLicenseCommandIncludesCompleteLicense(t *testing.T) {
	cmd := New("v1.0.0")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"license"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.String() != license.Text || !strings.Contains(out.String(), "Nate Schmoll") || !strings.Contains(out.String(), "THIRD-PARTY SOFTWARE") {
		t.Fatal("license command did not print all embedded license text")
	}
}
