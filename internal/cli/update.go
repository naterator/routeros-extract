// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"context"
	"fmt"

	"github.com/naterator/routeros-extract/internal/update"
	"github.com/spf13/cobra"
)

type updateRunner func(context.Context, string, bool) (update.Result, error)

func newUpdateCommand(version string, run updateRunner) *cobra.Command {
	var checkOnly bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Install the latest stable release",
		Long:  "Check GitHub for a newer release and update this binary.\nVerify its SHA-256 checksum before installing.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "Checking GitHub for a newer release...")
			result, err := run(cmd.Context(), version, checkOnly)
			if err != nil {
				return err
			}
			switch {
			case result.Updated:
				fmt.Fprintf(cmd.OutOrStdout(), "Updated %s to %s: %s\n", result.Current, result.Latest, result.Path)
				if result.Backup != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "Previous executable retained at %s; it can be removed after this command exits.\n", result.Backup)
				}
			case result.Available:
				fmt.Fprintf(cmd.OutOrStdout(), "Update available: %s -> %s. Run routeros-extract update to install it.\n", result.Current, result.Latest)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "No newer release available (installed %s, latest %s).\n", result.Current, result.Latest)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "Check without installing")
	return cmd
}
