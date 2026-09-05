// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"fmt"
	"strings"

	"github.com/naterator/routeros-extract/internal/extract"
	"github.com/spf13/cobra"
)

const helpWidth = 72

const helpUsage = `Usage:{{if .Runnable}}
  {{.UseLine}}{{else}}
  {{.CommandPath}} [command]{{end}}{{if .HasAvailableSubCommands}}{{if .Groups}}{{$commands := .Commands}}{{range .Groups}}{{$group := .}}

{{.Title}}{{range $commands}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding}} {{.Short}}{{end}}{{end}}{{end}}{{else}}

Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding}} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{if .Flags.HasAvailableFlags}}

Flags:
{{routerosHelpFlags .}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

More help: {{.CommandPath}} [command] --help{{end}}
`

func init() {
	cobra.AddTemplateFunc("routerosHelpFlags", func(cmd *cobra.Command) string {
		usage := cmd.Flags().FlagUsagesWrapped(helpWidth)
		// Format the displayed default without changing numeric flag parsing.
		usage = strings.ReplaceAll(usage,
			fmt.Sprintf("(default %d)", extract.DefaultMaxBytes),
			fmt.Sprintf("(default %d MiB)", extract.DefaultMaxBytes>>20))
		return strings.TrimRight(usage, "\n")
	})
}

func configureHelp(root *cobra.Command) {
	root.AddGroup(
		&cobra.Group{ID: "routeros", Title: "RouterOS commands:"},
		&cobra.Group{ID: "utility", Title: "Utility commands:"},
	)
	root.SetHelpCommandGroupID("utility")
	root.SetCompletionCommandGroupID("utility")
	root.SetUsageTemplate(helpUsage)
	root.SetFlagErrorFunc(showHelpOnError)
	for _, child := range root.Commands() {
		if validate := child.Args; validate != nil {
			child.Args = func(cmd *cobra.Command, args []string) error {
				return showHelpOnError(cmd, validate(cmd, args))
			}
		}
	}
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// Cobra creates these commands at execution time, after output is set.
		// Retain their generators and only replace the help text.
		for _, child := range root.Commands() {
			switch child.Name() {
			case "help":
				child.Short, child.Long = "Show command help", ""
			case "completion":
				child.Short, child.Long = "Generate shell completions", ""
				for _, shell := range child.Commands() {
					shell.Short = "Generate " + shell.Name() + " completions"
					shell.Long = ""
					switch shell.Name() {
					case "bash":
						shell.Example = "  source <(" + shell.CommandPath() + ")"
					case "zsh":
						shell.Example = "  autoload -Uz compinit && compinit\n  source <(" + shell.CommandPath() + ")"
					case "fish":
						shell.Example = "  " + shell.CommandPath() + " | source"
					case "powershell":
						shell.Example = "  " + shell.CommandPath() + " | Out-String |\n    Invoke-Expression"
					}
					if flag := shell.Flags().Lookup("no-descriptions"); flag != nil {
						flag.Usage = "Omit completion descriptions"
					}
				}
			}
		}
		cmd.InitDefaultHelpFlag()
		cmd.Flags().Lookup("help").Usage = "Show help"
		cmd.InitDefaultVersionFlag()
		if flag := cmd.Flags().Lookup("version"); flag != nil {
			flag.Usage = "Show version"
		}
		defaultHelp(cmd, args)
	})
}

func showHelpOnError(cmd *cobra.Command, err error) error {
	if err != nil {
		_ = cmd.Help()
	}
	return err
}
