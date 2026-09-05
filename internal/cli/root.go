// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/naterator/routeros-extract/internal/extract"
	"github.com/naterator/routeros-extract/internal/license"
	"github.com/naterator/routeros-extract/internal/update"
	"github.com/spf13/cobra"
)

func New(version string) *cobra.Command {
	opt := extract.Options{}
	r := &cobra.Command{Use: "routeros-extract", Short: "Inspect and extract RouterOS packages.", Version: version, SilenceErrors: true, SilenceUsage: true}
	r.AddCommand(&cobra.Command{
		Use: "license", Short: "Show licenses and notices", GroupID: "utility", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprint(cmd.OutOrStdout(), license.Text)
			return err
		},
	})
	r.PersistentFlags().Int64Var(&opt.MaxBytes, "max-bytes", extract.DefaultMaxBytes, "Input/payload byte limit")
	r.PersistentFlags().BoolVar(&opt.NoSymlinks, "no-symlinks", runtime.GOOS == "windows", "Keep symlinks as metadata")
	r.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := cmd.ValidateRequiredFlags(); err != nil {
			return showHelpOnError(cmd, err)
		}
		if opt.MaxBytes < 1 || opt.MaxBytes > 4<<30 {
			return fmt.Errorf("--max-bytes must be between 1 and 4294967296")
		}
		return nil
	}
	jsonOut := func(c *cobra.Command, v any) error {
		e := json.NewEncoder(c.OutOrStdout())
		e.SetIndent("", "  ")
		return e.Encode(v)
	}
	var inspectJSON bool
	inspect := &cobra.Command{Use: "inspect NPK [NPK...]", Short: "Show package metadata and sections", Args: cobra.MinimumNArgs(1), RunE: func(c *cobra.Command, args []string) error {
		all := []extract.Metadata{}
		for _, src := range args {
			b, e := extract.ReadInput(src, opt)
			if e != nil {
				return e
			}
			m, e := extract.Inspect(b, src)
			if e != nil {
				return e
			}
			all = append(all, m)
		}
		if inspectJSON {
			if len(all) == 1 {
				return jsonOut(c, all[0])
			}
			return jsonOut(c, all)
		}
		w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
		for _, m := range all {
			fmt.Fprintf(w, "%s: %d bytes, SHA256 %s\nINDEX\tTYPE\tOFFSET\tBYTES\tSECTION\tINFO\n", m.Source, m.Size, m.SHA256)
			for _, s := range m.Sections {
				info := s.Name + " " + s.Version
				if s.Text != "" {
					info = strings.ReplaceAll(strings.TrimSpace(s.Text), "\n", " ")
					if len(info) > 80 {
						info = info[:80] + "…"
					}
				}
				fmt.Fprintf(w, "%d\t%s\t%d\t%d\t%s\t%s\n", s.Index, s.TypeHex, s.PayloadOffset, s.Size, s.Label, info)
			}
		}
		return w.Flush()
	}}
	inspect.Flags().BoolVar(&inspectJSON, "json", false, "Print JSON")
	var out string
	ex := &cobra.Command{Use: "extract INPUT [INPUT...]", Short: "Extract NPK packages or ZIP collections", Args: cobra.MinimumNArgs(1), Example: "  routeros-extract extract package.npk -o extracted\n  routeros-extract extract all_packages.zip -o extracted", RunE: func(c *cobra.Command, args []string) error {
		for _, src := range args {
			stem := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
			dest := filepath.Join(out, stem)
			fmt.Fprintf(c.ErrOrStderr(), "Extracting %s → %s\n", src, dest)
			if strings.EqualFold(filepath.Ext(src), ".zip") {
				packages, e := extract.ExtractZIP(src, dest, opt)
				if e != nil {
					return fmt.Errorf("%s: %w (partial output retained at %s)", src, e, dest)
				}
				fmt.Fprintf(c.OutOrStdout(), "%s: %d NPK packages extracted and verified\n", dest, len(packages))
				continue
			}
			m, e := extract.Extract(src, dest, opt)
			if e != nil {
				return fmt.Errorf("%s: %w (partial output retained at %s)", src, e, dest)
			}
			fmt.Fprintf(c.OutOrStdout(), "%s: %d sections extracted and verified\n", dest, len(m.Sections))
		}
		return nil
	}}
	ex.Flags().StringVarP(&out, "out", "o", "extracted", "Output parent directory")
	ex.Flags().BoolVar(&opt.SectionsOnly, "sections-only", false, "Save raw sections only")
	ex.Flags().BoolVar(&opt.NoDerived, "no-derived", false, "Skip nested payload analysis")
	var kernelOut, fwOut, squashOut string
	kernel := &cobra.Command{Use: "kernel IMAGE", Short: "Extract kernel streams and initramfs", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		v, e := extract.Kernel(a[0], kernelOut, opt)
		if e != nil {
			return e
		}
		return jsonOut(c, v)
	}}
	firmware := &cobra.Command{Use: "firmware FWF", Short: "Extract RouterBOOT firmware", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		v, e := extract.Firmware(a[0], fwOut, opt)
		if e != nil {
			return e
		}
		return jsonOut(c, v)
	}}
	var consoleParser, consoleOut string
	console := &cobra.Command{Use: "console INPUT [INPUT...]", Short: "Decode console .mem definitions", Args: cobra.MinimumNArgs(1),
		Long:    "Decode console .mem files or search an extracted rootfs.\nRequires its matching nova/bin/parser executable.\nSupported profiles: 7.24.1-arm64 and 7.24.2-arm64.",
		Example: "  routeros-extract console rootfs --parser rootfs/nova/bin/parser \\\n    -o console-output",
		RunE: func(c *cobra.Command, args []string) error {
			v, err := extract.Console(args, consoleParser, consoleOut, opt)
			if err != nil {
				return err
			}
			return jsonOut(c, v)
		},
	}
	console.Flags().StringVar(&consoleParser, "parser", "", "Matching parser executable (required)")
	console.Flags().StringVarP(&consoleOut, "out", "o", "", "New output directory (required)")
	_ = console.MarkFlagRequired("parser")
	_ = console.MarkFlagRequired("out")
	squash := &cobra.Command{Use: "squashfs IMAGE", Short: "Extract a SquashFS filesystem", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if e := extract.SquashFS(a[0], squashOut, opt); e != nil {
			return e
		}
		fmt.Fprintln(c.OutOrStdout(), squashOut)
		return nil
	}}
	for _, v := range []struct {
		c *cobra.Command
		p *string
	}{{kernel, &kernelOut}, {firmware, &fwOut}, {squash, &squashOut}} {
		v.c.Flags().StringVarP(v.p, "out", "o", "", "New output directory (required)")
		_ = v.c.MarkFlagRequired("out")
	}
	analyze := &cobra.Command{Use: "analyze DIRECTORY [DIRECTORY...]", Short: "Analyze extracted files", Args: cobra.MinimumNArgs(1), RunE: func(c *cobra.Command, a []string) error {
		for _, dir := range a {
			v, e := extract.Analyze(dir, opt)
			if e != nil {
				return e
			}
			if e = jsonOut(c, v); e != nil {
				return e
			}
		}
		return nil
	}}
	var compareOut string
	compare := &cobra.Command{Use: "compare BEFORE AFTER", Short: "Compare extracted packages", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, a []string) error {
		v, e := extract.Compare(a[0], a[1], compareOut)
		if e != nil {
			return e
		}
		return jsonOut(c, v)
	}}
	compare.Flags().StringVarP(&compareOut, "out", "o", "", "New report directory (required)")
	_ = compare.MarkFlagRequired("out")
	var source string
	verify := &cobra.Command{Use: "verify DIRECTORY", Short: "Verify an extraction", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		v, e := extract.Verify(a[0], source)
		if e != nil {
			return e
		}
		return jsonOut(c, v)
	}}
	verify.Flags().StringVar(&source, "source", "", "Check the original NPK or ZIP")
	for _, command := range []*cobra.Command{inspect, ex, kernel, firmware, squash, console, analyze, compare, verify} {
		command.GroupID = "routeros"
		r.AddCommand(command)
	}
	updater := newUpdateCommand(version, update.Run)
	updater.GroupID = "utility"
	r.AddCommand(updater)
	configureHelp(r)
	return r
}
