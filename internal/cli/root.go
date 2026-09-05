// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"

	routerosextract "github.com/naterator/routeros-extract"
	"github.com/naterator/routeros-extract/internal/extract"
	"github.com/naterator/routeros-extract/internal/update"
	"github.com/spf13/cobra"
)

func New(version string) *cobra.Command {
	opt := extract.Options{}
	r := &cobra.Command{Use: "routeros-extract", Short: "Extract and inspect RouterOS packages, kernels, and RouterBOOT firmware", Version: version, SilenceErrors: true, SilenceUsage: true}
	r.Long = "Extract RouterOS NPKs and nested firmware using native Go.\nKeeps original sections, Linux metadata, portable browse copies, and SHA256 manifests.\nNo extracted code is executed. MikroTik signatures are retained but not authenticated."
	r.AddCommand(&cobra.Command{
		Use: "license", Short: "Print the license and third-party notices", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprint(cmd.OutOrStdout(), routerosextract.License)
			return err
		},
	})
	r.PersistentFlags().Int64Var(&opt.MaxBytes, "max-bytes", extract.DefaultMaxBytes, "maximum bytes per input, file container, filesystem, or recursive kernel scan")
	r.PersistentFlags().BoolVar(&opt.NoSymlinks, "no-symlinks", runtime.GOOS == "windows", "retain link metadata without creating host symlinks")
	r.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
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
	inspect := &cobra.Command{Use: "inspect NPK [NPK...]", Short: "Read package metadata and list sections without extracting", Args: cobra.MinimumNArgs(1), RunE: func(c *cobra.Command, args []string) error {
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
	inspect.Flags().BoolVar(&inspectJSON, "json", false, "print machine-readable metadata")
	var out string
	ex := &cobra.Command{Use: "extract INPUT [INPUT...]", Short: "Fully extract NPK packages or all_packages ZIP archives", Args: cobra.MinimumNArgs(1), Example: "  routeros-extract extract routeros-7.24.2-arm64.npk all_packages-arm64-7.24.2.zip -o extracted", RunE: func(c *cobra.Command, args []string) error {
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
	ex.Flags().StringVarP(&out, "out", "o", "extracted", "parent directory for one new folder per NPK")
	ex.Flags().BoolVar(&opt.SectionsOnly, "sections-only", false, "save raw sections and metadata only")
	ex.Flags().BoolVar(&opt.NoDerived, "no-derived", false, "extract package files and filesystems without nested analysis")
	var kernelOut, fwOut, squashOut string
	kernel := &cobra.Command{Use: "kernel IMAGE", Short: "Extract XZ/gzip streams and initramfs from a boot image", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		v, e := extract.Kernel(a[0], kernelOut, opt)
		if e != nil {
			return e
		}
		return jsonOut(c, v)
	}}
	firmware := &cobra.Command{Use: "firmware FWF", Short: "Extract modern or legacy RouterBOOT firmware", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		v, e := extract.Firmware(a[0], fwOut, opt)
		if e != nil {
			return e
		}
		return jsonOut(c, v)
	}}
	squash := &cobra.Command{Use: "squashfs IMAGE", Short: "Export a SquashFS filesystem, archive, and manifests", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
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
		v.c.Flags().StringVarP(v.p, "out", "o", "", "new destination directory")
		_ = v.c.MarkFlagRequired("out")
	}
	analyze := &cobra.Command{Use: "analyze DIRECTORY [DIRECTORY...]", Short: "Add derived payloads and inventories to existing extractions", Args: cobra.MinimumNArgs(1), RunE: func(c *cobra.Command, a []string) error {
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
	compare := &cobra.Command{Use: "compare BEFORE AFTER", Short: "Compare extracted packages by bytes and original metadata", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, a []string) error {
		v, e := extract.Compare(a[0], a[1], compareOut)
		if e != nil {
			return e
		}
		return jsonOut(c, v)
	}}
	compare.Flags().StringVarP(&compareOut, "out", "o", "", "new directory for JSON, CSV, and Markdown reports")
	_ = compare.MarkFlagRequired("out")
	var source string
	verify := &cobra.Command{Use: "verify DIRECTORY", Short: "Verify output hashes, links, and NPK section reconstruction", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		v, e := extract.Verify(a[0], source)
		if e != nil {
			return e
		}
		return jsonOut(c, v)
	}}
	verify.Flags().StringVar(&source, "source", "", "also compare against this original NPK or ZIP")
	r.AddCommand(inspect, ex, kernel, firmware, squash, analyze, compare, verify)
	r.AddCommand(newUpdateCommand(version, update.Run))
	return r
}
