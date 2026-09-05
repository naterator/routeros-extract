// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Diff struct {
	Path      string `json:"path"`
	Status    string `json:"status"`
	Type      string `json:"type"`
	OldSize   *int64 `json:"old_size"`
	NewSize   *int64 `json:"new_size"`
	OldSHA256 string `json:"old_sha256"`
	NewSHA256 string `json:"new_sha256"`
	OldTarget string `json:"old_target"`
	NewTarget string `json:"new_target"`
}
type Comparison struct {
	Before        string         `json:"before"`
	After         string         `json:"after"`
	Comparison    string         `json:"comparison"`
	RootFS        map[string]int `json:"rootfs"`
	RegularFiles  map[string]int `json:"rootfs_regular_files"`
	FileContainer map[string]int `json:"file_container"`
	RouterBOOT    map[string]int `json:"routerboot_matched_by_family"`
}

func manifestSet(d *disk, kind uint16) (map[string]Entry, error) {
	m, e := readJSON[Metadata](d, "metadata.json")
	if e != nil {
		return nil, e
	}
	out := map[string]Entry{}
	for _, s := range m.Sections {
		if s.Type != kind || s.ExtractedTo == "" {
			continue
		}
		list, e := readJSON[[]Entry](d, s.ExtractedTo+"-manifest.json")
		if e != nil {
			return nil, e
		}
		for _, v := range list {
			if e = safePath(v.Path); e != nil {
				return nil, e
			}
			key := v.Path
			if s.ExtractedTo != "files" && s.ExtractedTo != "rootfs" {
				key = s.ExtractedTo + "/" + key
			}
			if _, ok := out[key]; ok {
				return nil, fmt.Errorf("duplicate manifest path: %s", key)
			}
			out[key] = v
		}
	}
	return out, nil
}
func diffEntries(a, b map[string]Entry) []Diff {
	keys := map[string]bool{}
	for p := range a {
		keys[p] = true
	}
	for p := range b {
		keys[p] = true
	}
	names := []string{}
	for p := range keys {
		names = append(names, p)
	}
	sort.Strings(names)
	rows := []Diff{}
	for _, p := range names {
		x, xok := a[p]
		y, yok := b[p]
		status := "unchanged"
		switch {
		case !xok:
			status = "added"
		case !yok:
			status = "removed"
		case x.Type != y.Type:
			status = "type_changed"
		case x.SHA256 != y.SHA256:
			status = "content_changed"
		case x.Target != y.Target:
			status = "symlink_changed"
		case x.Mode != y.Mode:
			status = "mode_changed"
		}
		typ := y.Type
		if !yok {
			typ = x.Type
		}
		r := Diff{Path: p, Status: status, Type: typ, OldSHA256: x.SHA256, NewSHA256: y.SHA256, OldTarget: x.Target, NewTarget: y.Target}
		if xok && x.Type == "file" {
			sz := x.Size
			r.OldSize = &sz
		}
		if yok && y.Type == "file" {
			sz := y.Size
			r.NewSize = &sz
		}
		rows = append(rows, r)
	}
	return rows
}
func statuses(rows []Diff, regular bool) map[string]int {
	m := map[string]int{}
	for _, r := range rows {
		if !regular || r.Type == "file" {
			m[r.Status]++
		}
	}
	return m
}

var firmwareVersion = regexp.MustCompile(`-[0-9]+\.[0-9]+[^/]*\.fwf$`)

func firmwareSet(m map[string]Entry) (map[string]Entry, error) {
	out := map[string]Entry{}
	for p, v := range m {
		if v.Type == "file" && strings.HasSuffix(p, ".fwf") {
			key := firmwareVersion.ReplaceAllString(p, ".fwf")
			if _, ok := out[key]; ok {
				return nil, fmt.Errorf("ambiguous firmware family: %s", key)
			}
			out[key] = v
		}
	}
	return out, nil
}
func sizeText(p *int64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatInt(*p, 10)
}

func Compare(before, after, destination string) (Comparison, error) {
	s := Comparison{Before: filepath.Base(before), After: filepath.Base(after), Comparison: "SHA256 of file bytes, symlink targets, node types, and original modes; ignores mtime and host path aliases"}
	a, e := openDisk(before)
	if e != nil {
		return s, e
	}
	defer a.Close()
	b, e := openDisk(after)
	if e != nil {
		return s, e
	}
	defer b.Close()
	ar, e := manifestSet(a, 0x15)
	if e != nil {
		return s, e
	}
	br, e := manifestSet(b, 0x15)
	if e != nil {
		return s, e
	}
	af, e := manifestSet(a, 4)
	if e != nil {
		return s, e
	}
	bf, e := manifestSet(b, 4)
	if e != nil {
		return s, e
	}
	ab, e := firmwareSet(ar)
	if e != nil {
		return s, e
	}
	bb, e := firmwareSet(br)
	if e != nil {
		return s, e
	}
	root := diffEntries(ar, br)
	files := diffEntries(af, bf)
	boots := diffEntries(ab, bb)
	s.RootFS = statuses(root, false)
	s.RegularFiles = statuses(root, true)
	s.FileContainer = statuses(files, false)
	s.RouterBOOT = statuses(boots, false)
	d, e := newDisk(destination)
	if e != nil {
		return s, e
	}
	defer d.Close()
	if e = d.json("summary.json", s); e != nil {
		return s, e
	}
	for name, rows := range map[string][]Diff{"rootfs": root, "file-container": files, "routerboot": boots} {
		if e = d.json(name+"-diff.json", rows); e != nil {
			return s, e
		}
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		_ = w.Write([]string{"path", "status", "type", "old_size", "new_size", "old_sha256", "new_sha256", "old_target", "new_target"})
		for _, r := range rows {
			_ = w.Write([]string{r.Path, r.Status, r.Type, sizeText(r.OldSize), sizeText(r.NewSize), r.OldSHA256, r.NewSHA256, r.OldTarget, r.NewTarget})
		}
		w.Flush()
		if e = w.Error(); e != nil {
			return s, e
		}
		if e = d.put(name+"-diff.csv", buf.Bytes()); e != nil {
			return s, e
		}
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# %s to %s\n\nByte and metadata comparison; a changed hash alone does not establish changed behavior.\n\n", s.Before, s.After)
	md.WriteString("| Scope | Status | Count |\n|---|---|---:|\n")
	for _, scope := range []struct {
		name   string
		counts map[string]int
	}{{"Root filesystem", s.RootFS}, {"Regular files", s.RegularFiles}, {"File container", s.FileContainer}, {"RouterBOOT families", s.RouterBOOT}} {
		keys := []string{}
		for k := range scope.counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&md, "| %s | %s | %d |\n", scope.name, k, scope.counts[k])
		}
	}
	md.WriteString("\n| Original path | Change | Old bytes | New bytes |\n|---|---|---:|---:|\n")
	for _, r := range root {
		if r.Status != "unchanged" {
			fmt.Fprintf(&md, "| %s | %s | %s | %s |\n", strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ").Replace(r.Path), r.Status, sizeText(r.OldSize), sizeText(r.NewSize))
		}
	}
	if e = d.put("README.md", []byte(md.String())); e != nil {
		return s, e
	}
	return s, writeIntegrity(d)
}
