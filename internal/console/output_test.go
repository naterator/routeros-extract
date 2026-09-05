// SPDX-License-Identifier: BSD-3-Clause
package console

import (
	"strings"
	"testing"
)

func TestCommandsSortsAndNormalizesSummaries(t *testing.T) {
	longSummary := "  first\tsecond\nthird  "
	blankSummary := " \t\n "
	image := &Image{Nodes: []*Node{
		{Kind: "parameter", Paths: []string{"/ignored"}, Summary: &longSummary},
		{Kind: "command", Paths: []string{"/z", "/a"}, Summary: &longSummary},
		{Kind: "menu", Paths: []string{"/root"}, Summary: &blankSummary},
		{Kind: "menu", Paths: []string{"/root/child"}},
	}}

	want := "/a [command] — first second third\n" +
		"/root [menu]\n" +
		"/root/child [menu]\n" +
		"/z [command] — first second third\n"
	if got := string(image.Commands()); got != want {
		t.Fatalf("Commands() = %q, want %q", got, want)
	}
}

func TestStringsTSVEscapesTextAndLabelsUnclassifiedEntries(t *testing.T) {
	image := &Image{Strings: []*String{
		{Offset: 0x10, Address: 0x40000010, References: 2, Roles: []string{"description", "name"}, Encoding: "utf-8", Text: "line\n\"quoted\""},
		{Offset: 0x20, Address: 0x40000020, Encoding: "ascii", Text: "candidate"},
	}}

	lines := strings.Split(string(image.StringsTSV()), "\n")
	if len(lines) != 4 || lines[0] != "offset\taddress\treferences\troles\tencoding\ttext_json" {
		t.Fatalf("unexpected TSV framing: %q", string(image.StringsTSV()))
	}
	want := "0x00000010\t0x40000010\t2\tdescription,name\tutf-8\t\"line\\n\\\"quoted\\\"\""
	if lines[1] != want {
		t.Fatalf("escaped row = %q, want %q", lines[1], want)
	}
	if lines[2] != "0x00000020\t0x40000020\t0\tunclassified-candidate\tascii\t\"candidate\"" {
		t.Fatalf("unclassified row = %q", lines[2])
	}
}
