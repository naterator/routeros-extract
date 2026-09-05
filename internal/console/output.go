// SPDX-License-Identifier: BSD-3-Clause
package console

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Commands lists decoded paths. It does not assert that every record is
// exposed on a running router or that the CLI currently accepts that path.
func (image *Image) Commands() []byte {
	lines := []string{}
	for _, node := range image.Nodes {
		if node.Kind != "menu" && node.Kind != "command" {
			continue
		}
		for _, path := range node.Paths {
			line := fmt.Sprintf("%s [%s]", path, node.Kind)
			if node.Summary != nil && strings.TrimSpace(*node.Summary) != "" {
				line += " — " + strings.Join(strings.Fields(*node.Summary), " ")
			}
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n") + "\n")
}

func (image *Image) StringsTSV() []byte {
	var out bytes.Buffer
	out.WriteString("offset\taddress\treferences\troles\tencoding\ttext_json\n")
	for _, entry := range image.Strings {
		roles := strings.Join(entry.Roles, ",")
		if roles == "" {
			roles = "unclassified-candidate"
		}
		text, _ := json.Marshal(entry.Text)
		fmt.Fprintf(&out, "%s\t%s\t%d\t%s\t%s\t%s\n", entry.Offset, entry.Address, entry.References, roles, entry.Encoding, text)
	}
	return out.Bytes()
}
