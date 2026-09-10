// SPDX-License-Identifier: BSD-3-Clause
package console

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxNodes      = 100000
	maxReferences = 200000
	maxStrings    = 200000
	maxString     = 65536
	maxPathBytes  = 4096
	maxTextBytes  = 16 << 20
)

type Address uint32

func (a Address) String() string               { return fmt.Sprintf("0x%08x", uint32(a)) }
func (a Address) MarshalText() ([]byte, error) { return []byte(a.String()), nil }
func (a *Address) UnmarshalText(b []byte) error {
	v, err := strconv.ParseUint(string(b), 0, 32)
	*a = Address(v)
	return err
}

type Reference struct {
	Node  Address  `json:"node"`
	Flags *Address `json:"flags,omitempty"`
}

type Node struct {
	Address              Address     `json:"address"`
	Offset               Address     `json:"offset"`
	Vtable               Address     `json:"vtable"`
	Kind                 string      `json:"kind"`
	Layout               string      `json:"layout"`
	Flags04              Address     `json:"flags_04"`
	Flags08              Address     `json:"flags_08"`
	OptionalOffset       uint8       `json:"optional_fields_offset"`
	NameAddress          Address     `json:"name_address"`
	Name                 string      `json:"name"`
	OptionalExtra        *Address    `json:"optional_extra,omitempty"`
	OptionalByte         *uint8      `json:"optional_byte,omitempty"`
	Target               *Address    `json:"target,omitempty"`
	Optional0400         *Address    `json:"optional_0400,omitempty"`
	SummaryAddress       *Address    `json:"summary_address,omitempty"`
	Summary              *string     `json:"summary,omitempty"`
	DescriptionAddress   *Address    `json:"description_address,omitempty"`
	Description          *string     `json:"description,omitempty"`
	PropertyVectorOffset Address     `json:"property_vector_offset,omitempty"`
	Parent               *Address    `json:"parent,omitempty"`
	Children             []Reference `json:"children,omitempty"`
	Properties           []Reference `json:"properties,omitempty"`
	ArgumentsFirst       []Reference `json:"arguments_first,omitempty"`
	ArgumentsSecond      []Reference `json:"arguments_second,omitempty"`
	Paths                []string    `json:"paths"`
}

type Metadata struct {
	Input                string         `json:"input"`
	Size                 int            `json:"size"`
	SHA256               string         `json:"sha256"`
	MappingBase          Address        `json:"mapping_base"`
	WordSize             int            `json:"word_size"`
	ByteOrder            string         `json:"byte_order"`
	Compatibility        Address        `json:"build_compatibility_word"`
	WordAsUnixTime       string         `json:"word_as_unix_time"`
	ParserSHA256         string         `json:"parser_sha256"`
	ParserProfile        string         `json:"parser_profile"`
	Root                 Address        `json:"root"`
	HeaderSize           int            `json:"header_size"`
	Layout               string         `json:"layout"`
	HeaderWords          []Address      `json:"header_words"`
	NodeCounts           map[string]int `json:"node_counts"`
	NodesWithPaths       int            `json:"nodes_with_paths"`
	SummaryCount         int            `json:"summary_count"`
	DescriptionCount     int            `json:"description_count"`
	VtableMatchedObjects int            `json:"vtable_matched_objects"`
	StringCandidates     int            `json:"pointer_backed_string_candidates"`
}

type String struct {
	Offset     Address  `json:"offset"`
	Address    Address  `json:"address"`
	References int      `json:"references"`
	Roles      []string `json:"roles"`
	Encoding   string   `json:"encoding"`
	Text       string   `json:"text"`
}

type Image struct {
	Metadata Metadata  `json:"metadata"`
	Nodes    []*Node   `json:"nodes"`
	Strings  []*String `json:"-"`
}

// BaseName accepts only filenames the researched loader treats as a mapping.
// The returned address is also the identity used for duplicate detection.
func BaseName(name string) (uint32, error) {
	if !strings.HasSuffix(name, ".mem") {
		return 0, errors.New("console input must have a numeric .mem filename")
	}
	stem := strings.TrimSuffix(name, ".mem")
	if stem == "" {
		return 0, errors.New("missing decimal console mapping address")
	}
	for _, c := range stem {
		if c < '0' || c > '9' {
			return 0, errors.New("console .mem filename must contain its decimal mapping address")
		}
	}
	base, err := strconv.ParseUint(stem, 10, 32)
	if err != nil || base == 0 || base%4096 != 0 {
		return 0, errors.New("invalid 32-bit console mapping base")
	}
	return uint32(base), nil
}

type reader struct {
	data       []byte
	order      binary.ByteOrder
	base       uint32
	err        error
	nodes      map[uint32]*Node
	strings    map[uint32]*String
	cache      map[uint32]*String
	stringWork int64
	textBytes  int
	references int
}

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format, args...)
	}
}

// Count repeated help and expanded paths too: many small objects can all
// reference one long string, otherwise making JSON output grow quadratically.
func (r *reader) chargeText(n int) {
	if n > maxTextBytes-r.textBytes {
		r.fail("console report text exceeds 16 MiB limit")
		return
	}
	r.textBytes += n
}

func (r *reader) read(offset, size uint64) []byte {
	if offset > uint64(len(r.data)) || size > uint64(len(r.data))-offset {
		r.fail("out-of-bounds console read at %#x, length %#x", offset, size)
		return nil
	}
	return r.data[offset : offset+size]
}

func (r *reader) word(offset uint64) uint32 {
	b := r.read(offset, 4)
	if b == nil {
		return 0
	}
	if r.order == nil {
		return binary.LittleEndian.Uint32(b)
	}
	return r.order.Uint32(b)
}

func (r *reader) offset(address uint32, size uint64) (uint64, bool) {
	if address < r.base || uint64(address-r.base)+size > uint64(len(r.data)) {
		return 0, false
	}
	return uint64(address - r.base), true
}

func printable(raw []byte) (string, string, bool) {
	encoding := "ascii"
	for _, c := range raw {
		if c >= 128 {
			encoding = "utf-8"
			break
		}
	}
	var text string
	if utf8.Valid(raw) {
		text = string(raw)
	} else {
		encoding = "latin-1"
		runes := make([]rune, len(raw))
		for i, c := range raw {
			runes[i] = rune(c)
		}
		text = string(runes)
	}
	for _, c := range text {
		// Match the research decoder's printable Unicode categories, plus
		// the line separators and legacy NBSP actually present in help.
		if !unicode.IsGraphic(c) || (unicode.Is(unicode.Zs, c) && c != ' ' && c != '\u00a0') {
			if c != '\t' && c != '\r' && c != '\n' {
				return "", "", false
			}
		}
	}
	return text, encoding, true
}

func (r *reader) text(address uint32, role string) *String {
	entry, found := r.cache[address]
	if !found {
		if len(r.cache) >= maxStrings {
			r.fail("too many console string candidates")
			return nil
		}
		if offset, valid := r.offset(address, 1); valid {
			end := min(uint64(len(r.data)), offset+maxString)
			window := r.data[offset:end]
			n := bytes.IndexByte(window, 0)
			work := len(window)
			if n >= 0 {
				work = n + 1
			}
			r.stringWork -= int64(work)
			if r.stringWork < 0 {
				r.fail("console string scan work limit exceeded")
				return nil
			}
			if n >= 0 {
				if text, encoding, valid := printable(window[:n]); valid {
					entry = &String{Offset: Address(offset), Address: Address(address), Text: text, Encoding: encoding, Roles: []string{}}
				}
			}
		}
		r.cache[address] = entry
	}
	if role != "" {
		if entry == nil {
			r.fail("invalid console %s string pointer %#x", role, address)
			return nil
		}
		if !contains(entry.Roles, role) {
			entry.Roles = append(entry.Roles, role)
		}
		r.strings[address] = entry
	}
	return entry
}

func contains(list []string, value string) bool {
	for _, s := range list {
		if s == value {
			return true
		}
	}
	return false
}

func (r *reader) vector(offset uint64, stride uint32) []Reference {
	address, size := r.word(offset), r.word(offset+4)
	result := []Reference{}
	if size == 0 || r.err != nil {
		return result
	}
	if size%stride != 0 || address%4 != 0 {
		r.fail("misaligned console vector at %#x", offset)
		return result
	}
	start, ok := r.offset(address, uint64(size))
	if !ok {
		r.fail("console vector at %#x extends outside the image", offset)
		return result
	}
	count := uint64(size / stride)
	if count > uint64(maxReferences-r.references) {
		r.fail("too many console node references")
		return result
	}
	r.references += int(count)
	for pos := start; pos < start+uint64(size); pos += uint64(stride) {
		target := r.word(pos)
		if _, ok := r.nodes[target]; !ok {
			r.fail("unresolved console node %#x in vector at %#x", target, offset)
			break
		}
		entry := Reference{Node: Address(target)}
		if stride == 8 {
			flag := Address(r.word(pos + 4))
			entry.Flags = &flag
		}
		result = append(result, entry)
	}
	return result
}

func Decode(data []byte, base uint32, parser *Parser, source string) (*Image, error) {
	if len(data) < 0x6c {
		return nil, errors.New("truncated console image header")
	}
	if len(data) > MaxInputBytes {
		return nil, errors.New("console image exceeds 64 MiB limit")
	}
	if base == 0 || base%4096 != 0 || uint64(base)+uint64(len(data)) > 1<<32 {
		return nil, errors.New("invalid 32-bit console mapping range")
	}
	if parser == nil {
		return nil, errors.New("a matching console parser is required")
	}
	r := &reader{data: data, base: base, order: parser.order, nodes: map[uint32]*Node{}, strings: map[uint32]*String{}, cache: map[uint32]*String{}, stringWork: min(int64(len(data))*32, 128<<20)}
	stamp := r.word(0)
	headerSize, rootField, stringField := uint64(0x6c), uint64(0x1c), uint64(0x3c)
	root := r.word(rootField)
	rootOffset, ok := r.offset(root, 32)
	if !ok || root%4 != 0 {
		// The earlier header has 20 words; require a valid root and its checked
		// vtable below before using this layout.
		headerSize, rootField, stringField = 0x50, 0x10, 0x28
		root = r.word(rootField)
		rootOffset, ok = r.offset(root, 32)
	}
	if !ok || root%4 != 0 {
		return nil, errors.New("console root pointer is outside the image or unaligned")
	}
	classes, err := parser.nodeClasses(r.word(rootOffset))
	if err != nil {
		return nil, err
	}
	optionalMask, summaryMask, descriptionMask := uint8(4), uint8(8), uint8(16)
	byteMask, extraMask := uint8(0), uint8(0)
	layout := "console32"
	// Header strings provide a checked anchor when fields are inserted before
	// them. Do not interpret arbitrary pointers as header text.
	foundStrings := false
	for _, field := range []uint64{0x28, 0x38, 0x3c} {
		values := []string{"", "yes", "no"}
		valid := true
		for i, want := range values {
			addr := r.word(field + uint64(i)*4)
			o, ok := r.offset(addr, uint64(len(want)+1))
			if !ok || !bytes.Equal(data[o:o+uint64(len(want)+1)], append([]byte(want), 0)) {
				valid = false
				break
			}
		}
		if valid {
			stringField = field
			foundStrings = true
			break
		}
	}
	if !foundStrings {
		return nil, errors.New("unrecognized console header string layout")
	}
	switch stringField {
	case 0x28:
		byteMask = 2
		layout += "/flags-08-legacy"
	case 0x3c:
		layout += "/flags-08"
	case 0x38:
		if kind := parser.accessor(parser.vtables[r.word(rootOffset)][20]); kind == accessorThis || kind == accessorVoid {
			summaryMask, descriptionMask = 16, 32
			byteMask, extraMask = 2, 8
			layout += "/flags-10"
		} else {
			optionalMask, summaryMask, descriptionMask = 2, 4, 8
			layout += "/flags-04"
		}
	}
	// Preserve the known header and subsequent pointer/length extension words.
	headerSize = stringField + 0x28
	for headerSize+4 <= uint64(len(data)) && headerSize < 0x80 {
		v := r.word(headerSize)
		_, ptr := r.offset(v, 0)
		if v > 0x10000 && !ptr {
			break
		}
		headerSize += 4
	}
	byteOrder := "little"
	if parser.order == binary.BigEndian {
		byteOrder = "big"
	}
	image := &Image{Metadata: Metadata{Input: source, Size: len(data), SHA256: hash(data), MappingBase: Address(base), WordSize: 4, ByteOrder: byteOrder, Compatibility: Address(stamp), WordAsUnixTime: time.Unix(int64(stamp), 0).UTC().Format("2006-01-02T15:04:05+00:00"), ParserSHA256: parser.SHA256, ParserProfile: parser.Profile, Root: Address(root), HeaderSize: int(headerSize), Layout: layout, NodeCounts: map[string]int{}}, Nodes: []*Node{}, Strings: []*String{}}
	for offset := uint64(0); offset < headerSize; offset += 4 {
		image.Metadata.HeaderWords = append(image.Metadata.HeaderWords, Address(r.word(offset)))
	}
	for offset := headerSize; offset+4 <= uint64(len(data)) && r.err == nil; offset += 4 {
		vtable := r.word(offset)
		if _, ok := parser.vtables[vtable]; ok {
			image.Metadata.VtableMatchedObjects++
		}
		class, ok := classes[vtable]
		if !ok {
			continue
		}
		if len(image.Nodes) >= maxNodes {
			r.fail("too many console nodes")
			break
		}
		nameAddress := r.word(offset + 12)
		name := r.text(nameAddress, "name")
		if r.err != nil {
			break
		}
		if utf8.RuneCountInString(name.Text) > 256 || strings.ContainsAny(name.Text, "\r\n\t") {
			r.fail("invalid console node name at %#x", offset)
			break
		}
		flags := r.word(offset + 4)
		optionalOffset, optionalFlags := data[offset+4], data[offset+5]
		node := &Node{Address: Address(uint64(base) + offset), Offset: Address(offset), Vtable: Address(vtable), Kind: class.kind, Layout: class.layout, Flags04: Address(flags), Flags08: Address(r.word(offset + 8)), OptionalOffset: optionalOffset, NameAddress: Address(nameAddress), Name: name.Text, Paths: []string{}}
		if optionalFlags&(byteMask|optionalMask|extraMask|summaryMask|descriptionMask) != 0 && optionalOffset < 16 {
			r.fail("invalid console optional-field offset at %#x", offset)
			break
		}
		cursor := offset + uint64(optionalOffset)
		if optionalFlags&byteMask != 0 {
			b := r.read(cursor, 1)
			if b != nil {
				value := b[0]
				node.OptionalByte = &value
			}
			cursor++
		}
		cursor = (cursor + 3) &^ 3
		if optionalFlags&optionalMask != 0 {
			value := Address(r.word(cursor))
			node.Optional0400 = &value
			cursor += 4
		}
		if optionalFlags&extraMask != 0 {
			value := Address(r.word(cursor))
			node.OptionalExtra = &value
			cursor += 4
		}
		for _, field := range []struct {
			bit     uint8
			role    string
			address **Address
			value   **string
		}{{summaryMask, "summary", &node.SummaryAddress, &node.Summary}, {descriptionMask, "description", &node.DescriptionAddress, &node.Description}} {
			if optionalFlags&field.bit == 0 {
				continue
			}
			address := Address(r.word(cursor))
			text := r.text(uint32(address), field.role)
			if text != nil {
				*field.address = &address
				*field.value = &text.Text
			}
			cursor += 4
		}
		if r.err != nil {
			return nil, fmt.Errorf("node %s at %s: %w", node.Name, node.Address, r.err)
		}
		r.nodes[uint32(node.Address)] = node
		r.chargeText(len(node.Name))
		if node.Summary != nil {
			r.chargeText(len(*node.Summary))
		}
		if node.Description != nil {
			r.chargeText(len(*node.Description))
		}
		image.Nodes = append(image.Nodes, node)
	}
	if r.err != nil {
		return nil, r.err
	}
	if n := r.nodes[root]; n == nil || n.Name != "root" || n.Kind != "menu" {
		return nil, errors.New("console image has no valid root menu")
	}
	propertyOffsets, err := r.propertyOffsets(image.Nodes, layout)
	if err != nil {
		return nil, err
	}
	for _, node := range image.Nodes {
		offset := uint64(node.Offset)
		switch node.Kind {
		case "alias":
			a := Address(r.word(offset + 0x10))
			if r.nodes[uint32(a)] == nil {
				r.fail("unresolved console alias target %s", a)
			}
			node.Target = &a
		case "menu":
			node.Children = r.vector(offset+0x10, 4)
			parent := r.word(offset + 0x18)
			if parent != 0 {
				if n := r.nodes[parent]; n == nil || n.Kind != "menu" {
					r.fail("unknown console menu parent %#x", parent)
				}
				a := Address(parent)
				node.Parent = &a
			}
			if node.Layout == "settings" || node.Layout == "item-table" {
				if field := propertyOffsets[node.Vtable]; field != 0 {
					stride := uint32(8)
					if field < 0x60 {
						stride = 4
						node.Layout = "settings"
					} else {
						node.Layout = "item-table"
					}
					node.PropertyVectorOffset = Address(field)
					node.Properties = r.vector(offset+field, stride)
				} else {
					node.Properties = []Reference{}
				}
			}
		case "command":
			node.ArgumentsFirst = r.vector(offset+0x10, 4)
			node.ArgumentsSecond = r.vector(offset+0x18, 4)
		}
		if r.err != nil {
			return nil, fmt.Errorf("node %s at %s (%s): %w", node.Name, node.Address, node.Layout, r.err)
		}
	}
	if err := r.paths(root); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		offset uint64
		name   string
	}{{stringField, "empty"}, {stringField + 4, "yes"}, {stringField + 8, "no"}} {
		r.text(r.word(field.offset), "header:"+field.name)
	}
	for offset := 0; offset+4 <= len(data) && r.err == nil; offset += 4 {
		address := r.word(uint64(offset))
		if _, ok := r.offset(address, 1); !ok {
			continue
		}
		entry := r.text(address, "")
		if entry != nil && (entry.Text != "" || len(entry.Roles) > 0) {
			r.strings[address] = entry
			entry.References++
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	for _, node := range image.Nodes {
		image.Metadata.NodeCounts[node.Kind]++
		if len(node.Paths) > 0 {
			image.Metadata.NodesWithPaths++
		}
		if node.Summary != nil {
			image.Metadata.SummaryCount++
		}
		if node.Description != nil {
			image.Metadata.DescriptionCount++
		}
	}
	for _, entry := range r.strings {
		r.chargeText(len(entry.Text))
		sort.Strings(entry.Roles)
		image.Strings = append(image.Strings, entry)
	}
	if r.err != nil {
		return nil, r.err
	}
	sort.Slice(image.Strings, func(i, j int) bool { return image.Strings[i].Address < image.Strings[j].Address })
	image.Metadata.StringCandidates = len(image.Strings)
	return image, nil
}

func (r *reader) paths(root uint32) error {
	paths := map[uint32]map[string]bool{}
	ancestors := map[uint32]bool{}
	visits, entries := 0, 0
	add := func(address uint32, path string) error {
		if len(path) > maxPathBytes {
			return errors.New("console path exceeds length limit")
		}
		if paths[address] == nil {
			paths[address] = map[string]bool{}
		}
		if !paths[address][path] {
			r.chargeText(len(path))
			if r.err != nil {
				return r.err
			}
			entries++
			if entries > maxReferences {
				return errors.New("too many expanded console paths")
			}
			paths[address][path] = true
		}
		return nil
	}
	var walk func(uint32, string, int) error
	walk = func(address uint32, path string, depth int) error {
		if ancestors[address] || depth >= 64 {
			return errors.New("cycle or excessive depth in console menu hierarchy")
		}
		visits++
		if visits > maxReferences {
			return errors.New("excessive console hierarchy expansion")
		}
		ancestors[address] = true
		defer delete(ancestors, address)
		node := r.nodes[address]
		label := path
		if label == "" {
			label = "/"
		}
		if err := add(address, label); err != nil {
			return err
		}
		if node.Target != nil {
			return walk(uint32(*node.Target), path, depth+1)
		}
		for _, group := range [][]Reference{node.Properties, node.ArgumentsFirst, node.ArgumentsSecond} {
			for _, entry := range group {
				target := uint32(entry.Node)
				if err := add(target, label+" :: "+r.nodes[target].Name); err != nil {
					return err
				}
			}
		}
		for _, entry := range node.Children {
			target := uint32(entry.Node)
			if err := walk(target, path+"/"+r.nodes[target].Name, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		return err
	}
	for address, names := range paths {
		for path := range names {
			r.nodes[address].Paths = append(r.nodes[address].Paths, path)
		}
		sort.Strings(r.nodes[address].Paths)
	}
	return nil
}

// Property-vector fields have moved within settings and item-table classes.
// Check every instance of a vtable against the supported structural layouts.
// Two plausible nonempty layouts are ambiguous; invalid fields cannot become
// empty property lists simply because another candidate contains zeros.
func (r *reader) propertyOffsets(nodes []*Node, layout string) (map[Address]uint64, error) {
	groups := map[Address][]*Node{}
	for _, node := range nodes {
		if node.Layout == "item-table" || node.Layout == "settings" {
			groups[node.Vtable] = append(groups[node.Vtable], node)
		}
	}
	result := map[Address]uint64{}
	work := maxReferences * 8
	for vtable, group := range groups {
		chosen := uint64(0)
		empty := false
		fields := []uint64{0x20, 0x60, 0x68}
		switch layout {
		case "console32/flags-08-legacy":
			fields = []uint64{0x20, 0x64}
		case "console32/flags-10", "console32/flags-04":
			fields = []uint64{0x28, 0x68}
		}
		invalidCandidate := false
		for _, field := range fields {
			stride := uint32(8)
			if field < 0x60 {
				stride = 4
			}
			if (group[0].Layout == "item-table" && field < 0x60) || (group[0].Layout == "settings" && layout != "console32/flags-08-legacy" && field >= 0x60) {
				continue
			}
			valid, nonempty := true, false
			for _, node := range group {
				offset := uint64(node.Offset) + field
				if offset+8 > uint64(len(r.data)) || (node.OptionalOffset != 0 && field+8 > uint64(node.OptionalOffset)) {
					valid = false
					break
				}
				ptr, size := r.word(offset), r.word(offset+4)
				if size == 0 {
					if ptr != 0 {
						if _, ok := r.offset(ptr, 0); !ok {
							valid = false
							break
						}
					}
					continue
				}
				if ptr%4 != 0 || size%stride != 0 || size/stride > maxReferences {
					valid = false
					break
				}
				start, ok := r.offset(ptr, uint64(size))
				if !ok {
					valid = false
					break
				}
				for pos := start; pos < start+uint64(size); pos += uint64(stride) {
					work--
					if work < 0 {
						return nil, errors.New("console property-layout work limit exceeded")
					}
					target := r.nodes[r.word(pos)]
					if target == nil || target.Kind != "parameter" {
						valid = false
						break
					}
				}
				if !valid {
					break
				}
				nonempty = true
			}
			if !valid {
				invalidCandidate = true
				continue
			}
			if !nonempty {
				empty = true
				continue
			}
			if chosen != 0 {
				return nil, fmt.Errorf("ambiguous console property-vector layout for vtable %s", vtable)
			}
			chosen = field
		}
		if chosen == 0 && (!empty || invalidCandidate) {
			return nil, fmt.Errorf("unsupported console property-vector layout for vtable %s", vtable)
		}
		result[vtable] = chosen
	}
	return result, nil
}
