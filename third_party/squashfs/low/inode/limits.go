package inode

// These limits keep malformed inode fields from turning into unbounded Go
// allocations before the metadata reader can report a truncated record. They
// are deliberately generous compared with normal SquashFS path components
// and the extractor's per-input output limit.
const (
	maxInodeBlockEntries  = 4 << 20
	maxSymlinkTarget      = 1 << 20
	maxDirectoryIndexName = 255
)
