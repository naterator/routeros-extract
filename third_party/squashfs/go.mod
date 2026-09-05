module github.com/CalebQ42/squashfs

go 1.25

require (
	github.com/anchore/go-lzo v0.1.1
	github.com/klauspost/compress v1.20.0
	github.com/mikelolasagasti/xz v1.0.1
	github.com/pierrec/lz4/v4 v4.1.29
	github.com/ulikunitz/xz v0.5.16
)

replace github.com/mikelolasagasti/xz => ../xz
