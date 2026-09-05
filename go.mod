module github.com/naterator/routeros-extract

go 1.25.0

require (
	github.com/CalebQ42/squashfs v1.4.1
	github.com/mikelolasagasti/xz v1.0.1
	github.com/spf13/cobra v1.10.2
	golang.org/x/mod v0.40.0
)

require (
	github.com/anchore/go-lzo v0.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.29 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/ulikunitz/xz v0.5.16 // indirect
)

replace github.com/mikelolasagasti/xz => ./third_party/xz

replace github.com/CalebQ42/squashfs => ./third_party/squashfs
