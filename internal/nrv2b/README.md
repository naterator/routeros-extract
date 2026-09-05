# NRV2B decoder provenance

`decode.go` is a Go adaptation of these MIT-licensed RetDec sources by
Avast Software, pinned to revision
`9450585772e6f1c18e5f0b2ad5518a18d6bce71e`:

- [Nrv2bData::decompress](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpacker/decompression/nrv/nrv2b_data.cpp)
  (SHA-256 `1ee9bbadf5a6ba79c1ccd33ea95d3ae6d178482c577aa3d2c30e852fe546a4cb`).
- [BitParserLe32](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/include/retdec/unpacker/decompression/nrv/bit_parsers.h)
  (SHA-256 `65f041b4e9ee8de9b759806c1c7bb0d880011ce60c1531f69329423401f9774b`).

Both upstream files explicitly identify their MIT license. The complete
copyright and permission notice is retained in
the RetDec section of the root [LICENSE](../../LICENSE).

The port replaces RetDec's buffer classes with bounded Go slices, shares the
integer-code reader between distance and length decoding, checks complete
32-bit control-word reads, rejects arithmetic overflow and invalid lookbehind
distances, and reports bytes consumed. The caller checks RouterBOOT's exact
output length, CRC32, and trailing padding. No RetDec executable, other RetDec
component, or RetDec dependency is incorporated.

This implementation replaces the earlier UCL/Eric Biederman-derived decoder;
that decoder is not included in this source tree. This is an attributed port
of a permissively licensed implementation, not a claim of clean-room authorship.
