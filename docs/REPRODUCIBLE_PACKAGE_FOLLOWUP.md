# Reproducible Distribution Package Follow-up

This item is deliberately separate from the secure Owner Dashboard release.
Semantic package parity is already accepted for the current gate; byte parity
is not.

## Audit evidence

- Local archive: 1,187,248 bytes
- Local SHA-256:
  `BBE1D6CEED45AB22D1F80363518E6B6AE9CFA3CB3FA3AEF34870163ACC2D7AF7`
- Railway archive: 1,188,501 bytes
- Railway SHA-256:
  `24AB016A547DA6C16F411AB17ABD8ACF787FCF7861E37ABEFC0A9FDB6C9FBFD4`
- Both archives contain 478 entries.
- Missing/additional entries: zero.
- After CRLF-to-LF normalization, semantic content differences: zero.
- Raw differences: 107 newline-only files plus ZIP timestamp metadata.

## Follow-up acceptance criteria

1. Normalize manifest source files to an explicit archive newline policy.
2. Write every ZIP entry with a fixed timestamp, permissions, ordering, and
   compression settings.
3. Build twice on Windows and twice in the Railway Linux image.
4. Require all four archive SHA-256 values to match.
5. Preserve the manifest endpoint and download checksum headers added by the
   secure Owner Dashboard branch.
