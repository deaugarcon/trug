# Changelog

## v0.1.1-alpha — 2026-07-02

- **Notes export includes the decoded note body** (`schema_version: 2`), decoded from the
  backup's note store via a dependency-free gzip + protobuf reader — no new packages.
- Privacy: a locked (password-protected) note's body is withheld as an empty string; a body
  that cannot be decoded is omitted, never guessed. Decode failures never abort an export.
- Inspect preview: folder names truncate at the same 40-character bound as title/snippet.
- Device-verified on iOS 27 (counts-only evidence). 350-test suite.

## v0.1.0-alpha — 2026-07-02

- Initial public alpha: device detection & pairing, local backup (create, list, browse,
  verify, extract, encryption management), inspect & export of messages, contacts, call
  history, and a notes preview as JSON or CSV.
- Privacy invariants P1–P4 (see SECURITY.md); redacted inspect vs. consented full export.
- Homebrew tap install; 325-test suite. Restore not yet supported.
