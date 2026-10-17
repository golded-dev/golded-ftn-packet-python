# P1 Handoff Report: `golded-ftn-packet` (`0.1.0`)

## 1. Scope and Contract Compliance

Implemented `golded-ftn-packet` (`0.1.0`, import package `golded_ftn_packet`, `requires-python = ">=3.12"`, runtime dependency `golded-ftn>=1.2.2,<2`) in `/Users/odinn/Projects/golded-dev/golded-ftn-packet-python` according to the amended frozen contract `ftn-node-work/contracts/packet-v1.md`.

This pass applied the Claude P1 review fixes so the package matches that amended contract.

- **Public API** (frozen surface only):
  - Types: `PacketDialect`, `ExtensionMatch`
  - Value classes: `PacketLimits`, `PacketReadOptions`, `MessageDecodeOptions`, `PacketAddressFields`, `PacketHeader`, `PackedMessageBytes`, `PacketRecord`, `PacketMessage`, `PacketMessageInput`, `PacketHeaderInput`, `PacketWriteResult`
  - Exceptions: `PacketError`, `PacketParseError`, `PacketSemanticError`, `PacketEncodeError`
  - Functions & iterators: `PacketReader`, `read_packet`, `open_packet`, `decode_message`, `resolve_netmail_addresses`, `encode_message`, `write_packet`
  - Not exported: `ExtensionMatchKind`, `PackedMessageWire`, `PacketMessageClass`
- **Review fixes applied**:
  - **B2:** `write_packet` re-frames every `PackedMessageBytes` with the shared reader validator `_frame_record` (35/35/71 bounds, `date_raw[19]==0`, exactly four NUL-terminated fields after offset 34, `PacketLimits` text/control caps). Smuggled interior NULs or extra packed records raise `PacketEncodeError(code="invalid_packed_message")`.
  - **B3:** Unicode encode/decode failures are raised outside `except` blocks so `PacketError.__cause__` and `__context__` stay `None`. `PacketError.__reduce__` is unchanged. Payload fields keep `repr=False`.
  - **D1:** `MessageDecodeOptions.__post_init__` validates `fallback_charset` / `ibmpc_charset` via `validate_decode_options` (`ValueError`).
  - **D3/D4:** Reader and writer require every present `CHRS`/`CHARSET` identifier to be recognized and to resolve to the same canonical charset. A present `CHRS` level token must match FTSC level `1`/`2`/`4`. Disagreement is `conflicting_charset`; unknown identifiers are `unsupported_charset`.
  - **D6:** Empty / non-printable `area_tag` (parameter or body) raises `invalid_area_tag`. `missing_area_tag` is only used when echomail has no tag at all.
  - **D7:** Netmail `AREA:` rejection is case-sensitive (`body_text` begins with literal `AREA:`). Prose `Area: ...` is allowed.
  - **D8:** `__all__` matches the frozen public surface.
  - **D12:** Stream writes go through `_write_exactly`, which loops until all bytes are written.

## 2. Verification Commands and Results

All verification commands were executed from `/Users/odinn/Projects/golded-dev/golded-ftn-packet-python`:

```bash
.venv/bin/pytest -q
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy --strict src tests
```

- **Pytest**: `79 passed in 0.15s`
- **Ruff check**: `All checks passed!`
- **Ruff format**: `9 files already formatted`
- **Mypy (`--strict src tests`)**: `Success: no issues found in 9 source files`

sdist/wheel/twine and isolated wheel install were not re-run in this review-fix pass.

## 3. Remaining known gaps

Not in the required review-fix list and left unchanged:

- Non-blocking `stream.read()` returning `None` is still treated as EOF (`truncated_*` / `missing_packet_terminator`).
- A single leftover byte where a type word should be is still `truncated_record`.
- `open_packet` still lets `OSError` through (path may appear in that OS error, not in `PacketError`).
- `FtnAddress` / `ControlLine` assumptions against pinned `golded_ftn` commit `c42a159c…` were not re-verified here.
