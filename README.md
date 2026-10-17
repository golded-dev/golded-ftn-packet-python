# golded-ftn-packet

Streaming Fidonet Technology Network (FTN) Type-2 (`FTS-0001.016`) and Type-2+ (`FSC-0039.004`, `FSC-0048.002`) packet reader, message decoder, netmail address resolver, and Type-2+ packet writer for Python 3.12+.

## Features

- **Streaming framing (`read_packet`, `open_packet`, `PacketReader`)**: Validates the 58-byte packet header immediately, streams bounded `PacketRecord` items on seekable or non-seekable streams (including short reads), and enforces `0x0000` packet termination followed by physical EOF before marking `reader.is_complete = True`.
- **Conservative Type-2 / Type-2+ capability discrimination**: Distinguishes baseline `FTS-0001.016` (`"type2"`), `FSC-0039.004` masked-MSB (`"fsc39_masked_msb"`), and `FSC-0048.002` exact capability validation (`"exact"`), including `auxNet` origin point sentinel (`0xFFFF`) handling and zone conflict detection.
- **Per-record semantic decoding (`decode_message`, `resolve_netmail_addresses`)**: Strict `1970..2069` two-digit year window, `TZUTC` / `TZUTCINFO` parsing (`-1439..1439` minutes), `CHRS` / `CHARSET` resolution (`FTS-5003.001`), and `INTL` / `FMPT` / `TOPT` netmail address resolution (`FTS-4001.001`).
- **Deterministic serialization (`encode_message`, `write_packet`)**: Emits Type-2+ (`FSC-0048.002`) packet headers and canonical netmail/echomail control paragraphs (`AREA:` always on line 1 for echomail, followed immediately by `TZUTC` and `CHRS`).
- **Confidentiality by construction**: `repr()` of all dataclasses and `str()` / `repr()` of all `PacketError` exceptions expose only structural and numeric metadata, never message text, names, subjects, control values, passwords, or filesystem paths.
