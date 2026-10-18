# golded-ftn-packet

Version 0.1.0 candidate. Python 3.12–3.14 on Linux and macOS.

## Installation

```sh
python -m pip install golded-ftn-packet==0.1.0
```

The command becomes available after publication. For the unpublished suite, install
all reviewed wheels from the candidate wheelhouse; no sibling checkouts are needed.

## First working example

```python
import io
from datetime import datetime
from golded_ftn import FtnAddress
from golded_ftn_packet import (
    PacketHeaderInput,
    PacketMessageInput,
    encode_message,
    write_packet,
    read_packet,
    decode_message,
)

a = FtnAddress(zone=2, net=999, node=1)
b = FtnAddress(zone=2, net=999, node=2)
message = encode_message(
    PacketMessageInput(
        from_name="Alice",
        to_name="Bob",
        subject="Demo",
        body_text="Hello.\n",
        from_address=a,
        to_address=b,
        posted_at=datetime(2026, 3, 15, 12),
    )
)
stream = io.BytesIO()
# 0x00FE is a synthetic fixture value, never a production product assignment.
write_packet(
    stream,
    header=PacketHeaderInput(
        origin=a,
        destination=b,
        created_at=datetime(2026, 3, 15, 12),
        product_id=0x00FE,
    ),
    messages=[message],
)
reader = read_packet(io.BytesIO(stream.getvalue()))
records = list(reader)
assert reader.is_complete and len(records) == 1
assert "Hello." in decode_message(records[0]).decoded_text
```

## Formats and semantics

Reads bounded Type-2 and Type-2+ packets; writes Type-2+ packets. Type 2.2,
fileecho and archive extraction are outside this package. Stream consumption must
reach the packet terminator and physical EOF before `is_complete` is true. A record
being yielded does not prove the remaining packet is valid.

`decode_message` validates date, charset and controls separately from framing.
`resolve_netmail_addresses` reconciles INTL/FMPT/TOPT with packed addresses.
`encode_message` canonicalizes LF, CRLF and CR to CR wire lines. It does not repair
conflicting controls. `write_packet` requires an explicit product_id; obtain your
production product assignment instead of copying fixture `0x00FE`.

## Errors and recovery

`PacketParseError` means framing failed: do not import a partial packet as complete.
`PacketSemanticError` identifies an invalid record; a caller may quarantine that
record only after validating the whole packet. `PacketEncodeError` rejects invalid
outbound fields. Codes, offsets and ordinals are safe diagnostics; payloads remain
private. The library does not authenticate incoming links or write message bases.

## Public API reference

Signatures below are extracted from the installed candidate wheel. Constructors
are keyword-only where shown. Default enum repr values describe defaults, not
Python source to paste.

### `ExtensionMatch`

```text
ExtensionMatch(*args, **kwargs)
```

### `MessageDecodeOptions`

```text
MessageDecodeOptions(*, fallback_charset: 'str' = 'CP850', ibmpc_charset: 'str' = 'CP437') -> None
```


### `PackedMessageBytes`

```text
PackedMessageBytes(*, raw_bytes: 'bytes') -> None
```


### `PacketAddressFields`

```text
PacketAddressFields(*, zone: 'int | None', net: 'int', node: 'int', point: 'int | None' = None) -> None
```


```text
PacketAddressFields.resolve(self, *, default_zone: 'int | None' = None, domain: 'str | None' = None) -> 'FtnAddress'
```

### `PacketDialect`

```text
PacketDialect(*args, **kwargs)
```

### `PacketEncodeError`

```text
PacketEncodeError(code: 'str', *, offset: 'int | None' = None, message_ordinal: 'int | None' = None, field: 'str | None' = None) -> 'None'
```

### `PacketError`

```text
PacketError(code: 'str', *, offset: 'int | None' = None, message_ordinal: 'int | None' = None, field: 'str | None' = None) -> 'None'
```

### `PacketHeader`

```text
PacketHeader(*, raw_bytes: 'bytes', dialect: 'PacketDialect', extension_match: 'ExtensionMatch', origin: 'PacketAddressFields', destination: 'PacketAddressFields', created_at: 'datetime', baud: 'int', product_id: 'int', serial_number: 'int | None', revision_major: 'int | None', revision_minor: 'int | None', password_raw: 'bytes', capability_raw: 'int', validation_copy_raw: 'int', capability_effective: 'int', product_data_raw: 'bytes' = b'\x00\x00\x00\x00') -> None
```


### `PacketHeaderInput`

```text
PacketHeaderInput(*, origin: 'FtnAddress', destination: 'FtnAddress', created_at: 'datetime', product_id: 'int', password: 'bytes' = b'', revision_major: 'int' = 0, revision_minor: 'int' = 0, baud: 'int' = 0, product_data: 'bytes' = b'\x00\x00\x00\x00') -> None
```


### `PacketLimits`

```text
PacketLimits(*, max_packet_bytes: 'int' = 67108864, max_messages: 'int' = 100000, max_message_text_bytes: 'int' = 4194304, max_control_line_bytes: 'int' = 65536, max_control_lines: 'int' = 4096) -> None
```


### `PacketMessage`

```text
PacketMessage(*, record: 'PacketRecord', from_name: 'str', to_name: 'str', subject: 'str', decoded_text: 'str', posted_at: 'datetime', original_date_text: 'str', tzutc_minutes: 'int | None', encoding: 'str', attributes: 'int', cost: 'int', packed_origin: 'PacketAddressFields', packed_destination: 'PacketAddressFields', control_lines: 'tuple[ControlLine, ...]') -> None
```


### `PacketMessageInput`

```text
PacketMessageInput(*, from_name: 'str', to_name: 'str', subject: 'str', body_text: 'str', from_address: 'FtnAddress', to_address: 'FtnAddress', posted_at: 'datetime', tzutc_minutes: 'int | None' = None, attributes: 'int' = 0, cost: 'int' = 0, target_charset: 'str' = 'CP850', message_class: "Literal['netmail', 'echomail']" = 'netmail', area_tag: 'str | None' = None) -> None
```


### `PacketParseError`

```text
PacketParseError(code: 'str', *, offset: 'int | None' = None, message_ordinal: 'int | None' = None, field: 'str | None' = None) -> 'None'
```

### `PacketReadOptions`

```text
PacketReadOptions(*, limits: 'PacketLimits' = <factory>) -> None
```


### `PacketReader`

```text
PacketReader(stream: 'BinaryIO', *, options: 'PacketReadOptions') -> 'None'
```

Streaming Type-2 / Type-2+ packet reader.

### `PacketRecord`

```text
PacketRecord(*, ordinal: 'int', offset: 'int', wire: 'PackedMessageBytes', header_raw: 'bytes', date_raw: 'bytes', to_name_raw: 'bytes', from_name_raw: 'bytes', subject_raw: 'bytes', text_raw: 'bytes') -> None
```


### `PacketSemanticError`

```text
PacketSemanticError(code: 'str', *, offset: 'int | None' = None, message_ordinal: 'int | None' = None, field: 'str | None' = None) -> 'None'
```

### `PacketWriteResult`

```text
PacketWriteResult(*, bytes_written: 'int', messages_written: 'int') -> None
```


### `decode_message`

```text
decode_message(record: 'PacketRecord', *, options: 'MessageDecodeOptions' = MessageDecodeOptions(fallback_charset='CP850', ibmpc_charset='CP437')) -> 'PacketMessage'
```

### `encode_message`

```text
encode_message(message: 'PacketMessageInput') -> 'PackedMessageBytes'
```

### `open_packet`

```text
open_packet(path: 'str | PathLike[str]', *, options: 'PacketReadOptions' = PacketReadOptions(limits=PacketLimits(max_packet_bytes=67108864, max_messages=100000, max_message_text_bytes=4194304, max_control_line_bytes=65536, max_control_lines=4096))) -> 'Iterator[PacketReader]'
```

### `read_packet`

```text
read_packet(stream: 'BinaryIO', *, options: 'PacketReadOptions' = PacketReadOptions(limits=PacketLimits(max_packet_bytes=67108864, max_messages=100000, max_message_text_bytes=4194304, max_control_line_bytes=65536, max_control_lines=4096))) -> 'PacketReader'
```

### `resolve_netmail_addresses`

```text
resolve_netmail_addresses(message: 'PacketMessage', *, default_zone: 'int | None' = None, domain: 'str | None' = None) -> 'tuple[FtnAddress, FtnAddress]'
```

### `write_packet`

```text
write_packet(stream: 'BinaryIO', *, header: 'PacketHeaderInput', messages: 'Iterable[PackedMessageBytes]', limits: 'PacketLimits' = PacketLimits(max_packet_bytes=67108864, max_messages=100000, max_message_text_bytes=4194304, max_control_line_bytes=65536, max_control_lines=4096)) -> 'PacketWriteResult'
```
