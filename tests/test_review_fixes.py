from __future__ import annotations

import io
import pickle
import struct
import traceback
from datetime import datetime

import pytest
from golded_ftn import FtnAddress

from golded_ftn_packet import (
    MessageDecodeOptions,
    PackedMessageBytes,
    PacketEncodeError,
    PacketError,
    PacketHeaderInput,
    PacketLimits,
    PacketMessageInput,
    PacketParseError,
    PacketSemanticError,
    decode_message,
    encode_message,
    read_packet,
    write_packet,
)

HEADER_STRUCT = struct.Struct("<12H2B8s4H2B5H4s")
MSG_HEADER_STRUCT = struct.Struct("<7H")
PRIVACY_SENTINEL = "ZXQ_UNIQUE_SENTINEL_7b2c9e"


def _pack_raw_header() -> bytes:
    return HEADER_STRUCT.pack(
        42,
        99,
        2026,
        9,
        17,
        12,
        34,
        56,
        0,
        2,
        210,
        210,
        0xFE,
        1,
        b"SECRET\x00\x00",
        2,
        2,
        0,
        0x0100,
        0x00,
        2,
        0x0001,
        2,
        2,
        0,
        0,
        b"TEST",
    )


def _pack_raw_record(
    *,
    to_name: bytes = b"Sysop",
    from_name: bytes = b"User",
    subject: bytes = b"Test Subject",
    text: bytes = b"Hello\r",
    date_raw: bytes = b"17 Oct 26  12:34:56\x00",
) -> bytes:
    header_14 = MSG_HEADER_STRUCT.pack(2, 42, 99, 210, 210, 0, 0)
    return (
        header_14
        + date_raw
        + to_name
        + b"\x00"
        + from_name
        + b"\x00"
        + subject
        + b"\x00"
        + text
        + b"\x00"
    )


def _header_input() -> PacketHeaderInput:
    return PacketHeaderInput(
        origin=FtnAddress(zone=2, net=210, node=42),
        destination=FtnAddress(zone=2, net=210, node=99),
        created_at=datetime(2026, 10, 17, 12, 0, 0),
        product_id=0x00FE,
        password=b"PASSW0RD",
    )


def _message_input(**overrides: object) -> PacketMessageInput:
    values: dict[str, object] = {
        "from_name": "Alice",
        "to_name": "Bob",
        "subject": "Subject",
        "body_text": "Hello\r",
        "from_address": FtnAddress(zone=2, net=210, node=42),
        "to_address": FtnAddress(zone=2, net=210, node=99),
        "posted_at": datetime(2026, 10, 17, 12, 0, 0),
    }
    values.update(overrides)
    return PacketMessageInput(**values)  # type: ignore[arg-type]


def _write(
    messages: list[PackedMessageBytes], *, limits: PacketLimits | None = None
) -> None:
    kwargs: dict[str, object] = {
        "header": _header_input(),
        "messages": messages,
    }
    if limits is not None:
        kwargs["limits"] = limits
    write_packet(io.BytesIO(), **kwargs)  # type: ignore[arg-type]


def _assert_error_hides_sentinel(err: BaseException, sentinel: str) -> None:
    assert sentinel not in str(err)
    assert sentinel not in repr(err)
    assert err.__cause__ is None
    assert err.__context__ is None
    formatted = "".join(traceback.format_exception(err))
    assert sentinel not in formatted


def test_write_packet_rejects_smuggled_packed_records() -> None:
    packed = encode_message(_message_input())
    smuggled = PackedMessageBytes(raw_bytes=packed.raw_bytes + packed.raw_bytes)
    with pytest.raises(PacketEncodeError) as exc_info:
        _write([smuggled])
    assert exc_info.value.code == "invalid_packed_message"

    terminator = packed.raw_bytes.rfind(b"\x00")
    interior_nul = PackedMessageBytes(
        raw_bytes=packed.raw_bytes[:terminator]
        + b"\x00"
        + packed.raw_bytes[terminator:]
    )
    with pytest.raises(PacketEncodeError) as exc_info:
        _write([interior_nul])
    assert exc_info.value.code == "invalid_packed_message"


def test_privacy_sentinel_absent_from_errors_and_traceback() -> None:
    decode_text = b"\x01CHRS: UTF-8 4\r" + PRIVACY_SENTINEL.encode("ascii") + b"\r"
    record = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header()
                + _pack_raw_record(
                    from_name=PRIVACY_SENTINEL.encode("ascii") + b"\xff",
                    subject=PRIVACY_SENTINEL.encode("ascii"),
                    text=decode_text,
                )
                + b"\x00\x00"
            )
        )
    )
    with pytest.raises(PacketSemanticError) as decode_info:
        decode_message(record)
    _assert_error_hides_sentinel(decode_info.value, PRIVACY_SENTINEL)

    non_ascii_token = PRIVACY_SENTINEL.encode("ascii") + bytes([0x80])
    charset_record = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header()
                + _pack_raw_record(
                    text=b"\x01CHRS: " + non_ascii_token + b" 2\rHello\r"
                )
                + b"\x00\x00"
            )
        )
    )
    with pytest.raises(PacketSemanticError) as charset_info:
        decode_message(charset_record)
    _assert_error_hides_sentinel(charset_info.value, PRIVACY_SENTINEL)

    with pytest.raises(PacketEncodeError) as encode_info:
        encode_message(
            _message_input(
                from_name=f"{PRIVACY_SENTINEL}\u00e9",
                to_name=PRIVACY_SENTINEL,
                subject=PRIVACY_SENTINEL,
                body_text=f"{PRIVACY_SENTINEL}\r",
                target_charset="ASCII",
            )
        )
    _assert_error_hides_sentinel(encode_info.value, PRIVACY_SENTINEL)

    header = _header_input()
    packed = encode_message(
        _message_input(
            from_name=PRIVACY_SENTINEL,
            to_name=PRIVACY_SENTINEL,
            subject=PRIVACY_SENTINEL,
            body_text=f"{PRIVACY_SENTINEL}\r",
        )
    )
    for obj in (header, packed):
        assert PRIVACY_SENTINEL not in repr(obj)
        assert "PASSW0RD" not in repr(obj)


def test_chrs_and_charset_must_agree() -> None:
    disagree = b"\x01CHARSET: ASCII\r\x01CHRS: UTF-8 4\rHello\r"
    record = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header() + _pack_raw_record(text=disagree) + b"\x00\x00"
            )
        )
    )
    with pytest.raises(PacketSemanticError) as exc_info:
        decode_message(record)
    assert exc_info.value.code == "conflicting_charset"

    unknown_beside_valid = b"\x01CHRS: CP850 2\r\x01CHARSET: SHIFT-JIS\rHello\r"
    unknown_record = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header()
                + _pack_raw_record(text=unknown_beside_valid)
                + b"\x00\x00"
            )
        )
    )
    with pytest.raises(PacketSemanticError) as exc_info:
        decode_message(unknown_record)
    assert exc_info.value.code == "unsupported_charset"

    with pytest.raises(PacketEncodeError) as encode_info:
        encode_message(
            _message_input(
                body_text="\x01CHRS: CP850 2\r\x01CHARSET: UTF-8\rHello\r",
                target_charset="CP850",
            )
        )
    assert encode_info.value.code == "conflicting_charset"

    with pytest.raises(PacketEncodeError) as level_info:
        encode_message(
            _message_input(
                body_text="\x01CHRS: CP850 4\rHello\r",
                target_charset="CP850",
            )
        )
    assert level_info.value.code == "conflicting_charset"


def test_invalid_area_tag_is_distinct_from_missing() -> None:
    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(_message_input(message_class="echomail", area_tag=""))
    assert exc_info.value.code == "invalid_area_tag"

    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(_message_input(message_class="echomail", area_tag="has space"))
    assert exc_info.value.code == "invalid_area_tag"

    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(
            _message_input(message_class="echomail", body_text="AREA:\rHello\r")
        )
    assert exc_info.value.code == "invalid_area_tag"

    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(
            _message_input(
                message_class="echomail",
                area_tag="FIDO.TEST",
                body_text="AREA:\rHello\r",
            )
        )
    assert exc_info.value.code == "invalid_area_tag"

    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(_message_input(message_class="echomail"))
    assert exc_info.value.code == "missing_area_tag"


def test_netmail_area_prefix_is_case_sensitive() -> None:
    packed = encode_message(_message_input(body_text="Area: local notes\rHello\r"))
    assert packed.raw_bytes.endswith(b"Area: local notes\rHello\r\x00")

    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(_message_input(body_text="AREA:FIDO.TEST\rHello\r"))
    assert exc_info.value.code == "unexpected_area_tag"


def test_packet_error_pickle_round_trip() -> None:
    original = PacketError(
        code="decode_error",
        offset=58,
        message_ordinal=3,
        field="text",
    )
    restored = pickle.loads(pickle.dumps(original))
    assert type(restored) is PacketError
    assert restored.code == "decode_error"
    assert restored.offset == 58
    assert restored.message_ordinal == 3
    assert restored.field == "text"

    parse_err = PacketParseError(
        code="field_too_long",
        offset=70,
        message_ordinal=1,
        field="subject",
    )
    parse_restored = pickle.loads(pickle.dumps(parse_err))
    assert type(parse_restored) is PacketParseError
    assert parse_restored.code == parse_err.code
    assert parse_restored.offset == parse_err.offset
    assert parse_restored.message_ordinal == parse_err.message_ordinal
    assert parse_restored.field == parse_err.field


def test_message_decode_options_validate_charsets() -> None:
    with pytest.raises(ValueError):
        MessageDecodeOptions(fallback_charset="SHIFT-JIS")
    with pytest.raises(ValueError):
        MessageDecodeOptions(ibmpc_charset="UTF-8")
    options = MessageDecodeOptions(fallback_charset="cp850", ibmpc_charset="ibm437")
    assert options.fallback_charset == "cp850"
    assert options.ibmpc_charset == "ibm437"
