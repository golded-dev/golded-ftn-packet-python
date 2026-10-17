from __future__ import annotations

import dataclasses
import io
import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest
from golded_ftn import ControlLine, FtnAddress

import golded_ftn_packet
from golded_ftn_packet import (
    ExtensionMatch,
    MessageDecodeOptions,
    PacketAddressFields,
    PacketDialect,
    PacketEncodeError,
    PacketError,
    PacketHeader,
    PacketHeaderInput,
    PacketLimits,
    PacketMessage,
    PacketMessageInput,
    PacketParseError,
    PacketReadOptions,
    PacketRecord,
    PacketSemanticError,
    PacketWriteResult,
    decode_message,
    encode_message,
    open_packet,
    read_packet,
    resolve_netmail_addresses,
    write_packet,
)

HEADER_STRUCT = struct.Struct("<12H2B8s4H2B5H4s")
MSG_HEADER_STRUCT = struct.Struct("<7H")


def _pack_raw_header(
    *,
    orig_node: int = 42,
    dest_node: int = 99,
    year: int = 2026,
    month: int = 9,  # zero-based October
    day: int = 17,
    hour: int = 12,
    minute: int = 34,
    second: int = 56,
    baud: int = 0,
    packet_type: int = 2,
    orig_net: int = 210,
    dest_net: int = 210,
    prod_code_lo: int = 0xFE,
    serial_or_rev_major: int = 1,
    password: bytes = b"SECRET\x00\x00",
    q_orig_zone: int = 2,
    q_dest_zone: int = 2,
    aux_net: int = 0,
    cw_validation_copy: int = 0x0100,
    prod_code_hi: int = 0x00,
    prod_rev_minor: int = 2,
    cap_word: int = 0x0001,
    orig_zone: int = 2,
    dest_zone: int = 2,
    orig_point: int = 0,
    dest_point: int = 0,
    prod_data: bytes = b"TEST",
) -> bytes:
    return HEADER_STRUCT.pack(
        orig_node,
        dest_node,
        year,
        month,
        day,
        hour,
        minute,
        second,
        baud,
        packet_type,
        orig_net,
        dest_net,
        prod_code_lo,
        serial_or_rev_major,
        password,
        q_orig_zone,
        q_dest_zone,
        aux_net,
        cw_validation_copy,
        prod_code_hi,
        prod_rev_minor,
        cap_word,
        orig_zone,
        dest_zone,
        orig_point,
        dest_point,
        prod_data,
    )


def _pack_raw_record(
    *,
    msg_type: int = 2,
    orig_node: int = 42,
    dest_node: int = 99,
    orig_net: int = 210,
    dest_net: int = 210,
    attributes: int = 0x0001,
    cost: int = 0,
    date_raw: bytes = b"17 Oct 26  12:34:56\x00",
    to_name: bytes = b"Sysop",
    from_name: bytes = b"User",
    subject: bytes = b"Test Subject",
    text: bytes = b"\x01CHRS: CP850 2\rHello FTN!\r",
) -> bytes:
    header_14 = MSG_HEADER_STRUCT.pack(
        msg_type,
        orig_node,
        dest_node,
        orig_net,
        dest_net,
        attributes,
        cost,
    )
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


class ShortReadNonSeekableStream(io.RawIOBase):
    """Non-seekable binary stream yielding at most ``step`` bytes per read."""

    def __init__(self, data: bytes, *, step: int = 2) -> None:
        self._data = data
        self._pos = 0
        self._step = step

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def seek(self, offset: int, whence: int = 0) -> int:
        raise OSError("Stream is not seekable")

    def tell(self) -> int:
        raise OSError("Stream is not seekable")

    def read(self, size: int = -1) -> bytes:
        if self._pos >= len(self._data):
            return b""
        limit = self._step if size < 0 else min(size, self._step)
        chunk = self._data[self._pos : self._pos + limit]
        self._pos += len(chunk)
        return chunk


def test_public_surface_matches_contract() -> None:
    assert "ExtensionMatch" in golded_ftn_packet.__all__
    assert "PackedMessageBytes" in golded_ftn_packet.__all__
    assert "ExtensionMatchKind" not in golded_ftn_packet.__all__
    assert "PackedMessageWire" not in golded_ftn_packet.__all__
    assert "PacketMessageClass" not in golded_ftn_packet.__all__
    dialect: PacketDialect = "type2_extended"
    match: ExtensionMatch = "exact"
    assert dialect == "type2_extended"
    assert match == "exact"


def test_header_p0_baseline_type2_and_literal_ffff_orig_net() -> None:
    raw_header = _pack_raw_header(
        orig_node=15,
        dest_node=30,
        orig_net=0xFFFF,
        dest_net=210,
        prod_code_lo=0x12,
        serial_or_rev_major=7,
        q_orig_zone=2,
        q_dest_zone=0,
        aux_net=210,
        cw_validation_copy=0x0000,
        prod_code_hi=0x34,
        prod_rev_minor=9,
        cap_word=0x0000,
        orig_zone=99,
        dest_zone=99,
        orig_point=5,
        dest_point=6,
    )
    reader = read_packet(io.BytesIO(raw_header + b"\x00\x00"))
    hdr = reader.header
    assert hdr.dialect == "type2"
    assert hdr.extension_match == "none"
    assert hdr.capability_effective == 0
    assert hdr.product_id == 0x12
    assert hdr.serial_number == 7
    assert hdr.revision_major is None
    assert hdr.revision_minor is None
    assert hdr.origin == PacketAddressFields(zone=2, net=65535, node=15, point=None)
    assert hdr.destination == PacketAddressFields(
        zone=None, net=210, node=30, point=None
    )
    assert list(reader) == []
    assert reader.is_complete is True


def test_header_p39_masked_msb_discrimination() -> None:
    # capWord has MSB set (0x8001), validation copy is byte-swapped 0x0001 -> 0x0100
    raw_header = _pack_raw_header(
        cap_word=0x8001,
        cw_validation_copy=0x0100,
        prod_code_lo=0xFE,
        prod_code_hi=0x01,
        serial_or_rev_major=3,
        prod_rev_minor=4,
        orig_zone=2,
        q_orig_zone=0,
        dest_zone=0,
        q_dest_zone=2,
        orig_point=1,
        dest_point=2,
    )
    reader = read_packet(io.BytesIO(raw_header + b"\x00\x00"))
    hdr = reader.header
    assert hdr.dialect == "type2_extended"
    assert hdr.extension_match == "fsc39_masked_msb"
    assert hdr.capability_raw == 0x8001
    assert hdr.validation_copy_raw == 0x0100
    assert hdr.capability_effective == 0x0001
    assert hdr.product_id == 0x01FE
    assert hdr.serial_number is None
    assert hdr.revision_major == 3
    assert hdr.revision_minor == 4
    assert hdr.origin == PacketAddressFields(zone=2, net=210, node=42, point=1)
    assert hdr.destination == PacketAddressFields(zone=2, net=210, node=99, point=2)


def test_header_p48_exact_and_point_sentinel_aux_net() -> None:
    raw_header = _pack_raw_header(
        cap_word=0x0001,
        cw_validation_copy=0x0100,
        orig_net=0xFFFF,
        aux_net=210,
        orig_point=3,
        dest_point=0,
    )
    reader = read_packet(io.BytesIO(raw_header + b"\x00\x00"))
    hdr = reader.header
    assert hdr.dialect == "type2_extended"
    assert hdr.extension_match == "exact"
    assert hdr.origin == PacketAddressFields(zone=2, net=210, node=42, point=3)
    assert hdr.origin.resolve() == FtnAddress(zone=2, net=210, node=42, point=3)
    assert hdr.destination.resolve() == FtnAddress(zone=2, net=210, node=99, point=None)


@pytest.mark.parametrize(
    ("cap_word", "cw_copy", "aux_net"),
    [
        (0x0001, 0x0100, 0),  # exact match, but auxNet == 0
        (0x8001, 0x0100, 210),  # fsc39_masked_msb match, even with auxNet != 0
    ],
)
def test_header_point_sentinel_ambiguous_raises(
    cap_word: int,
    cw_copy: int,
    aux_net: int,
) -> None:
    raw_header = _pack_raw_header(
        cap_word=cap_word,
        cw_validation_copy=cw_copy,
        orig_net=0xFFFF,
        aux_net=aux_net,
        orig_point=2,
    )
    with pytest.raises(PacketParseError) as exc_info:
        read_packet(io.BytesIO(raw_header + b"\x00\x00"))
    assert exc_info.value.code == "ambiguous_point_sentinel"
    assert exc_info.value.field == "origin_net"
    assert exc_info.value.offset == 20


def test_header_conflicting_zone_fields() -> None:
    raw_orig_conflict = _pack_raw_header(orig_zone=2, q_orig_zone=1)
    with pytest.raises(PacketParseError) as exc_info:
        read_packet(io.BytesIO(raw_orig_conflict + b"\x00\x00"))
    assert exc_info.value.code == "conflicting_zone_fields"
    assert exc_info.value.field == "origin_zone"
    assert exc_info.value.offset == 34

    raw_dest_conflict = _pack_raw_header(dest_zone=3, q_dest_zone=4)
    with pytest.raises(PacketParseError) as exc_info:
        read_packet(io.BytesIO(raw_dest_conflict + b"\x00\x00"))
    assert exc_info.value.code == "conflicting_zone_fields"
    assert exc_info.value.field == "destination_zone"
    assert exc_info.value.offset == 36


def test_header_framing_errors() -> None:
    with pytest.raises(PacketParseError) as exc_info:
        read_packet(io.BytesIO(b"\x00" * 57))
    assert exc_info.value.code == "truncated_header"

    bad_type = _pack_raw_header(packet_type=1)
    with pytest.raises(PacketParseError) as exc_info:
        read_packet(io.BytesIO(bad_type + b"\x00\x00"))
    assert exc_info.value.code == "unsupported_packet_type"
    assert exc_info.value.offset == 18

    bad_month = _pack_raw_header(month=12)  # zero-based month must be 0..11
    with pytest.raises(PacketParseError) as exc_info:
        read_packet(io.BytesIO(bad_month + b"\x00\x00"))
    assert exc_info.value.code == "invalid_header_datetime"

    bad_feb = _pack_raw_header(year=2025, month=1, day=29)
    with pytest.raises(PacketParseError) as exc_info:
        read_packet(io.BytesIO(bad_feb + b"\x00\x00"))
    assert exc_info.value.code == "invalid_header_datetime"


def test_address_fields_resolve() -> None:
    fields = PacketAddressFields(zone=None, net=210, node=42, point=0)
    with pytest.raises(PacketSemanticError) as exc_info:
        fields.resolve()
    assert exc_info.value.code == "missing_zone_context"

    with pytest.raises(PacketSemanticError) as exc_info:
        fields.resolve(default_zone=0)
    assert exc_info.value.code == "missing_zone_context"

    resolved = fields.resolve(default_zone=2, domain="fidonet")
    assert resolved == FtnAddress(
        zone=2, net=210, node=42, point=None, domain="fidonet"
    )


@pytest.mark.parametrize("step", [1, 2, 3, 7])
def test_short_read_non_seekable_stream_and_completeness(step: int) -> None:
    rec1 = _pack_raw_record(subject=b"First")
    rec2 = _pack_raw_record(subject=b"Second")
    packet_bytes = _pack_raw_header() + rec1 + rec2 + b"\x00\x00"

    stream = ShortReadNonSeekableStream(packet_bytes, step=step)
    reader = read_packet(stream)  # type: ignore[arg-type]
    assert reader.is_complete is False

    r0 = next(reader)
    assert r0.ordinal == 0
    assert r0.offset == 58
    assert r0.subject_raw == b"First"
    assert reader.is_complete is False

    r1 = next(reader)
    assert r1.ordinal == 1
    assert r1.offset == 58 + len(rec1)
    assert r1.subject_raw == b"Second"
    assert reader.is_complete is False

    with pytest.raises(StopIteration):
        next(reader)
    assert reader.is_complete is True


def test_trailing_data_and_missing_terminator(tmp_path: Path) -> None:
    rec = _pack_raw_record()
    trailing_pkt = _pack_raw_header() + rec + b"\x00\x00\x99"
    reader = read_packet(io.BytesIO(trailing_pkt))
    _ = next(reader)
    with pytest.raises(PacketParseError) as exc_info:
        next(reader)
    assert exc_info.value.code == "trailing_data"
    assert reader.is_complete is False

    missing_term_pkt = _pack_raw_header() + rec
    reader2 = read_packet(io.BytesIO(missing_term_pkt))
    _ = next(reader2)
    with pytest.raises(PacketParseError) as exc_info:
        next(reader2)
    assert exc_info.value.code == "missing_packet_terminator"
    assert reader2.is_complete is False

    half_term_pkt = _pack_raw_header() + rec + b"\x00"
    reader3 = read_packet(io.BytesIO(half_term_pkt))
    _ = next(reader3)
    with pytest.raises(PacketParseError) as exc_info:
        next(reader3)
    assert exc_info.value.code == "truncated_record"
    assert reader3.is_complete is False

    # Test open_packet helper
    pkt_path = tmp_path / "valid.pkt"
    pkt_path.write_bytes(_pack_raw_header() + rec + b"\x00\x00")
    with open_packet(pkt_path) as file_reader:
        records = list(file_reader)
        assert len(records) == 1
        assert file_reader.is_complete is True


def test_string_byte_bounds_35_36_and_71_72() -> None:
    # Exact maximum lengths: to_name=35, from_name=35, subject=71
    ok_rec = _pack_raw_record(
        to_name=b"T" * 35,
        from_name=b"F" * 35,
        subject=b"S" * 71,
    )
    reader = read_packet(io.BytesIO(_pack_raw_header() + ok_rec + b"\x00\x00"))
    records = list(reader)
    assert len(records) == 1
    assert len(records[0].to_name_raw) == 35
    assert len(records[0].from_name_raw) == 35
    assert len(records[0].subject_raw) == 71
    assert reader.is_complete is True

    # 36 bytes in to_name -> field_too_long
    bad_to = _pack_raw_record(to_name=b"T" * 36)
    r_to = read_packet(io.BytesIO(_pack_raw_header() + bad_to + b"\x00\x00"))
    with pytest.raises(PacketParseError) as exc_info:
        next(r_to)
    assert exc_info.value.code == "field_too_long"
    assert exc_info.value.field == "to_name"

    # 36 bytes in from_name -> field_too_long
    bad_from = _pack_raw_record(from_name=b"F" * 36)
    r_from = read_packet(io.BytesIO(_pack_raw_header() + bad_from + b"\x00\x00"))
    with pytest.raises(PacketParseError) as exc_info:
        next(r_from)
    assert exc_info.value.code == "field_too_long"
    assert exc_info.value.field == "from_name"

    # 72 bytes in subject -> field_too_long
    bad_subj = _pack_raw_record(subject=b"S" * 72)
    r_subj = read_packet(io.BytesIO(_pack_raw_header() + bad_subj + b"\x00\x00"))
    with pytest.raises(PacketParseError) as exc_info:
        next(r_subj)
    assert exc_info.value.code == "field_too_long"
    assert exc_info.value.field == "subject"


def test_limits_enforcement() -> None:
    rec = _pack_raw_record(text=b"\x01A: 123456\r\x01B: 123456\rBody\r")
    pkt = _pack_raw_header() + rec + rec + b"\x00\x00"

    # max_messages
    r_msg = read_packet(
        io.BytesIO(pkt),
        options=PacketReadOptions(limits=PacketLimits(max_messages=1)),
    )
    _ = next(r_msg)
    with pytest.raises(PacketParseError) as exc_info:
        next(r_msg)
    assert exc_info.value.code == "message_limit"

    # max_packet_bytes
    r_pkt = read_packet(
        io.BytesIO(pkt),
        options=PacketReadOptions(limits=PacketLimits(max_packet_bytes=70)),
    )
    with pytest.raises(PacketParseError) as exc_info:
        next(r_pkt)
    assert exc_info.value.code == "packet_limit"

    # max_message_text_bytes
    r_txt = read_packet(
        io.BytesIO(pkt),
        options=PacketReadOptions(limits=PacketLimits(max_message_text_bytes=5)),
    )
    with pytest.raises(PacketParseError) as exc_info:
        next(r_txt)
    assert exc_info.value.code == "text_limit"

    # max_control_lines
    r_ctrl_count = read_packet(
        io.BytesIO(pkt),
        options=PacketReadOptions(limits=PacketLimits(max_control_lines=1)),
    )
    with pytest.raises(PacketParseError) as exc_info:
        next(r_ctrl_count)
    assert exc_info.value.code == "control_limit"

    # max_control_line_bytes
    r_ctrl_len = read_packet(
        io.BytesIO(pkt),
        options=PacketReadOptions(limits=PacketLimits(max_control_line_bytes=4)),
    )
    with pytest.raises(PacketParseError) as exc_info:
        next(r_ctrl_len)
    assert exc_info.value.code == "control_limit"


@pytest.mark.parametrize(
    ("date_raw", "expected_dt"),
    [
        (b"01 Jan 70  00:00:00\x00", datetime(1970, 1, 1, 0, 0, 0)),
        (b"31 Dec 99  23:59:59\x00", datetime(1999, 12, 31, 23, 59, 59)),
        (b"01 Jan 00  00:00:00\x00", datetime(2000, 1, 1, 0, 0, 0)),
        (b"31 Dec 69  23:59:59\x00", datetime(2069, 12, 31, 23, 59, 59)),
        (b" 5 Mar 26  08:09:10\x00", datetime(2026, 3, 5, 8, 9, 10)),
        (b"29 Feb 24  12:00:00\x00", datetime(2024, 2, 29, 12, 0, 0)),
    ],
)
def test_decode_message_date_window_and_leading_space(
    date_raw: bytes,
    expected_dt: datetime,
) -> None:
    raw = _pack_raw_header() + _pack_raw_record(date_raw=date_raw) + b"\x00\x00"
    record = next(read_packet(io.BytesIO(raw)))
    msg = decode_message(record)
    assert msg.posted_at == expected_dt
    assert msg.original_date_text == date_raw[:19].decode("ascii")


@pytest.mark.parametrize(
    "bad_date_raw",
    [
        b"00 Jan 26  12:00:00\x00",
        b"32 Jan 26  12:00:00\x00",
        b"29 Feb 25  12:00:00\x00",
        b"17 Oct 26 12:34:56 \x00",  # single space before time
        b"17 OCT 26  12:34:56\x00",  # wrong month case
        b"17 Oct 26  24:00:00\x00",
        b"17 Oct 26  12:60:00\x00",
        b"17 Oct 26  12:00:60\x00",
        b"17 Oct 26  12:00:00!",  # not NUL-terminated
        b"17 Oct\x0026  12:00:00\x00",  # embedded NUL
    ],
)
def test_decode_message_invalid_datetime(bad_date_raw: bytes) -> None:
    raw = _pack_raw_header() + _pack_raw_record(date_raw=bad_date_raw) + b"\x00\x00"
    record = next(read_packet(io.BytesIO(raw)))
    with pytest.raises(PacketSemanticError) as exc_info:
        decode_message(record)
    assert exc_info.value.code == "invalid_message_datetime"


@pytest.mark.parametrize(
    ("tz_line", "expected_minutes"),
    [
        (b"\x01TZUTC: +0200\r", 120),
        (b"\x01TZUTC: 0200\r", 120),
        (b"\x01TZUTC: -0330\r", -210),
        (b"\x01TZUTC: 0000\r", 0),
        (b"\x01TZUTC: -0000\r", 0),
        (b"\x01TZUTC: 1345\r", 825),  # > 12h valid per FTS-4008 (< 24h)
        (b"\x01TZUTC: -2359\r", -1439),
        (b"\x01TZUTCINFO: +0200\r\x01TZUTC: 0200\r", 120),
    ],
)
def test_decode_message_tzutc_variants(tz_line: bytes, expected_minutes: int) -> None:
    raw = _pack_raw_header() + _pack_raw_record(text=tz_line + b"Body\r") + b"\x00\x00"
    record = next(read_packet(io.BytesIO(raw)))
    msg = decode_message(record)
    assert msg.tzutc_minutes == expected_minutes


def test_decode_message_tzutc_errors() -> None:
    for bad_tz in (
        b"\x01TZUTC: 2400\r",
        b"\x01TZUTC: 0260\r",
        b"\x01TZUTC: +200\r",
        b"\x01TZUTC:\r",
    ):
        raw = _pack_raw_header() + _pack_raw_record(text=bad_tz) + b"\x00\x00"
        record = next(read_packet(io.BytesIO(raw)))
        with pytest.raises(PacketSemanticError) as exc_info:
            decode_message(record)
        assert exc_info.value.code == "malformed_tzutc"

    conflict_tz = b"\x01TZUTC: 0200\r\x01TZUTCINFO: -0500\r"
    record = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header() + _pack_raw_record(text=conflict_tz) + b"\x00\x00"
            )
        )
    )
    with pytest.raises(PacketSemanticError) as exc_info:
        decode_message(record)
    assert exc_info.value.code == "conflicting_tzutc"


def test_decode_message_chrs_charset_precedence_and_ibmpc() -> None:
    # Agreeing CHRS and CHARSET declarations resolve to the same codec
    text = "\x01CHARSET: UTF-8\r\x01CHRS: UTF-8 4\rSmørrebrød\r".encode()
    record = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header()
                + _pack_raw_record(from_name="Søren".encode(), text=text)
                + b"\x00\x00"
            )
        )
    )
    msg = decode_message(record)
    assert msg.encoding == "UTF-8"
    assert msg.from_name == "Søren"
    assert "Smørrebrød" in msg.decoded_text
    assert (
        ControlLine(name="CHRS", value="UTF-8 4", raw="CHRS: UTF-8 4")
        in msg.control_lines
    )

    # IBMPC maps to options.ibmpc_charset (default CP437, configurable e.g. CP866)
    cyrillic_word = "Привет"
    ibmpc_text = b"\x01CHRS: IBMPC 2\r" + cyrillic_word.encode("cp866") + b"\r"
    rec_ibmpc = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header() + _pack_raw_record(text=ibmpc_text) + b"\x00\x00"
            )
        )
    )
    msg_cp866 = decode_message(
        rec_ibmpc,
        options=MessageDecodeOptions(ibmpc_charset="CP866"),
    )
    assert msg_cp866.encoding == "CP866"
    assert cyrillic_word in msg_cp866.decoded_text

    # Contradictory CHRS lines raise conflicting_charset
    conflict_chrs = b"\x01CHRS: CP850 2\r\x01CHRS: UTF-8 4\rHello\r"
    rec_conflict = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header() + _pack_raw_record(text=conflict_chrs) + b"\x00\x00"
            )
        )
    )
    with pytest.raises(PacketSemanticError) as exc_info:
        decode_message(rec_conflict)
    assert exc_info.value.code == "conflicting_charset"

    # Unknown declared charset raises unsupported_charset without fallback
    unknown_chrs = b"\x01CHRS: SHIFT-JIS 2\rHello\r"
    rec_unknown = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header() + _pack_raw_record(text=unknown_chrs) + b"\x00\x00"
            )
        )
    )
    with pytest.raises(PacketSemanticError) as exc_info:
        decode_message(rec_unknown)
    assert exc_info.value.code == "unsupported_charset"

    # Strict decode error on invalid UTF-8 byte sequence
    bad_utf8 = b"\x01CHRS: UTF-8 4\r\xff\xfe\r"
    rec_bad_utf8 = next(
        read_packet(
            io.BytesIO(
                _pack_raw_header() + _pack_raw_record(text=bad_utf8) + b"\x00\x00"
            )
        )
    )
    with pytest.raises(PacketSemanticError) as exc_info:
        decode_message(rec_bad_utf8)
    assert exc_info.value.code == "decode_error"


def test_resolve_netmail_addresses_transit_and_conflicts() -> None:
    # Packet header is hub 2:210/1 -> 2:210/2, while netmail is 1:100/10.5 -> 3:300/20.9
    pkt_hdr = _pack_raw_header(
        orig_zone=2, orig_net=210, orig_node=1, dest_zone=2, dest_net=210, dest_node=2
    )
    netmail_rec = _pack_raw_record(
        orig_net=100,
        orig_node=10,
        dest_net=300,
        dest_node=20,
        text=(
            b"\x01INTL 3:300/20 1:100/10\r"
            b"\x01FMPT 5\r"
            b"\x01TOPT 9\r"
            b"\x01CHRS: CP850 2\r"
            b"Transit netmail body\r"
        ),
    )
    reader = read_packet(io.BytesIO(pkt_hdr + netmail_rec + b"\x00\x00"))
    assert reader.header.origin.resolve() == FtnAddress(zone=2, net=210, node=1)
    assert reader.header.destination.resolve() == FtnAddress(zone=2, net=210, node=2)

    msg = decode_message(next(reader))
    orig_addr, dest_addr = resolve_netmail_addresses(msg, domain="fidonet")
    assert orig_addr == FtnAddress(zone=1, net=100, node=10, point=5, domain="fidonet")
    assert dest_addr == FtnAddress(zone=3, net=300, node=20, point=9, domain="fidonet")

    # Mismatched INTL net/node vs packed header raises conflicting_address_control
    mismatch_rec = _pack_raw_record(
        orig_net=100,
        orig_node=10,
        dest_net=300,
        dest_node=20,
        text=b"\x01INTL 3:999/20 1:100/10\rBody\r",
    )
    msg_mismatch = decode_message(
        next(read_packet(io.BytesIO(pkt_hdr + mismatch_rec + b"\x00\x00")))
    )
    with pytest.raises(PacketSemanticError) as exc_info:
        resolve_netmail_addresses(msg_mismatch)
    assert exc_info.value.code == "conflicting_address_control"


def test_semantic_error_isolation_across_sibling_records() -> None:
    rec0 = _pack_raw_record(
        subject=b"Valid 0", text=b"\x01CHRS: ASCII 1\rFirst valid\r"
    )
    rec1_bad = _pack_raw_record(
        subject=b"Bad 1",
        date_raw=b"99 Bad 99  99:99:99\x00",
        text=b"\x01CHRS: UNKNOWN 2\rBroken middle record\r",
    )
    rec2 = _pack_raw_record(
        subject=b"Valid 2", text=b"\x01CHRS: ASCII 1\rThird valid\r"
    )

    reader = read_packet(
        io.BytesIO(_pack_raw_header() + rec0 + rec1_bad + rec2 + b"\x00\x00")
    )
    records = list(reader)
    assert len(records) == 3
    assert reader.is_complete is True

    msg0 = decode_message(records[0])
    assert msg0.subject == "Valid 0"

    with pytest.raises(PacketSemanticError) as exc_info:
        decode_message(records[1])
    assert exc_info.value.code == "invalid_message_datetime"
    assert exc_info.value.message_ordinal == 1
    assert records[1].wire.raw_bytes == rec1_bad

    msg2 = decode_message(records[2])
    assert msg2.subject == "Valid 2"


def test_encode_message_netmail_and_echomail_area_line_placement() -> None:
    # Echomail without AREA: in body_text emits AREA:<AREA_TAG>\r on line 1,
    # followed immediately by TZUTC and CHRS before existing kludges/body
    echo_input = PacketMessageInput(
        from_name="Alice",
        to_name="All",
        subject="Echo test",
        body_text="\x01MSGID: 2:210/42.1 12345678\rHello echo!\r",
        from_address=FtnAddress(zone=2, net=210, node=42, point=1),
        to_address=FtnAddress(zone=2, net=210, node=1),
        posted_at=datetime(2026, 10, 17, 14, 0, 0),
        tzutc_minutes=-210,
        target_charset="latin-1",
        message_class="echomail",
        area_tag="fido.test",
    )
    packed_echo = encode_message(echo_input)

    # Netmail with point addresses
    net_input = PacketMessageInput(
        from_name="Alice",
        to_name="Bob",
        subject="Netmail test",
        body_text="Private netmail\r",
        from_address=FtnAddress(zone=2, net=210, node=42, point=3),
        to_address=FtnAddress(zone=1, net=100, node=20, point=7),
        posted_at=datetime(2026, 10, 17, 14, 5, 0),
        tzutc_minutes=120,
        target_charset="utf8",
        message_class="netmail",
    )
    packed_net = encode_message(net_input)

    out_buf = io.BytesIO()
    hdr_in = PacketHeaderInput(
        origin=FtnAddress(zone=2, net=210, node=42, point=3),
        destination=FtnAddress(zone=2, net=210, node=1),
        created_at=datetime(2026, 10, 17, 14, 10, 0),
        product_id=0x00FE,
        password=b"PASS123",
        revision_major=1,
        revision_minor=0,
    )
    write_res: PacketWriteResult = write_packet(
        out_buf,
        header=hdr_in,
        messages=[packed_echo, packed_net],
    )
    assert write_res.messages_written == 2
    assert write_res.bytes_written == len(out_buf.getvalue())

    out_buf.seek(0)
    reader = read_packet(out_buf)
    assert reader.header.dialect == "type2_extended"
    assert reader.header.extension_match == "exact"
    assert reader.header.origin.resolve() == FtnAddress(
        zone=2, net=210, node=42, point=3
    )
    assert struct.unpack_from("<H", reader.header.raw_bytes, 20)[0] == 0xFFFF
    assert struct.unpack_from("<H", reader.header.raw_bytes, 38)[0] == 210

    records = list(reader)
    assert reader.is_complete is True
    assert len(records) == 2

    decoded_echo = decode_message(records[0])
    echo_lines = decoded_echo.decoded_text.split("\r")
    assert echo_lines[0] == "AREA:FIDO.TEST"
    assert echo_lines[1] == "\x01TZUTC: -0330"
    assert echo_lines[2] == "\x01CHRS: LATIN-1 2"
    assert echo_lines[3] == "\x01MSGID: 2:210/42.1 12345678"
    assert echo_lines[4] == "Hello echo!"
    assert decoded_echo.encoding == "ISO-8859-1"
    assert decoded_echo.tzutc_minutes == -210

    decoded_net = decode_message(records[1])
    assert decoded_net.encoding == "UTF-8"
    assert decoded_net.tzutc_minutes == 120
    orig_resolved, dest_resolved = resolve_netmail_addresses(decoded_net)
    assert orig_resolved == FtnAddress(zone=2, net=210, node=42, point=3)
    assert dest_resolved == FtnAddress(zone=1, net=100, node=20, point=7)


def test_encode_message_validation_errors() -> None:
    base_input = PacketMessageInput(
        from_name="Alice",
        to_name="Bob",
        subject="Subj",
        body_text="Body\r",
        from_address=FtnAddress(zone=2, net=210, node=42),
        to_address=FtnAddress(zone=2, net=210, node=99),
        posted_at=datetime(2026, 10, 17, 12, 0, 0),
    )

    # Aware datetime rejected
    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(
            dataclasses.replace(
                base_input,
                posted_at=datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC),
            )
        )
    assert exc_info.value.code == "naive_datetime_required"
    assert exc_info.value.field == "posted_at"

    # Year outside 1970..2069 rejected
    for bad_year in (1969, 2070):
        with pytest.raises(PacketEncodeError) as exc_info:
            encode_message(
                dataclasses.replace(
                    base_input,
                    posted_at=datetime(bad_year, 1, 1, 0, 0, 0),
                )
            )
        assert exc_info.value.code == "unsupported_message_year"
        assert exc_info.value.field == "posted_at"

    # Unmapped target_charset rejected
    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(dataclasses.replace(base_input, target_charset="SHIFT-JIS"))
    assert exc_info.value.code == "unsupported_charset"
    assert exc_info.value.field == "target_charset"

    # Netmail with area_tag or leading AREA: rejected
    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(dataclasses.replace(base_input, area_tag="FIDO.TEST"))
    assert exc_info.value.code == "unexpected_area_tag"

    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(
            dataclasses.replace(base_input, body_text="AREA:FIDO.TEST\rHello\r")
        )
    assert exc_info.value.code == "unexpected_area_tag"

    # Echomail missing area_tag and conflicting area_tag
    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(dataclasses.replace(base_input, message_class="echomail"))
    assert exc_info.value.code == "missing_area_tag"

    with pytest.raises(PacketEncodeError) as exc_info:
        encode_message(
            dataclasses.replace(
                base_input,
                message_class="echomail",
                area_tag="OTHER.AREA",
                body_text="AREA:FIDO.TEST\rHello\r",
            )
        )
    assert exc_info.value.code == "conflicting_area_tag"


def test_confidentiality_sentinel_privacy() -> None:
    sentinels = (
        "SENTINEL_FROM_USER",
        "SENTINEL_TO_USER",
        "SENTINEL_SUBJECT_LINE",
        "SENTINEL_BODY_SECRET",
        "SENTINEL_CTRL_VALUE",
        "PASSW0RD",
        "PROD",
        "/secret/filesystem/path.pkt",
    )

    msg_in = PacketMessageInput(
        from_name="SENTINEL_FROM_USER",
        to_name="SENTINEL_TO_USER",
        subject="SENTINEL_SUBJECT_LINE",
        body_text="\x01NOTE: SENTINEL_CTRL_VALUE\rSENTINEL_BODY_SECRET\r",
        from_address=FtnAddress(zone=2, net=210, node=42),
        to_address=FtnAddress(zone=2, net=210, node=99),
        posted_at=datetime(2026, 10, 17, 12, 0, 0),
    )
    hdr_in = PacketHeaderInput(
        origin=FtnAddress(zone=2, net=210, node=42),
        destination=FtnAddress(zone=2, net=210, node=99),
        created_at=datetime(2026, 10, 17, 12, 0, 0),
        product_id=0x00FE,
        password=b"PASSW0RD",
        product_data=b"PROD",
    )

    packed = encode_message(msg_in)
    buf = io.BytesIO()
    write_packet(buf, header=hdr_in, messages=[packed])
    buf.seek(0)
    reader = read_packet(buf)
    header: PacketHeader = reader.header
    record: PacketRecord = next(reader)
    decoded: PacketMessage = decode_message(record)

    objects_to_check: list[object] = [
        msg_in,
        hdr_in,
        packed,
        header,
        record,
        decoded,
        PacketParseError(
            code="field_too_long", offset=58, message_ordinal=0, field="subject"
        ),
        PacketSemanticError(
            code="decode_error", offset=58, message_ordinal=0, field="text"
        ),
        PacketEncodeError(code="invalid_password", field="password"),
    ]

    for obj in objects_to_check:
        text_repr = repr(obj)
        text_str = str(obj)
        for sentinel in sentinels:
            assert sentinel not in text_repr
            assert sentinel not in text_str

    for err in objects_to_check[-3:]:
        assert isinstance(err, PacketError)
        for sentinel in sentinels:
            assert sentinel not in repr(err)
            assert sentinel not in str(err)


@pytest.mark.parametrize(
    ("alias", "expected_codec", "expected_ftsc"),
    [
        ("ASCII", "ASCII", "ASCII 1"),
        ("CP437", "CP437", "CP437 2"),
        ("IBM437", "CP437", "CP437 2"),
        ("IBMPC", "CP437", "CP437 2"),
        ("CP850", "CP850", "CP850 2"),
        ("IBM850", "CP850", "CP850 2"),
        ("CP866", "CP866", "CP866 2"),
        ("IBM866", "CP866", "CP866 2"),
        ("CP1125", "CP1125", "CP1125 2"),
        ("CP1250", "CP1250", "CP1250 2"),
        ("CP1251", "CP1251", "CP1251 2"),
        ("CP1252", "CP1252", "CP1252 2"),
        ("ISO-8859-1", "ISO-8859-1", "LATIN-1 2"),
        ("LATIN-1", "ISO-8859-1", "LATIN-1 2"),
        ("LATIN1", "ISO-8859-1", "LATIN-1 2"),
        ("ISO-8859-2", "ISO-8859-2", "LATIN-2 2"),
        ("LATIN-2", "ISO-8859-2", "LATIN-2 2"),
        ("KOI8-R", "KOI8-R", "KOI8-R 2"),
        ("KOI8R", "KOI8-R", "KOI8-R 2"),
        ("KOI8-U", "KOI8-U", "KOI8-U 2"),
        ("KOI8U", "KOI8-U", "KOI8-U 2"),
        ("UTF-8", "UTF-8", "UTF-8 4"),
        ("UTF8", "UTF-8", "UTF-8 4"),
    ],
)
def test_all_ftsc_charset_mappings(
    alias: str,
    expected_codec: str,
    expected_ftsc: str,
) -> None:
    packed = encode_message(
        PacketMessageInput(
            from_name="Sender",
            to_name="Receiver",
            subject="Charset Check",
            body_text="Hello\r",
            from_address=FtnAddress(zone=2, net=210, node=42),
            to_address=FtnAddress(zone=2, net=210, node=99),
            posted_at=datetime(2026, 10, 17, 12, 0, 0),
            target_charset=alias,
        )
    )
    buf = io.BytesIO()
    write_packet(
        buf,
        header=PacketHeaderInput(
            origin=FtnAddress(zone=2, net=210, node=42),
            destination=FtnAddress(zone=2, net=210, node=99),
            created_at=datetime(2026, 10, 17, 12, 0, 0),
            product_id=0x00FE,
        ),
        messages=[packed],
    )
    buf.seek(0)
    reader = read_packet(buf)
    msg = decode_message(next(reader))
    assert msg.encoding == expected_codec
    assert (
        ControlLine(name="CHRS", value=expected_ftsc, raw=f"CHRS: {expected_ftsc}")
        in msg.control_lines
    )


def test_unterminated_fields_and_unsupported_record_type() -> None:
    hdr = _pack_raw_header()
    msg_hdr_and_date = (
        MSG_HEADER_STRUCT.pack(2, 42, 99, 210, 210, 0, 0) + b"17 Oct 26  12:34:56\x00"
    )

    # Unterminated to_name
    r1 = read_packet(io.BytesIO(hdr + msg_hdr_and_date + b"NoNulTo"))
    with pytest.raises(PacketParseError) as exc_info:
        next(r1)
    assert exc_info.value.code == "unterminated_field"
    assert exc_info.value.field == "to_name"

    # Unterminated from_name
    r2 = read_packet(io.BytesIO(hdr + msg_hdr_and_date + b"To\x00NoNulFrom"))
    with pytest.raises(PacketParseError) as exc_info:
        next(r2)
    assert exc_info.value.code == "unterminated_field"
    assert exc_info.value.field == "from_name"

    # Unterminated subject
    r3 = read_packet(io.BytesIO(hdr + msg_hdr_and_date + b"To\x00From\x00NoNulSubj"))
    with pytest.raises(PacketParseError) as exc_info:
        next(r3)
    assert exc_info.value.code == "unterminated_field"
    assert exc_info.value.field == "subject"

    # Unterminated text
    r4 = read_packet(
        io.BytesIO(hdr + msg_hdr_and_date + b"To\x00From\x00Subj\x00NoNulText")
    )
    with pytest.raises(PacketParseError) as exc_info:
        next(r4)
    assert exc_info.value.code == "unterminated_field"
    assert exc_info.value.field == "text"

    # Unsupported message type word (0x0003)
    r5 = read_packet(io.BytesIO(hdr + struct.pack("<H", 3) + b"\x00\x00"))
    with pytest.raises(PacketParseError) as exc_info:
        next(r5)
    assert exc_info.value.code == "unsupported_message_type"


def test_malformed_controls_and_duplicate_address_controls() -> None:
    for bad_ctrl in (
        b"\x01\rBody\r",
        b"\x01   \rBody\r",
        b"\x01:bad\rBody\r",
        b"\x01CHRS:\rBody\r",
    ):
        rec = next(
            read_packet(
                io.BytesIO(
                    _pack_raw_header() + _pack_raw_record(text=bad_ctrl) + b"\x00\x00"
                )
            )
        )
        with pytest.raises(PacketSemanticError) as exc_info:
            decode_message(rec)
        assert exc_info.value.code == "malformed_control"

    for bad_net_ctrl in (
        b"\x01INTL broken\r",
        b"\x01INTL 2:210/99 2:210/42\r\x01FMPT abc\r",
        b"\x01INTL 2:210/99 2:210/42\r\x01TOPT 0\r",
    ):
        rec = next(
            read_packet(
                io.BytesIO(
                    _pack_raw_header()
                    + _pack_raw_record(text=bad_net_ctrl)
                    + b"\x00\x00"
                )
            )
        )
        msg = decode_message(rec)
        with pytest.raises(PacketSemanticError) as exc_info:
            resolve_netmail_addresses(msg)
        assert exc_info.value.code == "malformed_control"

    for dup_net_ctrl in (
        b"\x01INTL 2:210/99 2:210/42\r\x01INTL 3:210/99 2:210/42\r",
        b"\x01INTL 2:210/99 2:210/42\r\x01FMPT 1\r\x01FMPT 2\r",
        b"\x01INTL 2:210/99 2:210/42\r\x01TOPT 1\r\x01TOPT 2\r",
    ):
        rec = next(
            read_packet(
                io.BytesIO(
                    _pack_raw_header()
                    + _pack_raw_record(text=dup_net_ctrl)
                    + b"\x00\x00"
                )
            )
        )
        msg = decode_message(rec)
        with pytest.raises(PacketSemanticError) as exc_info:
            resolve_netmail_addresses(msg)
        assert exc_info.value.code == "conflicting_address_control"
