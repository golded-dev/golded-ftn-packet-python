from __future__ import annotations

import re
import struct
from collections.abc import Iterable
from typing import BinaryIO

from golded_ftn import FtnAddress

from golded_ftn_packet._charsets import (
    is_valid_chrs_level_token,
    resolve_declared_charset,
    resolve_writer_charset,
)
from golded_ftn_packet._controls import (
    format_tzutc_value,
    format_wire_datetime,
    is_valid_area_tag,
    parse_control_text,
    parse_intl_value,
    parse_point_value,
    parse_tzutc_value,
    split_text_lines,
)
from golded_ftn_packet.errors import (
    PacketEncodeError,
    PacketParseError,
    PacketSemanticError,
)
from golded_ftn_packet.models import (
    PackedMessageBytes,
    PacketHeaderInput,
    PacketLimits,
    PacketMessageInput,
    PacketWriteResult,
)
from golded_ftn_packet.reader import _frame_record

_HEADER_STRUCT = struct.Struct("<12H2B8s4H2B5H4s")
_MSG_HEADER_STRUCT = struct.Struct("<7H")
_FIRST_LINE_SPLIT_RE = re.compile(r"\r\n|\r|\n")
_DEFAULT_LIMITS = PacketLimits()
_WRITE_LIMIT_CODES = frozenset({"text_limit", "control_limit", "field_too_long"})


def _encode_strict(text: str, codec: str) -> bytes | None:
    encoded: bytes | None = None
    try:
        encoded = text.encode(codec, errors="strict")
    except UnicodeEncodeError:
        pass
    return encoded


def _write_exactly(stream: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = stream.write(view)
        if not written:
            raise OSError("write made no progress")
        view = view[written:]


def _validate_address(addr: FtnAddress, *, field: str) -> None:
    if not (1 <= addr.zone <= 65535):
        raise PacketEncodeError(code="invalid_address", field=field)
    if not (0 <= addr.net <= 65535):
        raise PacketEncodeError(code="invalid_address", field=field)
    if not (0 <= addr.node <= 65535):
        raise PacketEncodeError(code="invalid_address", field=field)
    if addr.point is not None and not (0 <= addr.point <= 65535):
        raise PacketEncodeError(code="invalid_address", field=field)


def _validate_existing_controls(
    lines: list[str],
    *,
    message: PacketMessageInput,
    canonical_codec: str,
) -> tuple[bool, bool, bool, bool, bool]:
    """Validate existing control lines in body_text and return presence flags.

    Returns ``(has_intl, has_fmpt, has_topt, has_tzutc, has_chrs)``.
    """
    has_intl = False
    has_fmpt = False
    has_topt = False
    has_tzutc = False
    has_chrs = False

    seen_tzutc: int | None = None
    seen_chrs_codec: str | None = None
    seen_charset_codec: str | None = None

    orig_pt = message.from_address.point or 0
    dest_pt = message.to_address.point or 0
    expected_dest = (
        message.to_address.zone,
        message.to_address.net,
        message.to_address.node,
    )
    expected_orig = (
        message.from_address.zone,
        message.from_address.net,
        message.from_address.node,
    )

    for line in lines:
        if not line.startswith("\x01"):
            continue
        parsed = parse_control_text(line[1:])
        if parsed is None:
            raise PacketEncodeError(code="malformed_control", field="body_text")
        name, value = parsed

        if name in ("TZUTC", "TZUTCINFO"):
            minutes = parse_tzutc_value(value)
            if minutes is None:
                raise PacketEncodeError(code="malformed_tzutc", field="tzutc_minutes")
            if seen_tzutc is not None and seen_tzutc != minutes:
                raise PacketEncodeError(code="conflicting_tzutc", field="tzutc_minutes")
            if message.tzutc_minutes is not None and minutes != message.tzutc_minutes:
                raise PacketEncodeError(code="conflicting_tzutc", field="tzutc_minutes")
            seen_tzutc = minutes
            if name == "TZUTC":
                has_tzutc = True

        elif name in ("CHRS", "CHARSET"):
            tokens = value.split()
            if not tokens:
                raise PacketEncodeError(code="malformed_control", field=name)
            charset_error: str | None = None
            resolved: str | None = None
            try:
                resolved = resolve_declared_charset(
                    tokens[0],
                    ibmpc_codec="CP437",
                    field=name,
                )
            except PacketSemanticError as exc:
                charset_error = exc.code
            if charset_error is not None or resolved is None:
                raise PacketEncodeError(
                    code=charset_error or "unsupported_charset",
                    field="target_charset",
                )

            if resolved != canonical_codec:
                raise PacketEncodeError(
                    code="conflicting_charset", field="target_charset"
                )
            if (
                name == "CHRS"
                and len(tokens) >= 2
                and not is_valid_chrs_level_token(tokens[1], canonical_codec=resolved)
            ):
                raise PacketEncodeError(
                    code="conflicting_charset", field="target_charset"
                )
            if name == "CHRS":
                if seen_chrs_codec is not None and seen_chrs_codec != resolved:
                    raise PacketEncodeError(
                        code="conflicting_charset", field="target_charset"
                    )
                if seen_charset_codec is not None and seen_charset_codec != resolved:
                    raise PacketEncodeError(
                        code="conflicting_charset", field="target_charset"
                    )
                seen_chrs_codec = resolved
                has_chrs = True
            else:
                if seen_charset_codec is not None and seen_charset_codec != resolved:
                    raise PacketEncodeError(
                        code="conflicting_charset", field="target_charset"
                    )
                if seen_chrs_codec is not None and seen_chrs_codec != resolved:
                    raise PacketEncodeError(
                        code="conflicting_charset", field="target_charset"
                    )
                seen_charset_codec = resolved

        elif name == "INTL":
            parsed_intl = parse_intl_value(value)
            if parsed_intl is None:
                raise PacketEncodeError(code="malformed_control", field="INTL")
            dest_triple, orig_triple = parsed_intl
            if dest_triple != expected_dest or orig_triple != expected_orig:
                raise PacketEncodeError(
                    code="conflicting_address_control", field="INTL"
                )
            has_intl = True

        elif name == "FMPT":
            pt = parse_point_value(value)
            if pt is None:
                raise PacketEncodeError(code="malformed_control", field="FMPT")
            if pt != orig_pt:
                raise PacketEncodeError(
                    code="conflicting_address_control", field="FMPT"
                )
            has_fmpt = True

        elif name == "TOPT":
            pt = parse_point_value(value)
            if pt is None:
                raise PacketEncodeError(code="malformed_control", field="TOPT")
            if pt != dest_pt:
                raise PacketEncodeError(
                    code="conflicting_address_control", field="TOPT"
                )
            has_topt = True

    return has_intl, has_fmpt, has_topt, has_tzutc, has_chrs


def encode_message(message: PacketMessageInput) -> PackedMessageBytes:
    if message.posted_at.tzinfo is not None:
        raise PacketEncodeError(code="naive_datetime_required", field="posted_at")
    if not (1970 <= message.posted_at.year <= 2069):
        raise PacketEncodeError(code="unsupported_message_year", field="posted_at")

    _validate_address(message.from_address, field="from_address")
    _validate_address(message.to_address, field="to_address")

    if not (0 <= message.attributes <= 65535):
        raise PacketEncodeError(code="invalid_field_range", field="attributes")
    if not (0 <= message.cost <= 65535):
        raise PacketEncodeError(code="invalid_field_range", field="cost")

    if message.tzutc_minutes is not None and not (
        -1439 <= message.tzutc_minutes <= 1439
    ):
        raise PacketEncodeError(code="malformed_tzutc", field="tzutc_minutes")

    charset_spec = resolve_writer_charset(
        message.target_charset, field="target_charset"
    )

    for field_name, field_val in (
        ("from_name", message.from_name),
        ("to_name", message.to_name),
        ("subject", message.subject),
        ("body_text", message.body_text),
    ):
        if "\x00" in field_val:
            raise PacketEncodeError(code="embedded_nul", field=field_name)

    body_text = message.body_text
    first_break = _FIRST_LINE_SPLIT_RE.search(body_text)
    if first_break is None:
        first_line = body_text
        remainder_after_first = ""
    else:
        first_line = body_text[: first_break.start()]
        remainder_after_first = body_text[first_break.end() :]

    body_starts_with_area = first_line.startswith("AREA:")

    if message.message_class == "netmail":
        if message.area_tag is not None or body_starts_with_area:
            raise PacketEncodeError(code="unexpected_area_tag", field="area_tag")

        has_intl, has_fmpt, has_topt, has_tzutc, has_chrs = _validate_existing_controls(
            split_text_lines(body_text),
            message=message,
            canonical_codec=charset_spec.canonical_codec,
        )

        prefix_lines: list[str] = []
        if not has_intl:
            dest_3d = (
                f"{message.to_address.zone}:"
                f"{message.to_address.net}/{message.to_address.node}"
            )
            orig_3d = (
                f"{message.from_address.zone}:"
                f"{message.from_address.net}/{message.from_address.node}"
            )
            prefix_lines.append(f"\x01INTL {dest_3d} {orig_3d}\r")
        if message.from_address.point and not has_fmpt:
            prefix_lines.append(f"\x01FMPT {message.from_address.point}\r")
        if message.to_address.point and not has_topt:
            prefix_lines.append(f"\x01TOPT {message.to_address.point}\r")
        if message.tzutc_minutes is not None and not has_tzutc:
            prefix_lines.append(
                f"\x01TZUTC: {format_tzutc_value(message.tzutc_minutes)}\r"
            )
        if not has_chrs:
            prefix_lines.append(
                f"\x01CHRS: {charset_spec.ftsc_name} {charset_spec.ftsc_level}\r"
            )

        assembled_text = "".join(prefix_lines) + body_text

    elif message.message_class == "echomail":
        normalized_param_tag: str | None = None
        if message.area_tag is not None:
            if not is_valid_area_tag(message.area_tag):
                raise PacketEncodeError(code="invalid_area_tag", field="area_tag")
            normalized_param_tag = message.area_tag.upper()

        if body_starts_with_area:
            raw_body_tag = first_line[5:]
            if not is_valid_area_tag(raw_body_tag):
                raise PacketEncodeError(code="invalid_area_tag", field="area_tag")
            normalized_body_tag = raw_body_tag.upper()
            if (
                normalized_param_tag is not None
                and normalized_param_tag != normalized_body_tag
            ):
                raise PacketEncodeError(code="conflicting_area_tag", field="area_tag")
            effective_area_tag = normalized_body_tag
            body_after_area = remainder_after_first
        else:
            if normalized_param_tag is None:
                raise PacketEncodeError(code="missing_area_tag", field="area_tag")
            effective_area_tag = normalized_param_tag
            body_after_area = body_text

        _, _, _, has_tzutc, has_chrs = _validate_existing_controls(
            split_text_lines(body_after_area),
            message=message,
            canonical_codec=charset_spec.canonical_codec,
        )

        inserted_kludges: list[str] = []
        if message.tzutc_minutes is not None and not has_tzutc:
            inserted_kludges.append(
                f"\x01TZUTC: {format_tzutc_value(message.tzutc_minutes)}\r"
            )
        if not has_chrs:
            inserted_kludges.append(
                f"\x01CHRS: {charset_spec.ftsc_name} {charset_spec.ftsc_level}\r"
            )

        assembled_text = (
            f"AREA:{effective_area_tag}\r" + "".join(inserted_kludges) + body_after_area
        )
    else:
        raise PacketEncodeError(code="unsupported_message_class", field="message_class")

    codec = charset_spec.canonical_codec
    to_name_bytes = _encode_strict(message.to_name, codec)
    if to_name_bytes is None:
        raise PacketEncodeError(code="encode_error", field="to_name")

    from_name_bytes = _encode_strict(message.from_name, codec)
    if from_name_bytes is None:
        raise PacketEncodeError(code="encode_error", field="from_name")

    subject_bytes = _encode_strict(message.subject, codec)
    if subject_bytes is None:
        raise PacketEncodeError(code="encode_error", field="subject")

    # Packet wire text uses CR; base readers commonly return LF.
    assembled_text = (
        assembled_text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r")
    )
    text_bytes = _encode_strict(assembled_text, codec)
    if text_bytes is None:
        raise PacketEncodeError(code="encode_error", field="body_text")

    if len(to_name_bytes) > 35:
        raise PacketEncodeError(code="field_too_long", field="to_name")
    if len(from_name_bytes) > 35:
        raise PacketEncodeError(code="field_too_long", field="from_name")
    if len(subject_bytes) > 71:
        raise PacketEncodeError(code="field_too_long", field="subject")

    header_14 = _MSG_HEADER_STRUCT.pack(
        2,
        message.from_address.node,
        message.to_address.node,
        message.from_address.net,
        message.to_address.net,
        message.attributes,
        message.cost,
    )
    date_20 = format_wire_datetime(message.posted_at)

    raw_bytes = (
        header_14
        + date_20
        + to_name_bytes
        + b"\x00"
        + from_name_bytes
        + b"\x00"
        + subject_bytes
        + b"\x00"
        + text_bytes
        + b"\x00"
    )
    return PackedMessageBytes(raw_bytes=raw_bytes)


def _encode_packet_header(header: PacketHeaderInput) -> bytes:
    if header.created_at.tzinfo is not None:
        raise PacketEncodeError(code="naive_datetime_required", field="created_at")
    if not (1000 <= header.created_at.year <= 9999):
        raise PacketEncodeError(code="invalid_header_datetime", field="created_at")

    _validate_address(header.origin, field="origin")
    _validate_address(header.destination, field="destination")

    orig_point = header.origin.point or 0
    dest_point = header.destination.point or 0
    if orig_point > 0 and header.origin.net == 0:
        raise PacketEncodeError(code="ambiguous_point_sentinel", field="origin")

    if not (0 <= header.product_id <= 65535):
        raise PacketEncodeError(code="invalid_product_id", field="product_id")
    if not (0 <= header.revision_major <= 255):
        raise PacketEncodeError(code="invalid_field_range", field="revision_major")
    if not (0 <= header.revision_minor <= 255):
        raise PacketEncodeError(code="invalid_field_range", field="revision_minor")
    if not (0 <= header.baud <= 65535):
        raise PacketEncodeError(code="invalid_field_range", field="baud")

    if len(header.password) > 8 or not all(0x20 <= b <= 0x7E for b in header.password):
        raise PacketEncodeError(code="invalid_password", field="password")
    password_padded = header.password.ljust(8, b"\x00")

    if len(header.product_data) != 4:
        raise PacketEncodeError(code="invalid_product_data", field="product_data")

    if orig_point > 0:
        orig_net = 0xFFFF
        aux_net = header.origin.net
    else:
        orig_net = header.origin.net
        aux_net = 0

    prod_code_lo = header.product_id & 0xFF
    prod_code_hi = (header.product_id >> 8) & 0xFF

    return _HEADER_STRUCT.pack(
        header.origin.node,
        header.destination.node,
        header.created_at.year,
        header.created_at.month - 1,
        header.created_at.day,
        header.created_at.hour,
        header.created_at.minute,
        header.created_at.second,
        header.baud,
        2,  # packetType
        orig_net,
        header.destination.net,
        prod_code_lo,
        header.revision_major,
        password_padded,
        header.origin.zone,
        header.destination.zone,
        aux_net,
        0x0100,  # cwValidationCopy
        prod_code_hi,
        header.revision_minor,
        0x0001,  # capWord
        header.origin.zone,
        header.destination.zone,
        orig_point,
        dest_point,
        header.product_data,
    )


def write_packet(
    stream: BinaryIO,
    *,
    header: PacketHeaderInput,
    messages: Iterable[PackedMessageBytes],
    limits: PacketLimits = _DEFAULT_LIMITS,
) -> PacketWriteResult:
    header_bytes = _encode_packet_header(header)
    if 60 > limits.max_packet_bytes:
        raise PacketEncodeError(code="packet_limit", field="packet")

    buffered_messages: list[bytes] = []
    total_bytes = len(header_bytes) + 2  # include 2-byte 0x0000 terminator

    for idx, msg in enumerate(messages):
        if idx >= limits.max_messages:
            raise PacketEncodeError(
                code="message_limit",
                field="messages",
                message_ordinal=idx,
            )
        raw = msg.raw_bytes
        frame_error: PacketParseError | None = None
        try:
            _frame_record(raw, limits=limits, ordinal=idx, offset=0)
        except PacketParseError as exc:
            frame_error = exc
        if frame_error is not None:
            code = (
                frame_error.code
                if frame_error.code in _WRITE_LIMIT_CODES
                else "invalid_packed_message"
            )
            raise PacketEncodeError(
                code=code,
                field="messages",
                message_ordinal=idx,
                offset=frame_error.offset,
            )
        total_bytes += len(raw)
        if total_bytes > limits.max_packet_bytes:
            raise PacketEncodeError(
                code="packet_limit",
                field="packet",
                message_ordinal=idx,
            )
        buffered_messages.append(raw)

    _write_exactly(stream, header_bytes)
    for raw in buffered_messages:
        _write_exactly(stream, raw)
    _write_exactly(stream, b"\x00\x00")

    return PacketWriteResult(
        bytes_written=total_bytes,
        messages_written=len(buffered_messages),
    )
