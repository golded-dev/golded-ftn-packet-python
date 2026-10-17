from __future__ import annotations

import struct
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from os import PathLike
from typing import BinaryIO

from golded_ftn import ControlLine, FtnAddress

from golded_ftn_packet._charsets import (
    is_valid_chrs_level_token,
    resolve_declared_charset,
    resolve_fallback_charset,
    resolve_ibmpc_charset,
)
from golded_ftn_packet._controls import (
    parse_control_text,
    parse_intl_value,
    parse_point_value,
    parse_tzutc_value,
    parse_wire_datetime,
    split_raw_lines,
    split_text_lines,
)
from golded_ftn_packet.errors import PacketParseError, PacketSemanticError
from golded_ftn_packet.models import (
    ExtensionMatch,
    MessageDecodeOptions,
    PackedMessageBytes,
    PacketAddressFields,
    PacketDialect,
    PacketHeader,
    PacketLimits,
    PacketMessage,
    PacketReadOptions,
    PacketRecord,
)

_HEADER_STRUCT = struct.Struct("<12H2B8s4H2B5H4s")
_MSG_HEADER_STRUCT = struct.Struct("<7H")
_TWO_BYTE_STRUCT = struct.Struct("<H")
_DEFAULT_READ_OPTIONS = PacketReadOptions()
_DEFAULT_DECODE_OPTIONS = MessageDecodeOptions()

TO_NAME_MAX_BYTES = 35
FROM_NAME_MAX_BYTES = 35
SUBJECT_MAX_BYTES = 71
_PACKED_HEADER_BYTES = 14
_PACKED_DATE_BYTES = 20
_PACKED_PREFIX_BYTES = _PACKED_HEADER_BYTES + _PACKED_DATE_BYTES
_MIN_PACKED_MESSAGE_BYTES = _PACKED_PREFIX_BYTES + 4


def _decode_strict(data: bytes, encoding: str) -> str | None:
    decoded: str | None = None
    try:
        decoded = data.decode(encoding, errors="strict")
    except UnicodeDecodeError:
        pass
    return decoded


def _scan_nul_field(
    raw: bytes,
    start: int,
    max_len: int,
    *,
    ordinal: int,
    record_offset: int,
    field: str,
    limit_code: str,
) -> tuple[bytes, int]:
    nul = raw.find(0, start)
    if nul == -1:
        raise PacketParseError(
            code="unterminated_field",
            offset=record_offset + start,
            message_ordinal=ordinal,
            field=field,
        )
    field_len = nul - start
    if field_len > max_len:
        raise PacketParseError(
            code=limit_code,
            offset=record_offset + start,
            message_ordinal=ordinal,
            field=field,
        )
    return raw[start:nul], nul + 1


def _enforce_control_limits(
    text_raw: bytes,
    *,
    limits: PacketLimits,
    ordinal: int,
    text_offset: int,
) -> None:
    control_count = 0
    for raw_line in split_raw_lines(text_raw):
        if raw_line.startswith(b"\x01"):
            control_count += 1
            if control_count > limits.max_control_lines:
                raise PacketParseError(
                    code="control_limit",
                    offset=text_offset,
                    message_ordinal=ordinal,
                    field="control_lines",
                )
            if len(raw_line) - 1 > limits.max_control_line_bytes:
                raise PacketParseError(
                    code="control_limit",
                    offset=text_offset,
                    message_ordinal=ordinal,
                    field="control_line",
                )


def _frame_record(
    raw: bytes,
    *,
    limits: PacketLimits,
    ordinal: int = 0,
    offset: int = 0,
) -> PacketRecord:
    """Parse a complete packed Type-2 message from ``raw``.

    ``raw`` must be exactly one packed record: type word ``02 00``, 12 more
    header bytes, a 20-byte DateTime with a trailing NUL, then exactly four
    NUL-terminated fields after offset 34 and no leftover bytes.
    """
    if len(raw) < _MIN_PACKED_MESSAGE_BYTES:
        raise PacketParseError(
            code="truncated_record",
            offset=offset,
            message_ordinal=ordinal,
            field="header_raw",
        )
    header_raw = raw[:_PACKED_HEADER_BYTES]
    msg_type = _TWO_BYTE_STRUCT.unpack_from(header_raw, 0)[0]
    if msg_type != 2:
        raise PacketParseError(
            code="unsupported_message_type",
            offset=offset,
            message_ordinal=ordinal,
            field="message_type",
        )
    date_raw = raw[_PACKED_HEADER_BYTES:_PACKED_PREFIX_BYTES]
    if date_raw[19] != 0:
        raise PacketParseError(
            code="unterminated_field",
            offset=offset + _PACKED_HEADER_BYTES,
            message_ordinal=ordinal,
            field="date_raw",
        )
    pos = _PACKED_PREFIX_BYTES
    to_name_raw, pos = _scan_nul_field(
        raw,
        pos,
        TO_NAME_MAX_BYTES,
        ordinal=ordinal,
        record_offset=offset,
        field="to_name",
        limit_code="field_too_long",
    )
    from_name_raw, pos = _scan_nul_field(
        raw,
        pos,
        FROM_NAME_MAX_BYTES,
        ordinal=ordinal,
        record_offset=offset,
        field="from_name",
        limit_code="field_too_long",
    )
    subject_raw, pos = _scan_nul_field(
        raw,
        pos,
        SUBJECT_MAX_BYTES,
        ordinal=ordinal,
        record_offset=offset,
        field="subject",
        limit_code="field_too_long",
    )
    text_offset = offset + pos
    text_raw, pos = _scan_nul_field(
        raw,
        pos,
        limits.max_message_text_bytes,
        ordinal=ordinal,
        record_offset=offset,
        field="text",
        limit_code="text_limit",
    )
    if pos != len(raw):
        raise PacketParseError(
            code="trailing_data",
            offset=offset + pos,
            message_ordinal=ordinal,
            field="text",
        )
    _enforce_control_limits(
        text_raw,
        limits=limits,
        ordinal=ordinal,
        text_offset=text_offset,
    )
    return PacketRecord(
        ordinal=ordinal,
        offset=offset,
        wire=PackedMessageBytes(raw_bytes=raw),
        header_raw=header_raw,
        date_raw=date_raw,
        to_name_raw=to_name_raw,
        from_name_raw=from_name_raw,
        subject_raw=subject_raw,
        text_raw=text_raw,
    )


def _parse_packet_header(raw: bytes) -> PacketHeader:
    (
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
        password_raw,
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
    ) = _HEADER_STRUCT.unpack(raw)

    if packet_type != 2:
        raise PacketParseError(
            code="unsupported_packet_type",
            offset=18,
            field="packet_type",
        )

    if (
        not (1 <= year <= 9999)
        or not (0 <= month <= 11)
        or not (1 <= day <= 31)
        or not (0 <= hour <= 23)
        or not (0 <= minute <= 59)
        or not (0 <= second <= 59)
    ):
        raise PacketParseError(
            code="invalid_header_datetime",
            offset=4,
            field="created_at",
        )

    created_at: datetime | None = None
    try:
        created_at = datetime(year, month + 1, day, hour, minute, second)
    except ValueError:
        pass
    if created_at is None:
        raise PacketParseError(
            code="invalid_header_datetime",
            offset=4,
            field="created_at",
        )

    cw = cap_word
    copy = cw_validation_copy
    swapped = ((copy & 0xFF) << 8) | (copy >> 8)

    dialect: PacketDialect
    extension_match: ExtensionMatch
    if cw == swapped and (cw & 1) == 1:
        dialect = "type2_extended"
        extension_match = "exact"
        capability_effective = cw
    elif ((cw & 0x7FFF) == (swapped & 0x7FFF)) and (cw & 1) == 1:
        dialect = "type2_extended"
        extension_match = "fsc39_masked_msb"
        capability_effective = cw & 0x7FFF
    else:
        dialect = "type2"
        extension_match = "none"
        capability_effective = 0

    if dialect == "type2":
        origin = PacketAddressFields(
            zone=q_orig_zone or None,
            net=orig_net,
            node=orig_node,
            point=None,
        )
        destination = PacketAddressFields(
            zone=q_dest_zone or None,
            net=dest_net,
            node=dest_node,
            point=None,
        )
        product_id = prod_code_lo
        serial_number: int | None = serial_or_rev_major
        revision_major: int | None = None
        revision_minor: int | None = None
    else:
        if orig_zone != 0 and q_orig_zone != 0 and orig_zone != q_orig_zone:
            raise PacketParseError(
                code="conflicting_zone_fields",
                offset=34,
                field="origin_zone",
            )
        if dest_zone != 0 and q_dest_zone != 0 and dest_zone != q_dest_zone:
            raise PacketParseError(
                code="conflicting_zone_fields",
                offset=36,
                field="destination_zone",
            )

        resolved_orig_zone = orig_zone or q_orig_zone or None
        resolved_dest_zone = dest_zone or q_dest_zone or None
        resolved_orig_net = orig_net

        if orig_point != 0 and orig_net == 0xFFFF:
            if extension_match == "exact" and aux_net != 0:
                resolved_orig_net = aux_net
            else:
                raise PacketParseError(
                    code="ambiguous_point_sentinel",
                    offset=20,
                    field="origin_net",
                )

        origin = PacketAddressFields(
            zone=resolved_orig_zone,
            net=resolved_orig_net,
            node=orig_node,
            point=orig_point,
        )
        destination = PacketAddressFields(
            zone=resolved_dest_zone,
            net=dest_net,
            node=dest_node,
            point=dest_point,
        )
        product_id = (prod_code_hi << 8) | prod_code_lo
        serial_number = None
        revision_major = serial_or_rev_major
        revision_minor = prod_rev_minor

    return PacketHeader(
        raw_bytes=raw,
        dialect=dialect,
        extension_match=extension_match,
        origin=origin,
        destination=destination,
        created_at=created_at,
        baud=baud,
        product_id=product_id,
        serial_number=serial_number,
        revision_major=revision_major,
        revision_minor=revision_minor,
        password_raw=password_raw,
        capability_raw=cap_word,
        validation_copy_raw=cw_validation_copy,
        capability_effective=capability_effective,
        product_data_raw=prod_data,
    )


class PacketReader(Iterator[PacketRecord]):
    """Streaming Type-2 / Type-2+ packet reader."""

    def __init__(self, stream: BinaryIO, *, options: PacketReadOptions) -> None:
        self._stream = stream
        self._limits: PacketLimits = options.limits
        self._buf = bytearray()
        self._eof = False
        self._offset = 0
        self._ordinal = 0
        self._is_complete = False
        self._failed_error: PacketParseError | None = None

        header_raw = self._read_header_bytes()
        try:
            self._header = _parse_packet_header(header_raw)
        except PacketParseError as exc:
            self._failed_error = exc
            raise

    @property
    def header(self) -> PacketHeader:
        return self._header

    @property
    def is_complete(self) -> bool:
        return self._is_complete

    def __iter__(self) -> Iterator[PacketRecord]:
        return self

    def _fail(self, error: PacketParseError) -> PacketParseError:
        self._failed_error = error
        return error

    def _fill_buffer(self, min_bytes: int) -> None:
        while len(self._buf) < min_bytes and not self._eof:
            max_allowed_buffered = (self._limits.max_packet_bytes + 1) - (
                self._offset + len(self._buf)
            )
            read_size = min(8192, max(1, max_allowed_buffered))
            chunk = self._stream.read(read_size)
            if not chunk:
                self._eof = True
                break
            self._buf.extend(chunk)
            if self._offset + len(self._buf) > self._limits.max_packet_bytes + 1:
                break

    def _consume(
        self,
        n: int,
        *,
        ordinal: int | None = None,
        field: str = "packet",
    ) -> bytes:
        if self._offset + n > self._limits.max_packet_bytes:
            raise self._fail(
                PacketParseError(
                    code="packet_limit",
                    offset=self._limits.max_packet_bytes,
                    message_ordinal=ordinal,
                    field=field,
                )
            )
        data = bytes(self._buf[:n])
        del self._buf[:n]
        self._offset += n
        return data

    def _read_header_bytes(self) -> bytes:
        self._fill_buffer(58)
        if len(self._buf) < 58:
            if self._offset + len(self._buf) > self._limits.max_packet_bytes:
                raise self._fail(
                    PacketParseError(
                        code="packet_limit",
                        offset=self._limits.max_packet_bytes,
                        field="packet",
                    )
                )
            raise self._fail(
                PacketParseError(
                    code="truncated_header",
                    offset=len(self._buf),
                    field="header",
                )
            )
        return self._consume(58, field="header")

    def _read_fixed(
        self,
        n: int,
        *,
        ordinal: int,
        error_offset: int,
        field: str,
    ) -> bytes:
        self._fill_buffer(n)
        if len(self._buf) < n:
            if self._offset + len(self._buf) > self._limits.max_packet_bytes:
                raise self._fail(
                    PacketParseError(
                        code="packet_limit",
                        offset=self._limits.max_packet_bytes,
                        message_ordinal=ordinal,
                        field="packet",
                    )
                )
            raise self._fail(
                PacketParseError(
                    code="truncated_record",
                    offset=error_offset,
                    message_ordinal=ordinal,
                    field=field,
                )
            )
        return self._consume(n, ordinal=ordinal, field=field)

    def _read_cstring(
        self,
        max_len: int,
        *,
        ordinal: int,
        field: str,
        limit_code: str,
    ) -> bytes:
        field_offset = self._offset
        scan_pos = 0
        while True:
            nul_idx = self._buf.find(0, scan_pos)
            if nul_idx != -1:
                if (
                    self._offset + min(nul_idx, max_len) + 1
                    > self._limits.max_packet_bytes
                ):
                    raise self._fail(
                        PacketParseError(
                            code="packet_limit",
                            offset=self._limits.max_packet_bytes,
                            message_ordinal=ordinal,
                            field="packet",
                        )
                    )
                if nul_idx > max_len:
                    raise self._fail(
                        PacketParseError(
                            code=limit_code,
                            offset=field_offset,
                            message_ordinal=ordinal,
                            field=field,
                        )
                    )
                raw_with_nul = self._consume(nul_idx + 1, ordinal=ordinal, field=field)
                return raw_with_nul[:-1]

            scan_pos = len(self._buf)
            if (
                self._offset + min(scan_pos, max_len + 1)
                > self._limits.max_packet_bytes
            ):
                raise self._fail(
                    PacketParseError(
                        code="packet_limit",
                        offset=self._limits.max_packet_bytes,
                        message_ordinal=ordinal,
                        field="packet",
                    )
                )
            if scan_pos > max_len:
                raise self._fail(
                    PacketParseError(
                        code=limit_code,
                        offset=field_offset,
                        message_ordinal=ordinal,
                        field=field,
                    )
                )
            if self._eof:
                raise self._fail(
                    PacketParseError(
                        code="unterminated_field",
                        offset=field_offset,
                        message_ordinal=ordinal,
                        field=field,
                    )
                )
            self._fill_buffer(scan_pos + 1)

    def _check_control_limits(
        self,
        text_raw: bytes,
        *,
        ordinal: int,
        text_offset: int,
    ) -> None:
        try:
            _enforce_control_limits(
                text_raw,
                limits=self._limits,
                ordinal=ordinal,
                text_offset=text_offset,
            )
        except PacketParseError as exc:
            self._failed_error = exc
            raise

    def __next__(self) -> PacketRecord:
        if self._is_complete:
            raise StopIteration
        if self._failed_error is not None:
            raise self._failed_error

        record_offset = self._offset
        self._fill_buffer(2)
        if len(self._buf) == 0:
            raise self._fail(
                PacketParseError(
                    code="missing_packet_terminator",
                    offset=record_offset,
                    field="terminator",
                )
            )
        if len(self._buf) == 1:
            if self._offset + 1 > self._limits.max_packet_bytes:
                raise self._fail(
                    PacketParseError(
                        code="packet_limit",
                        offset=self._limits.max_packet_bytes,
                        field="packet",
                    )
                )
            raise self._fail(
                PacketParseError(
                    code="truncated_record",
                    offset=record_offset,
                    message_ordinal=self._ordinal,
                    field="message_type",
                )
            )

        type_bytes = self._consume(2, ordinal=self._ordinal, field="message_type")
        msg_type = _TWO_BYTE_STRUCT.unpack(type_bytes)[0]

        if msg_type == 0:
            self._fill_buffer(1)
            if len(self._buf) > 0:
                raise self._fail(
                    PacketParseError(
                        code="trailing_data",
                        offset=self._offset,
                        field="packet",
                    )
                )
            self._is_complete = True
            raise StopIteration

        if msg_type != 2:
            raise self._fail(
                PacketParseError(
                    code="unsupported_message_type",
                    offset=record_offset,
                    message_ordinal=self._ordinal,
                    field="message_type",
                )
            )

        ordinal = self._ordinal
        if ordinal >= self._limits.max_messages:
            raise self._fail(
                PacketParseError(
                    code="message_limit",
                    offset=record_offset,
                    message_ordinal=ordinal,
                    field="messages",
                )
            )

        rest_header = self._read_fixed(
            12,
            ordinal=ordinal,
            error_offset=record_offset,
            field="header_raw",
        )
        header_raw = type_bytes + rest_header
        date_raw = self._read_fixed(
            20,
            ordinal=ordinal,
            error_offset=self._offset,
            field="date_raw",
        )
        to_name_raw = self._read_cstring(
            TO_NAME_MAX_BYTES,
            ordinal=ordinal,
            field="to_name",
            limit_code="field_too_long",
        )
        from_name_raw = self._read_cstring(
            FROM_NAME_MAX_BYTES,
            ordinal=ordinal,
            field="from_name",
            limit_code="field_too_long",
        )
        subject_raw = self._read_cstring(
            SUBJECT_MAX_BYTES,
            ordinal=ordinal,
            field="subject",
            limit_code="field_too_long",
        )
        text_offset = self._offset
        text_raw = self._read_cstring(
            self._limits.max_message_text_bytes,
            ordinal=ordinal,
            field="text",
            limit_code="text_limit",
        )
        self._check_control_limits(text_raw, ordinal=ordinal, text_offset=text_offset)

        wire_bytes = (
            header_raw
            + date_raw
            + to_name_raw
            + b"\x00"
            + from_name_raw
            + b"\x00"
            + subject_raw
            + b"\x00"
            + text_raw
            + b"\x00"
        )
        record = PacketRecord(
            ordinal=ordinal,
            offset=record_offset,
            wire=PackedMessageBytes(raw_bytes=wire_bytes),
            header_raw=header_raw,
            date_raw=date_raw,
            to_name_raw=to_name_raw,
            from_name_raw=from_name_raw,
            subject_raw=subject_raw,
            text_raw=text_raw,
        )
        self._ordinal += 1
        return record


def read_packet(
    stream: BinaryIO,
    *,
    options: PacketReadOptions = _DEFAULT_READ_OPTIONS,
) -> PacketReader:
    return PacketReader(stream, options=options)


@contextmanager
def open_packet(
    path: str | PathLike[str],
    *,
    options: PacketReadOptions = _DEFAULT_READ_OPTIONS,
) -> Iterator[PacketReader]:
    with open(path, "rb") as stream:
        yield read_packet(stream, options=options)


def _scan_raw_controls_and_charset(
    text_raw: bytes,
    *,
    options: MessageDecodeOptions,
    ordinal: int,
    offset: int,
) -> str:
    fallback_codec = resolve_fallback_charset(
        options.fallback_charset,
        message_ordinal=ordinal,
        offset=offset,
    )
    ibmpc_codec = resolve_ibmpc_charset(
        options.ibmpc_charset,
        message_ordinal=ordinal,
        offset=offset,
    )

    chrs_codecs: list[str] = []
    charset_codecs: list[str] = []

    for raw_line in split_raw_lines(text_raw):
        if not raw_line.startswith(b"\x01"):
            continue
        body = raw_line[1:]
        if not body:
            raise PacketSemanticError(
                code="malformed_control",
                field="control_lines",
                message_ordinal=ordinal,
                offset=offset,
            )
        for b in body:
            if (b < 0x20 and b != 0x09) or b == 0x7F:
                raise PacketSemanticError(
                    code="malformed_control",
                    field="control_lines",
                    message_ordinal=ordinal,
                    offset=offset,
                )

        # Find delimiter (: or whitespace)
        delim_idx = -1
        delim_is_colon = False
        for idx, b in enumerate(body):
            if b == 0x3A:  # ':'
                delim_idx = idx
                delim_is_colon = True
                break
            if b in (0x20, 0x09):
                delim_idx = idx
                break

        if delim_idx == 0:
            raise PacketSemanticError(
                code="malformed_control",
                field="control_lines",
                message_ordinal=ordinal,
                offset=offset,
            )

        if delim_idx == -1:
            kw_bytes = body
            val_bytes = b""
        else:
            kw_bytes = body[:delim_idx]
            val_bytes = body[delim_idx + 1 :] if delim_is_colon else body[delim_idx:]

        if not kw_bytes or not all(0x21 <= b <= 0x7E and b != 0x3A for b in kw_bytes):
            raise PacketSemanticError(
                code="malformed_control",
                field="control_lines",
                message_ordinal=ordinal,
                offset=offset,
            )

        kw = kw_bytes.decode("ascii").upper()
        if kw in ("CHRS", "CHARSET"):
            tokens = val_bytes.split()
            if not tokens:
                raise PacketSemanticError(
                    code="malformed_control",
                    field=kw,
                    message_ordinal=ordinal,
                    offset=offset,
                )
            token0 = _decode_strict(tokens[0], "ascii")
            if token0 is None:
                raise PacketSemanticError(
                    code="unsupported_charset",
                    field=kw,
                    message_ordinal=ordinal,
                    offset=offset,
                )
            resolved = resolve_declared_charset(
                token0,
                ibmpc_codec=ibmpc_codec,
                field=kw,
                message_ordinal=ordinal,
                offset=offset,
            )
            if kw == "CHRS" and len(tokens) >= 2:
                level_token = _decode_strict(tokens[1], "ascii")
                if level_token is None or not is_valid_chrs_level_token(
                    level_token, canonical_codec=resolved
                ):
                    raise PacketSemanticError(
                        code="conflicting_charset",
                        field="CHRS",
                        message_ordinal=ordinal,
                        offset=offset,
                    )
            if kw == "CHRS":
                chrs_codecs.append(resolved)
            else:
                charset_codecs.append(resolved)

    declared_codecs = chrs_codecs + charset_codecs
    if len(set(declared_codecs)) > 1:
        conflict_field = "CHRS" if chrs_codecs else "CHARSET"
        raise PacketSemanticError(
            code="conflicting_charset",
            field=conflict_field,
            message_ordinal=ordinal,
            offset=offset,
        )
    if declared_codecs:
        return declared_codecs[0]
    return fallback_codec


def decode_message(
    record: PacketRecord,
    *,
    options: MessageDecodeOptions = _DEFAULT_DECODE_OPTIONS,
) -> PacketMessage:
    if len(record.header_raw) != 14:
        raise PacketSemanticError(
            code="malformed_control",
            field="header_raw",
            message_ordinal=record.ordinal,
            offset=record.offset,
        )

    (
        msg_type,
        orig_node,
        dest_node,
        orig_net,
        dest_net,
        attributes,
        cost,
    ) = _MSG_HEADER_STRUCT.unpack(record.header_raw)
    if msg_type != 2:
        raise PacketSemanticError(
            code="malformed_control",
            field="message_type",
            message_ordinal=record.ordinal,
            offset=record.offset,
        )

    parsed_date = parse_wire_datetime(record.date_raw)
    if parsed_date is None:
        raise PacketSemanticError(
            code="invalid_message_datetime",
            field="posted_at",
            message_ordinal=record.ordinal,
            offset=record.offset + 14,
        )
    posted_at, original_date_text = parsed_date

    encoding = _scan_raw_controls_and_charset(
        record.text_raw,
        options=options,
        ordinal=record.ordinal,
        offset=record.offset,
    )

    from_name = _decode_strict(record.from_name_raw, encoding)
    if from_name is None:
        raise PacketSemanticError(
            code="decode_error",
            field="from_name",
            message_ordinal=record.ordinal,
            offset=record.offset,
        )

    to_name = _decode_strict(record.to_name_raw, encoding)
    if to_name is None:
        raise PacketSemanticError(
            code="decode_error",
            field="to_name",
            message_ordinal=record.ordinal,
            offset=record.offset,
        )

    subject = _decode_strict(record.subject_raw, encoding)
    if subject is None:
        raise PacketSemanticError(
            code="decode_error",
            field="subject",
            message_ordinal=record.ordinal,
            offset=record.offset,
        )

    decoded_text = _decode_strict(record.text_raw, encoding)
    if decoded_text is None:
        raise PacketSemanticError(
            code="decode_error",
            field="text",
            message_ordinal=record.ordinal,
            offset=record.offset,
        )

    control_lines: list[ControlLine] = []
    tzutc_minutes: int | None = None

    for line in split_text_lines(decoded_text):
        if not line.startswith("\x01"):
            continue
        raw_without_soh = line[1:]
        parsed_ctrl = parse_control_text(raw_without_soh)
        if parsed_ctrl is None:
            raise PacketSemanticError(
                code="malformed_control",
                field="control_lines",
                message_ordinal=record.ordinal,
                offset=record.offset,
            )
        name, value = parsed_ctrl
        control_lines.append(ControlLine(name=name, value=value, raw=raw_without_soh))

        if name in ("TZUTC", "TZUTCINFO"):
            minutes = parse_tzutc_value(value)
            if minutes is None:
                raise PacketSemanticError(
                    code="malformed_tzutc",
                    field=name,
                    message_ordinal=record.ordinal,
                    offset=record.offset,
                )
            if tzutc_minutes is not None and tzutc_minutes != minutes:
                raise PacketSemanticError(
                    code="conflicting_tzutc",
                    field="tzutc_minutes",
                    message_ordinal=record.ordinal,
                    offset=record.offset,
                )
            tzutc_minutes = minutes

    return PacketMessage(
        record=record,
        from_name=from_name,
        to_name=to_name,
        subject=subject,
        decoded_text=decoded_text,
        posted_at=posted_at,
        original_date_text=original_date_text,
        tzutc_minutes=tzutc_minutes,
        encoding=encoding,
        attributes=attributes,
        cost=cost,
        packed_origin=PacketAddressFields(
            zone=None,
            net=orig_net,
            node=orig_node,
            point=None,
        ),
        packed_destination=PacketAddressFields(
            zone=None,
            net=dest_net,
            node=dest_node,
            point=None,
        ),
        control_lines=tuple(control_lines),
    )


def resolve_netmail_addresses(
    message: PacketMessage,
    *,
    default_zone: int | None = None,
    domain: str | None = None,
) -> tuple[FtnAddress, FtnAddress]:
    ordinal = message.record.ordinal
    offset = message.record.offset

    intl_dest: tuple[int, int, int] | None = None
    intl_orig: tuple[int, int, int] | None = None
    fmpt: int | None = None
    topt: int | None = None

    for cl in message.control_lines:
        key = cl.name.upper()
        if key == "INTL":
            parsed_intl = parse_intl_value(cl.value)
            if parsed_intl is None:
                raise PacketSemanticError(
                    code="malformed_control",
                    field="INTL",
                    message_ordinal=ordinal,
                    offset=offset,
                )
            dest_triple, orig_triple = parsed_intl
            dz, dnet, dnode = dest_triple
            oz, onet, onode = orig_triple

            if (
                dnet != message.packed_destination.net
                or dnode != message.packed_destination.node
                or onet != message.packed_origin.net
                or onode != message.packed_origin.node
            ):
                raise PacketSemanticError(
                    code="conflicting_address_control",
                    field="INTL",
                    message_ordinal=ordinal,
                    offset=offset,
                )

            if intl_dest is not None and (
                intl_dest != dest_triple or intl_orig != orig_triple
            ):
                raise PacketSemanticError(
                    code="conflicting_address_control",
                    field="INTL",
                    message_ordinal=ordinal,
                    offset=offset,
                )
            intl_dest = dest_triple
            intl_orig = orig_triple

        elif key == "FMPT":
            pt = parse_point_value(cl.value)
            if pt is None:
                raise PacketSemanticError(
                    code="malformed_control",
                    field="FMPT",
                    message_ordinal=ordinal,
                    offset=offset,
                )
            if fmpt is not None and fmpt != pt:
                raise PacketSemanticError(
                    code="conflicting_address_control",
                    field="FMPT",
                    message_ordinal=ordinal,
                    offset=offset,
                )
            fmpt = pt

        elif key == "TOPT":
            pt = parse_point_value(cl.value)
            if pt is None:
                raise PacketSemanticError(
                    code="malformed_control",
                    field="TOPT",
                    message_ordinal=ordinal,
                    offset=offset,
                )
            if topt is not None and topt != pt:
                raise PacketSemanticError(
                    code="conflicting_address_control",
                    field="TOPT",
                    message_ordinal=ordinal,
                    offset=offset,
                )
            topt = pt

    orig_fields = PacketAddressFields(
        zone=intl_orig[0] if intl_orig is not None else message.packed_origin.zone,
        net=message.packed_origin.net,
        node=message.packed_origin.node,
        point=fmpt if fmpt is not None else message.packed_origin.point,
    )
    dest_fields = PacketAddressFields(
        zone=intl_dest[0] if intl_dest is not None else message.packed_destination.zone,
        net=message.packed_destination.net,
        node=message.packed_destination.node,
        point=topt if topt is not None else message.packed_destination.point,
    )

    resolve_code: str | None = None
    resolve_field: str | None = None
    try:
        orig_addr = orig_fields.resolve(default_zone=default_zone, domain=domain)
        dest_addr = dest_fields.resolve(default_zone=default_zone, domain=domain)
    except PacketSemanticError as exc:
        resolve_code = exc.code
        resolve_field = exc.field
    else:
        return orig_addr, dest_addr
    raise PacketSemanticError(
        code=resolve_code,
        field=resolve_field,
        message_ordinal=ordinal,
        offset=offset,
    )
