from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from golded_ftn import ControlLine, FtnAddress

from golded_ftn_packet._charsets import validate_decode_options
from golded_ftn_packet.errors import PacketSemanticError

PacketDialect = Literal["type2", "type2_extended"]
ExtensionMatch = Literal["none", "exact", "fsc39_masked_msb"]


@dataclass(frozen=True, slots=True, kw_only=True)
class PacketLimits:
    max_packet_bytes: int = 64 * 1024 * 1024
    max_messages: int = 100_000
    max_message_text_bytes: int = 4 * 1024 * 1024
    max_control_line_bytes: int = 64 * 1024
    max_control_lines: int = 4096

    def __post_init__(self) -> None:
        for attr in (
            "max_packet_bytes",
            "max_messages",
            "max_message_text_bytes",
            "max_control_line_bytes",
            "max_control_lines",
        ):
            if getattr(self, attr) <= 0:
                raise ValueError(f"{attr} must be positive")


@dataclass(frozen=True, slots=True, kw_only=True)
class PacketReadOptions:
    limits: PacketLimits = field(default_factory=PacketLimits)


@dataclass(frozen=True, slots=True, kw_only=True)
class MessageDecodeOptions:
    fallback_charset: str = "CP850"
    ibmpc_charset: str = "CP437"

    def __post_init__(self) -> None:
        validate_decode_options(
            fallback_charset=self.fallback_charset,
            ibmpc_charset=self.ibmpc_charset,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class PacketAddressFields:
    zone: int | None
    net: int
    node: int
    point: int | None = None

    def resolve(
        self,
        *,
        default_zone: int | None = None,
        domain: str | None = None,
    ) -> FtnAddress:
        resolved_zone = self.zone if self.zone is not None else default_zone
        if resolved_zone is None or resolved_zone <= 0:
            raise PacketSemanticError(code="missing_zone_context", field="zone")
        if self.point is None or self.point == 0:
            resolved_point: int | None = None
        elif 1 <= self.point <= 65535:
            resolved_point = self.point
        else:
            raise PacketSemanticError(code="malformed_control", field="point")
        return FtnAddress(
            zone=resolved_zone,
            net=self.net,
            node=self.node,
            point=resolved_point,
            domain=domain,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class PacketHeader:
    raw_bytes: bytes = field(repr=False)
    dialect: PacketDialect
    extension_match: ExtensionMatch
    origin: PacketAddressFields
    destination: PacketAddressFields
    created_at: datetime
    baud: int
    product_id: int
    serial_number: int | None
    revision_major: int | None
    revision_minor: int | None
    password_raw: bytes = field(repr=False)
    capability_raw: int
    validation_copy_raw: int
    capability_effective: int
    product_data_raw: bytes = field(default=b"\x00\x00\x00\x00", repr=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class PackedMessageBytes:
    raw_bytes: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class PacketRecord:
    ordinal: int
    offset: int
    wire: PackedMessageBytes = field(repr=False)
    header_raw: bytes = field(repr=False)
    date_raw: bytes = field(repr=False)
    to_name_raw: bytes = field(repr=False)
    from_name_raw: bytes = field(repr=False)
    subject_raw: bytes = field(repr=False)
    text_raw: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class PacketMessage:
    record: PacketRecord
    from_name: str = field(repr=False)
    to_name: str = field(repr=False)
    subject: str = field(repr=False)
    decoded_text: str = field(repr=False)
    posted_at: datetime
    original_date_text: str = field(repr=False)
    tzutc_minutes: int | None
    encoding: str
    attributes: int
    cost: int
    packed_origin: PacketAddressFields
    packed_destination: PacketAddressFields
    control_lines: tuple[ControlLine, ...] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "control_lines", tuple(self.control_lines))


@dataclass(frozen=True, slots=True, kw_only=True)
class PacketMessageInput:
    from_name: str = field(repr=False)
    to_name: str = field(repr=False)
    subject: str = field(repr=False)
    body_text: str = field(repr=False)
    from_address: FtnAddress
    to_address: FtnAddress
    posted_at: datetime
    tzutc_minutes: int | None = None
    attributes: int = 0
    cost: int = 0
    target_charset: str = "CP850"
    message_class: Literal["netmail", "echomail"] = "netmail"
    area_tag: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PacketHeaderInput:
    origin: FtnAddress
    destination: FtnAddress
    created_at: datetime
    product_id: int
    password: bytes = field(default=b"", repr=False)
    revision_major: int = 0
    revision_minor: int = 0
    baud: int = 0
    product_data: bytes = field(default=b"\x00\x00\x00\x00", repr=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class PacketWriteResult:
    bytes_written: int
    messages_written: int
