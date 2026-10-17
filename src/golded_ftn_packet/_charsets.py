from __future__ import annotations

from dataclasses import dataclass

from golded_ftn_packet.errors import PacketEncodeError, PacketSemanticError


@dataclass(frozen=True, slots=True, kw_only=True)
class CharsetSpec:
    canonical_codec: str
    ftsc_name: str
    ftsc_level: int
    is_single_byte: bool


_CHARSET_SPECS: dict[str, CharsetSpec] = {
    "ASCII": CharsetSpec(
        canonical_codec="ASCII",
        ftsc_name="ASCII",
        ftsc_level=1,
        is_single_byte=True,
    ),
    "CP437": CharsetSpec(
        canonical_codec="CP437",
        ftsc_name="CP437",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "CP850": CharsetSpec(
        canonical_codec="CP850",
        ftsc_name="CP850",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "CP866": CharsetSpec(
        canonical_codec="CP866",
        ftsc_name="CP866",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "CP1125": CharsetSpec(
        canonical_codec="CP1125",
        ftsc_name="CP1125",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "CP1250": CharsetSpec(
        canonical_codec="CP1250",
        ftsc_name="CP1250",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "CP1251": CharsetSpec(
        canonical_codec="CP1251",
        ftsc_name="CP1251",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "CP1252": CharsetSpec(
        canonical_codec="CP1252",
        ftsc_name="CP1252",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "ISO-8859-1": CharsetSpec(
        canonical_codec="ISO-8859-1",
        ftsc_name="LATIN-1",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "ISO-8859-2": CharsetSpec(
        canonical_codec="ISO-8859-2",
        ftsc_name="LATIN-2",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "KOI8-R": CharsetSpec(
        canonical_codec="KOI8-R",
        ftsc_name="KOI8-R",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "KOI8-U": CharsetSpec(
        canonical_codec="KOI8-U",
        ftsc_name="KOI8-U",
        ftsc_level=2,
        is_single_byte=True,
    ),
    "UTF-8": CharsetSpec(
        canonical_codec="UTF-8",
        ftsc_name="UTF-8",
        ftsc_level=4,
        is_single_byte=False,
    ),
}

_ALIAS_TO_CANONICAL: dict[str, str] = {
    "ASCII": "ASCII",
    "CP437": "CP437",
    "IBM437": "CP437",
    "CP850": "CP850",
    "IBM850": "CP850",
    "CP866": "CP866",
    "IBM866": "CP866",
    "CP1125": "CP1125",
    "CP1250": "CP1250",
    "CP1251": "CP1251",
    "CP1252": "CP1252",
    "ISO-8859-1": "ISO-8859-1",
    "LATIN-1": "ISO-8859-1",
    "LATIN1": "ISO-8859-1",
    "ISO-8859-2": "ISO-8859-2",
    "LATIN-2": "ISO-8859-2",
    "KOI8-R": "KOI8-R",
    "KOI8R": "KOI8-R",
    "KOI8-U": "KOI8-U",
    "KOI8U": "KOI8-U",
    "UTF-8": "UTF-8",
    "UTF8": "UTF-8",
}


def get_charset_spec(canonical_codec: str) -> CharsetSpec:
    return _CHARSET_SPECS[canonical_codec]


def is_valid_chrs_level_token(token: str, *, canonical_codec: str) -> bool:
    if not token.isascii() or not token.isdigit():
        return False
    return int(token) == _CHARSET_SPECS[canonical_codec].ftsc_level


def validate_decode_options(
    *,
    fallback_charset: str,
    ibmpc_charset: str,
) -> None:
    fb_key = fallback_charset.strip().upper()
    if fb_key not in _ALIAS_TO_CANONICAL:
        raise ValueError("Unsupported fallback_charset")

    ibm_key = ibmpc_charset.strip().upper()
    ibm_canonical = _ALIAS_TO_CANONICAL.get(ibm_key)
    if ibm_canonical is None:
        raise ValueError("Unsupported ibmpc_charset")
    ibm_spec = _CHARSET_SPECS[ibm_canonical]
    if not ibm_spec.is_single_byte or ibm_canonical == "ASCII":
        raise ValueError("ibmpc_charset must be an 8-bit single-byte charset")


def resolve_fallback_charset(
    charset: str,
    *,
    message_ordinal: int | None = None,
    offset: int | None = None,
) -> str:
    key = charset.strip().upper()
    canonical = _ALIAS_TO_CANONICAL.get(key)
    if canonical is None:
        raise PacketSemanticError(
            code="unsupported_charset",
            field="fallback_charset",
            message_ordinal=message_ordinal,
            offset=offset,
        )
    return canonical


def resolve_ibmpc_charset(
    charset: str,
    *,
    message_ordinal: int | None = None,
    offset: int | None = None,
) -> str:
    key = charset.strip().upper()
    canonical = _ALIAS_TO_CANONICAL.get(key)
    if canonical is None:
        raise PacketSemanticError(
            code="unsupported_charset",
            field="ibmpc_charset",
            message_ordinal=message_ordinal,
            offset=offset,
        )
    spec = _CHARSET_SPECS[canonical]
    if not spec.is_single_byte or canonical == "ASCII":
        raise PacketSemanticError(
            code="unsupported_charset",
            field="ibmpc_charset",
            message_ordinal=message_ordinal,
            offset=offset,
        )
    return canonical


def resolve_declared_charset(
    token: str,
    *,
    ibmpc_codec: str,
    field: str,
    message_ordinal: int | None = None,
    offset: int | None = None,
) -> str:
    key = token.strip().upper()
    if key == "IBMPC":
        return ibmpc_codec
    canonical = _ALIAS_TO_CANONICAL.get(key)
    if canonical is None:
        raise PacketSemanticError(
            code="unsupported_charset",
            field=field,
            message_ordinal=message_ordinal,
            offset=offset,
        )
    return canonical


def resolve_writer_charset(
    target_charset: str, *, field: str = "target_charset"
) -> CharsetSpec:
    key = target_charset.strip().upper()
    if key == "IBMPC":
        return _CHARSET_SPECS["CP437"]
    canonical = _ALIAS_TO_CANONICAL.get(key)
    if canonical is None:
        raise PacketEncodeError(code="unsupported_charset", field=field)
    return _CHARSET_SPECS[canonical]
