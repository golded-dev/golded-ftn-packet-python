from __future__ import annotations

import re
from datetime import datetime

MONTH_NAMES: tuple[str, ...] = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)
_MONTH_TO_INT: dict[str, int] = {name: idx + 1 for idx, name in enumerate(MONTH_NAMES)}

_DATETIME_RE = re.compile(
    rb"^(?:([0-3][0-9])| ([1-9])) "
    rb"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    rb"([0-9]{2})  ([0-2][0-9]):([0-5][0-9]):([0-5][0-9])$"
)

_TZUTC_RE = re.compile(r"^([+-]?)([0-9]{2})([0-9]{2})$")
_CONTROL_SPLIT_RE = re.compile(r"^([^\s:]+)(?::\s*|\s+)(.*)$")
_CONTROL_BARE_RE = re.compile(r"^([^\s:]+)$")
_INTL_RE = re.compile(r"^([0-9]+):([0-9]+)/([0-9]+)\s+([0-9]+):([0-9]+)/([0-9]+)$")
_POINT_RE = re.compile(r"^([0-9]+)$")


def parse_wire_datetime(date_raw: bytes) -> tuple[datetime, str] | None:
    if len(date_raw) != 20 or date_raw[19] != 0:
        return None
    body = date_raw[:19]
    if b"\x00" in body:
        return None
    match = _DATETIME_RE.match(body)
    if match is None:
        return None
    day_two, day_spaced, mon_bytes, yy_bytes, hh_bytes, mm_bytes, ss_bytes = (
        match.groups()
    )
    day = int(day_two if day_two is not None else day_spaced)
    month = _MONTH_TO_INT[mon_bytes.decode("ascii")]
    yy = int(yy_bytes)
    year = 1900 + yy if yy >= 70 else 2000 + yy
    hour = int(hh_bytes)
    minute = int(mm_bytes)
    second = int(ss_bytes)
    if hour > 23 or minute > 59 or second > 59:
        return None
    try:
        dt = datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None
    return dt, body.decode("ascii")


def format_wire_datetime(dt: datetime) -> bytes:
    month_name = MONTH_NAMES[dt.month - 1]
    yy = dt.year % 100
    text = (
        f"{dt.day:02d} {month_name} {yy:02d}  "
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}\x00"
    )
    return text.encode("ascii")


def parse_tzutc_value(value: str) -> int | None:
    match = _TZUTC_RE.match(value.strip())
    if match is None:
        return None
    sign, hh_str, mm_str = match.groups()
    hh = int(hh_str)
    mm = int(mm_str)
    if mm > 59:
        return None
    total = hh * 60 + mm
    if total >= 24 * 60:
        return None
    if sign == "-" and total != 0:
        return -total
    return total


def format_tzutc_value(minutes: int) -> str:
    abs_min = abs(minutes)
    hh, mm = divmod(abs_min, 60)
    if minutes < 0:
        return f"-{hh:02d}{mm:02d}"
    return f"{hh:02d}{mm:02d}"


def split_raw_lines(data: bytes) -> list[bytes]:
    if not data:
        return []
    return re.split(rb"\r\n|\r|\n", data)


def split_text_lines(text: str) -> list[str]:
    if not text:
        return []
    return re.split(r"\r\n|\r|\n", text)


def parse_control_text(raw_without_soh: str) -> tuple[str, str] | None:
    if not raw_without_soh:
        return None
    for ch in raw_without_soh:
        code = ord(ch)
        if (code < 0x20 and ch != "\t") or code == 0x7F:
            return None
    match = _CONTROL_SPLIT_RE.match(raw_without_soh)
    if match is not None:
        name_raw, value_raw = match.groups()
    else:
        bare = _CONTROL_BARE_RE.match(raw_without_soh)
        if bare is None:
            return None
        name_raw = bare.group(1)
        value_raw = ""
    if not all(0x21 <= ord(c) <= 0x7E and c != ":" for c in name_raw):
        return None
    return name_raw.upper(), value_raw.strip()


def parse_intl_value(
    value: str,
) -> tuple[tuple[int, int, int], tuple[int, int, int]] | None:
    match = _INTL_RE.match(value.strip())
    if match is None:
        return None
    dz, dnet, dnode, oz, onet, onode = (int(g) for g in match.groups())
    if not (1 <= dz <= 65535 and 1 <= oz <= 65535):
        return None
    if not (
        0 <= dnet <= 65535
        and 0 <= dnode <= 65535
        and 0 <= onet <= 65535
        and 0 <= onode <= 65535
    ):
        return None
    return (dz, dnet, dnode), (oz, onet, onode)


def parse_point_value(value: str) -> int | None:
    match = _POINT_RE.match(value.strip())
    if match is None:
        return None
    pt = int(match.group(1))
    if not (1 <= pt <= 65535):
        return None
    return pt


def is_valid_area_tag(tag: str) -> bool:
    return bool(tag) and all(0x21 <= ord(ch) <= 0x7E for ch in tag)
