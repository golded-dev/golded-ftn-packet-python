"""Wire lines must use CR even when a base reader returns LF."""

from datetime import datetime

import pytest
from golded_ftn import FtnAddress

from golded_ftn_packet import PacketMessageInput, encode_message


@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("kind", ["netmail", "echomail"])
def test_wire_line_endings(ending: str, kind: str) -> None:
    text = ending.join(["\x01FMPT 1", "\x01TOPT 1", "First line", "Second line", ""])
    packed = encode_message(
        PacketMessageInput(
            from_name="C.1",
            to_name="A.1",
            subject="Private note",
            body_text=text,
            from_address=FtnAddress(zone=2, net=999, node=3, point=1),
            to_address=FtnAddress(zone=2, net=999, node=1, point=1),
            posted_at=datetime(2026, 3, 15, 12),
            message_class=kind,  # type: ignore[arg-type]
            area_tag="TEST.PUBLIC" if kind == "echomail" else None,
        )
    )
    assert b"\n" not in packed.raw_bytes
    assert b"\x01TOPT 1\rFirst line\rSecond line\r\x00" in packed.raw_bytes
