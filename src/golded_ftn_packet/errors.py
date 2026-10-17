from __future__ import annotations

from collections.abc import Callable


def _reconstruct_packet_error(
    cls: type[PacketError],
    code: str,
    offset: int | None,
    message_ordinal: int | None,
    field: str | None,
) -> PacketError:
    return cls(
        code,
        offset=offset,
        message_ordinal=message_ordinal,
        field=field,
    )


class PacketError(Exception):
    """Base exception for all packet framing, semantic, and encoding errors.

    ``str(error)`` and ``repr(error)`` expose only structural and numeric
    metadata and never include message content, names, subjects, control
    values, passwords, or filesystem paths.
    """

    code: str
    offset: int | None
    message_ordinal: int | None
    field: str | None

    def __init__(
        self,
        code: str,
        *,
        offset: int | None = None,
        message_ordinal: int | None = None,
        field: str | None = None,
    ) -> None:
        self.code = code
        self.offset = offset
        self.message_ordinal = message_ordinal
        self.field = field
        super().__init__(self._format_safe())
        self.__cause__ = None
        self.__context__ = None
        self.__suppress_context__ = True

    def __reduce__(
        self,
    ) -> tuple[
        Callable[
            [type[PacketError], str, int | None, int | None, str | None],
            PacketError,
        ],
        tuple[type[PacketError], str, int | None, int | None, str | None],
    ]:
        return (
            _reconstruct_packet_error,
            (
                self.__class__,
                self.code,
                self.offset,
                self.message_ordinal,
                self.field,
            ),
        )

    def _format_safe(self) -> str:
        parts = [f"code={self.code}"]
        if self.field is not None:
            parts.append(f"field={self.field}")
        if self.message_ordinal is not None:
            parts.append(f"message_ordinal={self.message_ordinal}")
        if self.offset is not None:
            parts.append(f"offset={self.offset}")
        return f"{self.__class__.__name__}({', '.join(parts)})"

    def __str__(self) -> str:
        return self._format_safe()

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"code={self.code!r}, "
            f"offset={self.offset!r}, "
            f"message_ordinal={self.message_ordinal!r}, "
            f"field={self.field!r})"
        )


class PacketParseError(PacketError):
    """Raised when packet framing, header layout, or size limits are violated."""


class PacketSemanticError(PacketError):
    """Raised when a record fails date, control, charset, or address decoding."""


class PacketEncodeError(PacketError):
    """Raised when outbound packet header or message inputs violate encoding rules."""
