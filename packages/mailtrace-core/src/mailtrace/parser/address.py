from email.header import decode_header, make_header
from email.headerregistry import Address
from email.errors import HeaderParseError
from email.utils import getaddresses

from ..models.report import HeaderField, Mailbox, ParseDefect


def decode_text(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except (LookupError, UnicodeError, ValueError):
        return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def addresses(field: HeaderField, defects: list[ParseDefect]) -> list[Mailbox]:
    value = field.value or ""
    result = []
    try:
        parsed = getaddresses([value])
    except (ValueError, IndexError, RecursionError):
        parsed = []
    for name, address in parsed:
        try:
            mailbox = Address(addr_spec=address)
            valid = bool(mailbox.username and mailbox.domain)
        except (ValueError, IndexError, HeaderParseError, RecursionError):
            valid = False
        if valid:
            result.append(Mailbox(display_name=decode_text(name) or None, address=address, header_id=field.id))
        else:
            defects.append(ParseDefect(code="INVALID_ADDRESS", message="无法提取完整邮箱地址。", header_id=field.id))
    if not parsed and value:
        defects.append(ParseDefect(code="INVALID_ADDRESS", message="无法提取完整邮箱地址。", header_id=field.id))
    return result
