"""Asyncio-based LDAP server with TLS/mTLS support."""
from __future__ import annotations

import asyncio
import logging
import re
import ssl
from collections.abc import Callable
from typing import Any

from . import ber
from .ber import BERElement, TagClass

logger = logging.getLogger(__name__)

LDAP_SUCCESS = 0
LDAP_OPERATIONS_ERROR = 1
LDAP_INVALID_CREDENTIALS = 49
LDAP_NO_SUCH_OBJECT = 32
LDAP_SIZE_LIMIT_EXCEEDED = 4


def _build_ldap_message(message_id: int, protocol_op: BERElement) -> bytes:
    msg = ber.encode_sequence([ber.encode_integer(message_id), protocol_op])
    return ber.encode_element(msg)


def _build_bind_response(message_id: int, result_code: int, matched_dn: str = "", message: str = "") -> bytes:
    resp = BERElement(TagClass.APPLICATION, True, 1, [
        ber.encode_enumerated(result_code),
        ber.encode_string(matched_dn),
        ber.encode_string(message),
    ])
    return _build_ldap_message(message_id, resp)


def _build_search_result_entry(message_id: int, dn: str, attributes: dict[str, list[str]]) -> bytes:
    attr_list = []
    for name, values in attributes.items():
        val_elements = [ber.encode_string(v) for v in values]
        attr_list.append(ber.encode_sequence([
            ber.encode_string(name),
            ber.encode_set(val_elements),
        ]))
    entry = BERElement(TagClass.APPLICATION, True, 4, [
        ber.encode_string(dn),
        ber.encode_sequence(attr_list),
    ])
    return _build_ldap_message(message_id, entry)


def _build_search_result_done(message_id: int, result_code: int = LDAP_SUCCESS, message: str = "") -> bytes:
    done = BERElement(TagClass.APPLICATION, True, 5, [
        ber.encode_enumerated(result_code),
        ber.encode_string(""),
        ber.encode_string(message),
    ])
    return _build_ldap_message(message_id, done)


def _parse_filter(el: BERElement, entry_attrs: dict[str, list[str]]) -> bool:
    # context-specific tags map to filter types per RFC 4511
    if el.tag_class == TagClass.CONTEXT:
        children = el.value if isinstance(el.value, list) else []

        if el.tag_number == 0:  # AND
            return all(_parse_filter(c, entry_attrs) for c in children)

        if el.tag_number == 1:  # OR
            return any(_parse_filter(c, entry_attrs) for c in children)

        if el.tag_number == 2:  # NOT
            if children:
                return not _parse_filter(children[0], entry_attrs)
            return True

        if el.tag_number == 3:  # equalityMatch
            if len(children) >= 2:
                attr = ber.decode_string(children[0]).lower()
                val = ber.decode_string(children[1]).lower()
                return any(v.lower() == val for v in entry_attrs.get(attr, []))
            return False

        if el.tag_number == 4:  # substrings
            if len(children) >= 2:
                attr = ber.decode_string(children[0]).lower()
                return _match_substring(children[1], entry_attrs.get(attr, []))
            return False

        if el.tag_number == 7:  # present
            assert isinstance(el.value, bytes)
            attr = el.value.decode("utf-8").lower()
            if attr == "objectclass":
                return True
            return attr in entry_attrs

    return True


def _match_substring(substrings_el: BERElement, values: list[str]) -> bool:
    children = substrings_el.value if isinstance(substrings_el.value, list) else []
    initial = ""
    any_parts: list[str] = []
    final = ""

    for child in children:
        assert isinstance(child.value, bytes)
        text = child.value.decode("utf-8").lower()
        if child.tag_number == 0:  # initial
            initial = text
        elif child.tag_number == 1:  # any
            any_parts.append(text)
        elif child.tag_number == 2:  # final
            final = text

    for val in values:
        v = val.lower()
        if initial and not v.startswith(initial):
            continue
        if final and not v.endswith(final):
            continue
        if all(part in v for part in any_parts):
            return True

    return False


def _parse_search_request(el: BERElement) -> dict[str, Any]:
    children = el.value if isinstance(el.value, list) else []
    if len(children) < 8:
        return {}

    base_dn = ber.decode_string(children[0])
    scope = ber.decode_enumerated(children[1])
    size_limit = ber.decode_integer(children[3])

    filter_el = children[6]

    requested_attrs: list[str] = []
    attrs_el = children[7]
    if isinstance(attrs_el.value, list):
        for attr_el in attrs_el.value:
            requested_attrs.append(ber.decode_string(attr_el))

    return {
        "base_dn": base_dn,
        "scope": scope,
        "size_limit": size_limit,
        "filter": filter_el,
        "attributes": requested_attrs,
    }


def _filter_attributes(entry_attrs: dict[str, list[str]], requested: list[str]) -> dict[str, list[str]]:
    if not requested:
        return entry_attrs
    req_lower = {a.lower() for a in requested}
    if "*" in req_lower:
        return entry_attrs
    return {k: v for k, v in entry_attrs.items() if k.lower() in req_lower}


def extract_filter_terms(el: BERElement) -> list[tuple[str, str]]:
    """Extract (ldap_attribute, search_value) pairs from an LDAP filter."""
    terms: list[tuple[str, str]] = []
    if el.tag_class != TagClass.CONTEXT:
        return terms

    children = el.value if isinstance(el.value, list) else []

    if el.tag_number in (0, 1):  # AND, OR
        for child in children:
            terms.extend(extract_filter_terms(child))

    elif el.tag_number == 2:  # NOT
        if children:
            terms.extend(extract_filter_terms(children[0]))

    elif el.tag_number == 3:  # equalityMatch
        if len(children) >= 2:
            attr = ber.decode_string(children[0])
            val = ber.decode_string(children[1])
            if attr.lower() != "objectclass":
                terms.append((attr, val))

    elif el.tag_number == 4:  # substrings
        if len(children) >= 2:
            attr = ber.decode_string(children[0])
            sub_children = children[1].value if isinstance(children[1].value, list) else []
            for sub in sub_children:
                if isinstance(sub.value, bytes):
                    val = sub.value.decode("utf-8")
                    if val:
                        terms.append((attr, val))

    return terms


class LDAPRequestHandler:
    def __init__(
        self,
        entries: list[dict[str, Any]],
        base_dn: str,
        bind_dn: str = "",
        bind_password: str = "",
        search_fn: Callable[[list[tuple[str, str]], tuple | None], list[dict[str, Any]]] | None = None,
    ):
        self.entries = entries
        self.base_dn = base_dn.lower()
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.search_fn = search_fn

    def handle_message(self, msg: BERElement, peer: tuple | None = None) -> list[bytes]:
        children = msg.value if isinstance(msg.value, list) else []
        if len(children) < 2:
            return []

        message_id = ber.decode_integer(children[0])
        op = children[1]

        if op.tag_class == TagClass.APPLICATION:
            if op.tag_number == 0:  # BindRequest
                return self._handle_bind(message_id, op)
            if op.tag_number == 3:  # SearchRequest
                return self._handle_search(message_id, op, peer)
            if op.tag_number == 2:  # UnbindRequest
                return []

        return [_build_search_result_done(message_id, LDAP_OPERATIONS_ERROR, "Unsupported operation")]

    def _handle_bind(self, message_id: int, op: BERElement) -> list[bytes]:
        children = op.value if isinstance(op.value, list) else []
        if len(children) >= 3:
            bind_name = ber.decode_string(children[1])
            assert isinstance(children[2].value, bytes)
            bind_pw = children[2].value.decode("utf-8", errors="replace")
        else:
            bind_name = ""
            bind_pw = ""

        if self.bind_dn and self.bind_password:
            if bind_name != self.bind_dn or bind_pw != self.bind_password:
                return [_build_bind_response(message_id, LDAP_INVALID_CREDENTIALS, message="Invalid credentials")]

        return [_build_bind_response(message_id, LDAP_SUCCESS)]

    def _handle_search(self, message_id: int, op: BERElement, peer: tuple | None = None) -> list[bytes]:
        req = _parse_search_request(op)
        if not req:
            return [_build_search_result_done(message_id, LDAP_OPERATIONS_ERROR)]

        base = req["base_dn"].lower()
        scope = req["scope"]  # 0=base, 1=oneLevel, 2=subtree

        if self.search_fn is not None:
            try:
                terms = extract_filter_terms(req["filter"])
                search_entries = self.search_fn(terms, peer)
            except Exception:
                logger.exception("Real-time search failed")
                return [_build_search_result_done(message_id, LDAP_OPERATIONS_ERROR, "Backend search failed")]
        else:
            search_entries = self.entries

        if scope == 0:
            for entry in search_entries:
                if entry["dn"].lower() == base:
                    attrs = {k.lower(): v for k, v in entry["attributes"].items()}
                    if _parse_filter(req["filter"], attrs):
                        filtered = _filter_attributes(entry["attributes"], req["attributes"])
                        return [
                            _build_search_result_entry(message_id, entry["dn"], filtered),
                            _build_search_result_done(message_id, LDAP_SUCCESS),
                        ]
            return [_build_search_result_done(message_id, LDAP_SUCCESS)]

        if scope == 1 and base != self.base_dn:
            return [_build_search_result_done(message_id, LDAP_SUCCESS)]

        if scope == 2 and base != self.base_dn and not self.base_dn.endswith("," + base):
            return [_build_search_result_done(message_id, LDAP_SUCCESS)]

        results: list[bytes] = []
        count = 0
        size_limit = req["size_limit"] if req["size_limit"] > 0 else 0

        for entry in search_entries:
            attrs = {k.lower(): v for k, v in entry["attributes"].items()}
            if _parse_filter(req["filter"], attrs):
                filtered = _filter_attributes(entry["attributes"], req["attributes"])
                results.append(_build_search_result_entry(message_id, entry["dn"], filtered))
                count += 1
                if size_limit and count >= size_limit:
                    results.append(_build_search_result_done(
                        message_id, LDAP_SIZE_LIMIT_EXCEEDED, "Size limit exceeded"))
                    return results

        results.append(_build_search_result_done(message_id, LDAP_SUCCESS))
        return results

    def update_entries(self, entries: list[dict[str, Any]]) -> None:
        self.entries = entries


class LDAPServer:
    def __init__(
        self,
        handler: LDAPRequestHandler,
        host: str = "0.0.0.0",
        port: int = 389,
        ssl_context: ssl.SSLContext | None = None,
        allowed_client_cns: list[str] | None = None,
    ):
        self.handler = handler
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.allowed_client_cns = allowed_client_cns
        self._server: asyncio.AbstractServer | None = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername", ("unknown",))
        logger.info("Client connected from %s", peer)

        if self.allowed_client_cns:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                logger.warning("mTLS required but no TLS connection from %s", peer)
                writer.close()
                await writer.wait_closed()
                return
            cert = ssl_obj.getpeercert()
            if not cert:
                logger.warning("mTLS required but no client certificate from %s", peer)
                writer.close()
                await writer.wait_closed()
                return
            cn = _extract_cn(cert)
            if cn not in self.allowed_client_cns:
                logger.warning("Client CN '%s' not in allowed list, rejecting %s", cn, peer)
                writer.close()
                await writer.wait_closed()
                return
            logger.info("Accepted client with CN '%s'", cn)

        buf = b""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                buf += data

                while buf:
                    msg, buf = ber.read_ldap_message(buf)
                    if msg is None:
                        break

                    responses = self.handler.handle_message(msg, peer)
                    if not responses:
                        writer.close()
                        await writer.wait_closed()
                        return

                    for resp_data in responses:
                        writer.write(resp_data)
                    await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            logger.exception("Error handling client %s", peer)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("Client disconnected: %s", peer)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            ssl=self.ssl_context,
        )
        addrs = [s.getsockname() for s in self._server.sockets]
        logger.info("LDAP server listening on %s", addrs)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()


def _extract_cn(cert: dict) -> str:
    subject = cert.get("subject", ())
    for rdn in subject:
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                return attr_value
    return ""


def create_ssl_context(
    certfile: str,
    keyfile: str,
    ca_certfile: str | None = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    import os
    for path, label in [(certfile, "TLS certificate"), (keyfile, "TLS key")]:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{label} not found: {path}")
    if ca_certfile and not os.path.isfile(ca_certfile):
        raise FileNotFoundError(f"TLS CA certificate not found: {ca_certfile}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        if ca_certfile:
            ctx.load_verify_locations(ca_certfile)
        else:
            ctx.load_default_certs()
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
