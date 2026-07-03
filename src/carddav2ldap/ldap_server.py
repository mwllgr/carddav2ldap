"""Asyncio-based LDAP server with TLS/mTLS support."""
from __future__ import annotations

import asyncio
import dataclasses
import hmac
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

_MAX_BUFFER = 1 * 1024 * 1024  # 1 MB per connection
_READ_TIMEOUT = 60.0  # seconds idle before disconnect
_MAX_BIND_FAILURES = 5  # close connection after this many failed binds
_MAX_CONNECTIONS_PER_IP = 20  # simultaneous connections per client IP
_BIND_FAILURE_DELAY = 0.5  # seconds to sleep after each failed bind


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
            if not isinstance(el.value, bytes):
                return False
            attr = el.value.decode("utf-8", errors="replace").lower()
            if attr == "objectclass":
                return True
            return attr in entry_attrs

    return False


def _match_substring(substrings_el: BERElement, values: list[str]) -> bool:
    children = substrings_el.value if isinstance(substrings_el.value, list) else []
    initial = ""
    any_parts: list[str] = []
    final = ""

    for child in children:
        if not isinstance(child.value, bytes):
            continue
        text = child.value.decode("utf-8", errors="replace").lower()
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


@dataclasses.dataclass
class RequesterInfo:
    peer: tuple | None = None
    bind_dn: str = ""


SearchFn = Callable[[list[tuple[str, str]], RequesterInfo | None], list[dict[str, Any]]]


@dataclasses.dataclass
class HandlerAccount:
    bind_dn: str
    bind_password: str
    entries: list[dict[str, Any]]
    search_fn: SearchFn | None = None


class LDAPRequestHandler:
    def __init__(
        self,
        accounts: list[HandlerAccount],
        base_dn: str,
    ):
        self.accounts = accounts
        self.base_dn = base_dn.lower()

    def handle_message(self, msg: BERElement, peer: tuple | None = None, conn_state: dict | None = None) -> list[bytes]:
        if conn_state is None:
            conn_state = {}
        children = msg.value if isinstance(msg.value, list) else []
        if len(children) < 2:
            return []

        message_id = ber.decode_integer(children[0])
        op = children[1]

        if op.tag_class == TagClass.APPLICATION:
            if op.tag_number == 0:  # BindRequest
                return self._handle_bind(message_id, op, conn_state)
            if op.tag_number == 3:  # SearchRequest
                return self._handle_search(message_id, op, peer, conn_state)
            if op.tag_number == 2:  # UnbindRequest
                conn_state.pop("account", None)
                return []

        return [_build_search_result_done(message_id, LDAP_OPERATIONS_ERROR, "Unsupported operation")]

    def _handle_bind(self, message_id: int, op: BERElement, conn_state: dict) -> list[bytes]:
        children = op.value if isinstance(op.value, list) else []
        if len(children) >= 3:
            bind_name = ber.decode_string(children[1])
            if not isinstance(children[2].value, bytes):
                return [_build_bind_response(message_id, LDAP_OPERATIONS_ERROR, message="Malformed bind request")]
            bind_pw = children[2].value.decode("utf-8", errors="replace")
        else:
            bind_name = ""
            bind_pw = ""

        anonymous_account: HandlerAccount | None = None
        for account in self.accounts:
            if not account.bind_dn and not account.bind_password:
                anonymous_account = account
                continue
            if bind_name == account.bind_dn and hmac.compare_digest(
                bind_pw.encode("utf-8"), account.bind_password.encode("utf-8")
            ):
                conn_state["account"] = account
                conn_state.pop("_bind_failure_count", None)
                return [_build_bind_response(message_id, LDAP_SUCCESS)]

        if anonymous_account is not None and not bind_name and not bind_pw:
            conn_state["account"] = anonymous_account
            conn_state.pop("_bind_failure_count", None)
            return [_build_bind_response(message_id, LDAP_SUCCESS)]

        conn_state["_bind_failure_count"] = conn_state.get("_bind_failure_count", 0) + 1
        conn_state["_bind_failed"] = True
        return [_build_bind_response(message_id, LDAP_INVALID_CREDENTIALS, message="Invalid credentials")]

    def _handle_search(self, message_id: int, op: BERElement, peer: tuple | None, conn_state: dict) -> list[bytes]:
        account: HandlerAccount | None = conn_state.get("account")
        if account is None:
            return [_build_search_result_done(message_id, LDAP_INVALID_CREDENTIALS, "Bind required")]

        req = _parse_search_request(op)
        if not req:
            return [_build_search_result_done(message_id, LDAP_OPERATIONS_ERROR)]

        base = req["base_dn"].lower()
        scope = req["scope"]  # 0=base, 1=oneLevel, 2=subtree

        if account.search_fn is not None:
            try:
                terms = extract_filter_terms(req["filter"])
                requester = RequesterInfo(peer=peer, bind_dn=account.bind_dn)
                search_entries = account.search_fn(terms, requester)
            except Exception:
                logger.exception("Real-time search failed")
                return [_build_search_result_done(message_id, LDAP_OPERATIONS_ERROR, "Backend search failed")]
        else:
            search_entries = account.entries

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

    def update_account_entries(self, index: int, entries: list[dict[str, Any]]) -> None:
        self.accounts[index].entries = entries


class LDAPServer:
    def __init__(
        self,
        handler: LDAPRequestHandler,
        host: str = "0.0.0.0",
        port: int = 389,
        ssl_context: ssl.SSLContext | None = None,
        allowed_client_cns: list[str] | None = None,
        plaintext_port: int = 0,
    ):
        self.handler = handler
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.allowed_client_cns = allowed_client_cns
        self.plaintext_port = plaintext_port
        self._server: asyncio.AbstractServer | None = None
        self._plaintext_server: asyncio.AbstractServer | None = None
        self._ip_connections: dict[str, int] = {}

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername", ("unknown",))
        logger.info("Client connected from %s", peer)

        ip = peer[0] if isinstance(peer, tuple) and len(peer) >= 1 else "unknown"
        if self._ip_connections.get(ip, 0) >= _MAX_CONNECTIONS_PER_IP:
            logger.warning("Connection limit for %s exceeded, rejecting", ip)
            writer.close()
            await writer.wait_closed()
            return
        self._ip_connections[ip] = self._ip_connections.get(ip, 0) + 1

        try:
            if self.allowed_client_cns:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj is None:
                    logger.warning("mTLS required but no TLS connection from %s", peer)
                    return
                cert = ssl_obj.getpeercert()
                if not cert:
                    logger.warning("mTLS required but no client certificate from %s", peer)
                    return
                cn = _extract_cn(cert)
                if cn not in self.allowed_client_cns:
                    logger.warning("Client CN '%s' not in allowed list, rejecting %s", cn, peer)
                    return
                logger.info("Accepted client with CN '%s'", cn)

            conn_state: dict = {}
            buf = b""
            try:
                while True:
                    try:
                        data = await asyncio.wait_for(reader.read(65536), timeout=_READ_TIMEOUT)
                    except asyncio.TimeoutError:
                        logger.info("Client %s timed out", peer)
                        break
                    if not data:
                        break
                    buf += data

                    if len(buf) > _MAX_BUFFER:
                        logger.warning("Receive buffer limit exceeded for %s, closing", peer)
                        break

                    while buf:
                        msg, buf = ber.read_ldap_message(buf)
                        if msg is None:
                            break

                        responses = self.handler.handle_message(msg, peer, conn_state)
                        if not responses:
                            writer.close()
                            await writer.wait_closed()
                            return

                        bind_failed = conn_state.pop("_bind_failed", False)
                        if bind_failed:
                            await asyncio.sleep(_BIND_FAILURE_DELAY)

                        for resp_data in responses:
                            writer.write(resp_data)
                        await writer.drain()

                        if bind_failed and conn_state.get("_bind_failure_count", 0) >= _MAX_BIND_FAILURES:
                            logger.warning("Too many bind failures from %s, closing", peer)
                            writer.close()
                            await writer.wait_closed()
                            return

            except (ConnectionResetError, BrokenPipeError):
                pass
            except Exception:
                logger.exception("Error handling client %s", peer)
        finally:
            count = self._ip_connections.get(ip, 1) - 1
            if count <= 0:
                self._ip_connections.pop(ip, None)
            else:
                self._ip_connections[ip] = count
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
        proto = "LDAPS" if self.ssl_context else "LDAP"
        logger.info("%s server listening on %s", proto, addrs)

        if self.plaintext_port and self.ssl_context:
            self._plaintext_server = await asyncio.start_server(
                self._handle_client,
                self.host,
                self.plaintext_port,
            )
            pt_addrs = [s.getsockname() for s in self._plaintext_server.sockets]
            logger.info("LDAP server listening on %s (plaintext)", pt_addrs)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        if self._plaintext_server is not None:
            async with self._server, self._plaintext_server:
                await asyncio.gather(
                    self._server.serve_forever(),
                    self._plaintext_server.serve_forever(),
                )
        else:
            async with self._server:
                await self._server.serve_forever()

    async def stop(self) -> None:
        if self._plaintext_server:
            self._plaintext_server.close()
            await self._plaintext_server.wait_closed()
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
