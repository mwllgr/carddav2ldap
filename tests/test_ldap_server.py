from __future__ import annotations

import asyncio
import ssl
from typing import Any

import pytest

from carddav_to_ldap import ber
from carddav_to_ldap.ber import BERElement, TagClass, encode_element, encode_sequence, encode_integer, encode_string
from carddav_to_ldap.ldap_server import (
    LDAPRequestHandler,
    LDAPServer,
    _build_bind_response,
    _build_search_result_done,
    _build_search_result_entry,
    _parse_filter,
    create_ssl_context,
)

SAMPLE_ENTRIES = [
    {
        "dn": "cn=John Doe,dc=contacts,dc=local",
        "attributes": {
            "cn": ["John Doe"],
            "sn": ["Doe"],
            "givenName": ["John"],
            "mail": ["john@example.com"],
            "telephoneNumber": ["+1-555-0100"],
            "objectClass": ["inetOrgPerson"],
        },
    },
    {
        "dn": "cn=Jane Smith,dc=contacts,dc=local",
        "attributes": {
            "cn": ["Jane Smith"],
            "sn": ["Smith"],
            "givenName": ["Jane"],
            "mail": ["jane@example.com"],
            "telephoneNumber": ["+1-555-0200"],
            "objectClass": ["inetOrgPerson"],
        },
    },
]


def _build_bind_request(message_id: int, dn: str = "", password: str = "") -> bytes:
    bind_op = BERElement(TagClass.APPLICATION, True, 0, [
        encode_integer(3),  # LDAP version
        encode_string(dn),
        BERElement(TagClass.CONTEXT, False, 0, password.encode("utf-8")),
    ])
    msg = encode_sequence([encode_integer(message_id), bind_op])
    return encode_element(msg)


def _build_search_request(
    message_id: int,
    base_dn: str = "dc=contacts,dc=local",
    scope: int = 2,
    filter_el: BERElement | None = None,
    attributes: list[str] | None = None,
    size_limit: int = 0,
) -> bytes:
    if filter_el is None:
        filter_el = BERElement(TagClass.CONTEXT, False, 7, b"objectClass")

    attr_els = [encode_string(a) for a in (attributes or [])]

    search_op = BERElement(TagClass.APPLICATION, True, 3, [
        encode_string(base_dn),
        ber.encode_enumerated(scope),
        ber.encode_enumerated(0),  # derefAliases
        encode_integer(size_limit),
        encode_integer(0),  # timeLimit
        ber.encode_boolean(False),  # typesOnly
        filter_el,
        encode_sequence(attr_els),
    ])
    msg = encode_sequence([encode_integer(message_id), search_op])
    return encode_element(msg)


def _build_unbind_request(message_id: int) -> bytes:
    unbind_op = BERElement(TagClass.APPLICATION, False, 2, b"")
    msg = encode_sequence([encode_integer(message_id), unbind_op])
    return encode_element(msg)


def _parse_response(data: bytes) -> list[dict]:
    responses = []
    while data:
        msg, data = ber.read_ldap_message(data)
        if msg is None:
            break
        children = msg.value
        assert isinstance(children, list)
        message_id = ber.decode_integer(children[0])
        op = children[1]
        responses.append({
            "message_id": message_id,
            "op_tag": op.tag_number,
            "op": op,
        })
    return responses


class TestLDAPRequestHandler:
    def setup_method(self):
        self.handler = LDAPRequestHandler(
            entries=SAMPLE_ENTRIES,
            base_dn="dc=contacts,dc=local",
        )

    def test_bind_anonymous(self):
        req = _build_bind_request(1)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        assert len(responses) == 1
        parsed = _parse_response(responses[0])
        assert parsed[0]["op_tag"] == 1  # BindResponse
        result_code = ber.decode_enumerated(parsed[0]["op"].value[0])
        assert result_code == 0  # success

    def test_bind_with_credentials(self):
        handler = LDAPRequestHandler(
            entries=SAMPLE_ENTRIES,
            base_dn="dc=contacts,dc=local",
            bind_dn="cn=admin",
            bind_password="secret",
        )
        req = _build_bind_request(1, "cn=admin", "secret")
        msg, _ = ber.read_ldap_message(req)
        responses = handler.handle_message(msg)
        parsed = _parse_response(responses[0])
        result_code = ber.decode_enumerated(parsed[0]["op"].value[0])
        assert result_code == 0

    def test_bind_wrong_password(self):
        handler = LDAPRequestHandler(
            entries=SAMPLE_ENTRIES,
            base_dn="dc=contacts,dc=local",
            bind_dn="cn=admin",
            bind_password="secret",
        )
        req = _build_bind_request(1, "cn=admin", "wrong")
        msg, _ = ber.read_ldap_message(req)
        responses = handler.handle_message(msg)
        parsed = _parse_response(responses[0])
        result_code = ber.decode_enumerated(parsed[0]["op"].value[0])
        assert result_code == 49  # invalidCredentials

    def test_search_all(self):
        req = _build_search_request(2)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]  # SearchResultEntry
        done = [p for p in all_parsed if p["op_tag"] == 5]  # SearchResultDone
        assert len(entries) == 2
        assert len(done) == 1
        assert ber.decode_enumerated(done[0]["op"].value[0]) == 0

    def test_search_equality_filter(self):
        eq_filter = BERElement(TagClass.CONTEXT, True, 3, [
            encode_string("cn"),
            encode_string("John Doe"),
        ])
        req = _build_search_request(3, filter_el=eq_filter)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 1

    def test_search_substring_filter(self):
        sub_filter = BERElement(TagClass.CONTEXT, True, 4, [
            encode_string("cn"),
            BERElement(TagClass.UNIVERSAL, True, 0x10, [
                BERElement(TagClass.CONTEXT, False, 1, b"Doe"),  # any
            ]),
        ])
        req = _build_search_request(4, filter_el=sub_filter)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 1

    def test_search_present_filter(self):
        present_filter = BERElement(TagClass.CONTEXT, False, 7, b"mail")
        req = _build_search_request(5, filter_el=present_filter)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 2

    def test_search_and_filter(self):
        and_filter = BERElement(TagClass.CONTEXT, True, 0, [
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("sn"),
                encode_string("Doe"),
            ]),
            BERElement(TagClass.CONTEXT, False, 7, b"mail"),
        ])
        req = _build_search_request(6, filter_el=and_filter)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 1

    def test_search_or_filter(self):
        or_filter = BERElement(TagClass.CONTEXT, True, 1, [
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("cn"),
                encode_string("John Doe"),
            ]),
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("cn"),
                encode_string("Jane Smith"),
            ]),
        ])
        req = _build_search_request(7, filter_el=or_filter)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 2

    def test_search_not_filter(self):
        not_filter = BERElement(TagClass.CONTEXT, True, 2, [
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("cn"),
                encode_string("John Doe"),
            ]),
        ])
        req = _build_search_request(8, filter_el=not_filter)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 1

    def test_search_size_limit(self):
        req = _build_search_request(9, size_limit=1)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        done = [p for p in all_parsed if p["op_tag"] == 5]
        assert len(entries) == 1
        assert ber.decode_enumerated(done[0]["op"].value[0]) == 4  # sizeLimitExceeded

    def test_search_specific_attributes(self):
        req = _build_search_request(10, attributes=["cn", "mail"])
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 2

    def test_unbind(self):
        req = _build_unbind_request(3)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        assert responses == []

    def test_search_base_scope_on_base_dn_returns_nothing(self):
        req = _build_search_request(12, base_dn="dc=contacts,dc=local", scope=0)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 0

    def test_search_base_scope_on_entry_returns_that_entry(self):
        req = _build_search_request(19, base_dn="cn=John Doe,dc=contacts,dc=local", scope=0)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 1

    def test_search_one_level_at_base_returns_entries(self):
        req = _build_search_request(13, base_dn="dc=contacts,dc=local", scope=1)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 2

    def test_search_one_level_at_entry_returns_nothing(self):
        req = _build_search_request(14, base_dn="cn=John Doe,dc=contacts,dc=local", scope=1)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 0

    def test_search_subtree_at_base_returns_entries(self):
        req = _build_search_request(15, base_dn="dc=contacts,dc=local", scope=2)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 2

    def test_search_subtree_at_entry_returns_nothing(self):
        req = _build_search_request(16, base_dn="cn=John Doe,dc=contacts,dc=local", scope=2)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 0

    def test_search_subtree_from_parent_returns_entries(self):
        req = _build_search_request(17, base_dn="dc=local", scope=2)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 2

    def test_search_unrelated_base_returns_nothing(self):
        req = _build_search_request(18, base_dn="dc=other,dc=com", scope=2)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 0

    def test_update_entries(self):
        self.handler.update_entries([SAMPLE_ENTRIES[0]])
        req = _build_search_request(11)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg)
        all_parsed = []
        for r in responses:
            all_parsed.extend(_parse_response(r))
        entries = [p for p in all_parsed if p["op_tag"] == 4]
        assert len(entries) == 1


@pytest.mark.asyncio
class TestLDAPServerIntegration:
    async def test_server_bind_and_search(self):
        handler = LDAPRequestHandler(
            entries=SAMPLE_ENTRIES,
            base_dn="dc=contacts,dc=local",
        )
        server = LDAPServer(handler, host="127.0.0.1", port=0)
        await server.start()
        port = server._server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            writer.write(_build_bind_request(1))
            await writer.drain()
            data = await reader.read(4096)
            parsed = _parse_response(data)
            assert parsed[0]["op_tag"] == 1
            assert ber.decode_enumerated(parsed[0]["op"].value[0]) == 0

            writer.write(_build_search_request(2))
            await writer.drain()
            data = await reader.read(65536)
            parsed = _parse_response(data)
            entries = [p for p in parsed if p["op_tag"] == 4]
            done = [p for p in parsed if p["op_tag"] == 5]
            assert len(entries) == 2
            assert len(done) == 1

            writer.write(_build_unbind_request(3))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    async def test_server_tls(self, tls_certs):
        handler = LDAPRequestHandler(
            entries=SAMPLE_ENTRIES,
            base_dn="dc=contacts,dc=local",
        )
        ssl_ctx = create_ssl_context(
            certfile=tls_certs["server_cert"],
            keyfile=tls_certs["server_key"],
        )
        server = LDAPServer(handler, host="127.0.0.1", port=0, ssl_context=ssl_ctx)
        await server.start()
        port = server._server.sockets[0].getsockname()[1]

        try:
            client_ctx = ssl.create_default_context(cafile=tls_certs["ca_cert"])
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=client_ctx)

            writer.write(_build_bind_request(1))
            await writer.drain()
            data = await reader.read(4096)
            parsed = _parse_response(data)
            assert parsed[0]["op_tag"] == 1
            assert ber.decode_enumerated(parsed[0]["op"].value[0]) == 0

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    async def test_server_mtls_accepted(self, tls_certs):
        handler = LDAPRequestHandler(
            entries=SAMPLE_ENTRIES,
            base_dn="dc=contacts,dc=local",
        )
        ssl_ctx = create_ssl_context(
            certfile=tls_certs["server_cert"],
            keyfile=tls_certs["server_key"],
            ca_certfile=tls_certs["ca_cert"],
            require_client_cert=True,
        )
        server = LDAPServer(
            handler, host="127.0.0.1", port=0,
            ssl_context=ssl_ctx,
            allowed_client_cns=["test-client"],
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]

        try:
            client_ctx = ssl.create_default_context(cafile=tls_certs["ca_cert"])
            client_ctx.load_cert_chain(tls_certs["client_cert"], tls_certs["client_key"])
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=client_ctx)

            writer.write(_build_bind_request(1))
            await writer.drain()
            data = await reader.read(4096)
            parsed = _parse_response(data)
            assert parsed[0]["op_tag"] == 1
            assert ber.decode_enumerated(parsed[0]["op"].value[0]) == 0

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    async def test_server_mtls_wrong_cn_rejected(self, tls_certs):
        handler = LDAPRequestHandler(
            entries=SAMPLE_ENTRIES,
            base_dn="dc=contacts,dc=local",
        )
        ssl_ctx = create_ssl_context(
            certfile=tls_certs["server_cert"],
            keyfile=tls_certs["server_key"],
            ca_certfile=tls_certs["ca_cert"],
            require_client_cert=True,
        )
        server = LDAPServer(
            handler, host="127.0.0.1", port=0,
            ssl_context=ssl_ctx,
            allowed_client_cns=["other-client"],
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]

        try:
            client_ctx = ssl.create_default_context(cafile=tls_certs["ca_cert"])
            client_ctx.load_cert_chain(tls_certs["client_cert"], tls_certs["client_key"])
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=client_ctx)

            writer.write(_build_bind_request(1))
            await writer.drain()
            data = await reader.read(4096)
            assert data == b""

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()
