from __future__ import annotations

import asyncio
import ssl
from typing import Any

import pytest

from carddav2ldap import ber
from carddav2ldap.ber import BERElement, TagClass, encode_element, encode_sequence, encode_integer, encode_string
from carddav2ldap.ldap_server import (
    HandlerAccount,
    LDAPRequestHandler,
    LDAPServer,
    _build_bind_response,
    _build_search_result_done,
    _build_search_result_entry,
    _parse_filter,
    create_ssl_context,
    extract_filter_terms,
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

SAMPLE_ENTRIES_2 = [
    {
        "dn": "cn=Bob User,dc=contacts,dc=local",
        "attributes": {
            "cn": ["Bob User"],
            "sn": ["User"],
            "objectClass": ["inetOrgPerson"],
        },
    },
]


def _make_anonymous_account(entries=None):
    return HandlerAccount(bind_dn="", bind_password="", entries=entries or SAMPLE_ENTRIES)


def _make_auth_account(bind_dn="cn=admin", bind_password="secret", entries=None):
    return HandlerAccount(bind_dn=bind_dn, bind_password=bind_password, entries=entries or SAMPLE_ENTRIES)


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


def _bind_and_get_state(handler, dn="", password=""):
    conn_state: dict = {}
    req = _build_bind_request(1, dn, password)
    msg, _ = ber.read_ldap_message(req)
    handler.handle_message(msg, conn_state=conn_state)
    return conn_state


def _search_entries(handler, conn_state, msg_id=2, **kwargs):
    req = _build_search_request(msg_id, **kwargs)
    msg, _ = ber.read_ldap_message(req)
    responses = handler.handle_message(msg, conn_state=conn_state)
    all_parsed = []
    for r in responses:
        all_parsed.extend(_parse_response(r))
    entries = [p for p in all_parsed if p["op_tag"] == 4]
    done = [p for p in all_parsed if p["op_tag"] == 5]
    return entries, done


class TestLDAPRequestHandler:
    def setup_method(self):
        self.handler = LDAPRequestHandler(
            accounts=[_make_anonymous_account()],
            base_dn="dc=contacts,dc=local",
        )
        self.conn_state = _bind_and_get_state(self.handler)

    def test_bind_anonymous(self):
        conn_state: dict = {}
        req = _build_bind_request(1)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg, conn_state=conn_state)
        assert len(responses) == 1
        parsed = _parse_response(responses[0])
        assert parsed[0]["op_tag"] == 1
        assert ber.decode_enumerated(parsed[0]["op"].value[0]) == 0
        assert "account" in conn_state

    def test_bind_with_credentials(self):
        handler = LDAPRequestHandler(
            accounts=[_make_auth_account()],
            base_dn="dc=contacts,dc=local",
        )
        conn_state: dict = {}
        req = _build_bind_request(1, "cn=admin", "secret")
        msg, _ = ber.read_ldap_message(req)
        responses = handler.handle_message(msg, conn_state=conn_state)
        parsed = _parse_response(responses[0])
        assert ber.decode_enumerated(parsed[0]["op"].value[0]) == 0

    def test_bind_wrong_password(self):
        handler = LDAPRequestHandler(
            accounts=[_make_auth_account()],
            base_dn="dc=contacts,dc=local",
        )
        conn_state: dict = {}
        req = _build_bind_request(1, "cn=admin", "wrong")
        msg, _ = ber.read_ldap_message(req)
        responses = handler.handle_message(msg, conn_state=conn_state)
        parsed = _parse_response(responses[0])
        assert ber.decode_enumerated(parsed[0]["op"].value[0]) == 49

    def test_search_without_bind_rejected(self):
        conn_state: dict = {}
        entries, done = _search_entries(self.handler, conn_state)
        assert len(entries) == 0
        assert len(done) == 1
        assert ber.decode_enumerated(done[0]["op"].value[0]) == 49

    def test_search_all(self):
        entries, done = _search_entries(self.handler, self.conn_state)
        assert len(entries) == 2
        assert len(done) == 1
        assert ber.decode_enumerated(done[0]["op"].value[0]) == 0

    def test_search_equality_filter(self):
        eq_filter = BERElement(TagClass.CONTEXT, True, 3, [
            encode_string("cn"),
            encode_string("John Doe"),
        ])
        entries, _ = _search_entries(self.handler, self.conn_state, filter_el=eq_filter)
        assert len(entries) == 1

    def test_search_substring_filter(self):
        sub_filter = BERElement(TagClass.CONTEXT, True, 4, [
            encode_string("cn"),
            BERElement(TagClass.UNIVERSAL, True, 0x10, [
                BERElement(TagClass.CONTEXT, False, 1, b"Doe"),
            ]),
        ])
        entries, _ = _search_entries(self.handler, self.conn_state, filter_el=sub_filter)
        assert len(entries) == 1

    def test_search_present_filter(self):
        present_filter = BERElement(TagClass.CONTEXT, False, 7, b"mail")
        entries, _ = _search_entries(self.handler, self.conn_state, filter_el=present_filter)
        assert len(entries) == 2

    def test_search_and_filter(self):
        and_filter = BERElement(TagClass.CONTEXT, True, 0, [
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("sn"),
                encode_string("Doe"),
            ]),
            BERElement(TagClass.CONTEXT, False, 7, b"mail"),
        ])
        entries, _ = _search_entries(self.handler, self.conn_state, filter_el=and_filter)
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
        entries, _ = _search_entries(self.handler, self.conn_state, filter_el=or_filter)
        assert len(entries) == 2

    def test_search_not_filter(self):
        not_filter = BERElement(TagClass.CONTEXT, True, 2, [
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("cn"),
                encode_string("John Doe"),
            ]),
        ])
        entries, _ = _search_entries(self.handler, self.conn_state, filter_el=not_filter)
        assert len(entries) == 1

    def test_search_size_limit(self):
        entries, done = _search_entries(self.handler, self.conn_state, size_limit=1)
        assert len(entries) == 1
        assert ber.decode_enumerated(done[0]["op"].value[0]) == 4

    def test_search_specific_attributes(self):
        entries, _ = _search_entries(self.handler, self.conn_state, attributes=["cn", "mail"])
        assert len(entries) == 2

    def test_unbind(self):
        conn_state = _bind_and_get_state(self.handler)
        assert "account" in conn_state
        req = _build_unbind_request(3)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg, conn_state=conn_state)
        assert responses == []
        assert "account" not in conn_state

    def test_search_base_scope_on_base_dn_returns_nothing(self):
        entries, _ = _search_entries(self.handler, self.conn_state, scope=0)
        assert len(entries) == 0

    def test_search_base_scope_on_entry_returns_that_entry(self):
        entries, _ = _search_entries(
            self.handler, self.conn_state, msg_id=19,
            base_dn="cn=John Doe,dc=contacts,dc=local", scope=0,
        )
        assert len(entries) == 1

    def test_search_one_level_at_base_returns_entries(self):
        entries, _ = _search_entries(self.handler, self.conn_state, scope=1)
        assert len(entries) == 2

    def test_search_one_level_at_entry_returns_nothing(self):
        entries, _ = _search_entries(
            self.handler, self.conn_state,
            base_dn="cn=John Doe,dc=contacts,dc=local", scope=1,
        )
        assert len(entries) == 0

    def test_search_subtree_at_base_returns_entries(self):
        entries, _ = _search_entries(self.handler, self.conn_state, scope=2)
        assert len(entries) == 2

    def test_search_subtree_at_entry_returns_nothing(self):
        entries, _ = _search_entries(
            self.handler, self.conn_state,
            base_dn="cn=John Doe,dc=contacts,dc=local", scope=2,
        )
        assert len(entries) == 0

    def test_search_subtree_from_parent_returns_entries(self):
        entries, _ = _search_entries(
            self.handler, self.conn_state, base_dn="dc=local", scope=2,
        )
        assert len(entries) == 2

    def test_search_unrelated_base_returns_nothing(self):
        entries, _ = _search_entries(
            self.handler, self.conn_state, base_dn="dc=other,dc=com", scope=2,
        )
        assert len(entries) == 0

    def test_search_fn_callback(self):
        def fake_search(terms, requester=None):
            return [SAMPLE_ENTRIES[0]]

        handler = LDAPRequestHandler(
            accounts=[HandlerAccount(bind_dn="", bind_password="", entries=[], search_fn=fake_search)],
            base_dn="dc=contacts,dc=local",
        )
        conn_state = _bind_and_get_state(handler)
        entries, _ = _search_entries(handler, conn_state, msg_id=20)
        assert len(entries) == 1

    def test_search_fn_receives_terms(self):
        received_terms = []

        def capture_search(terms, requester=None):
            received_terms.extend(terms)
            return SAMPLE_ENTRIES

        handler = LDAPRequestHandler(
            accounts=[HandlerAccount(bind_dn="", bind_password="", entries=[], search_fn=capture_search)],
            base_dn="dc=contacts,dc=local",
        )
        conn_state = _bind_and_get_state(handler)
        eq_filter = BERElement(TagClass.CONTEXT, True, 3, [
            encode_string("cn"),
            encode_string("John"),
        ])
        _search_entries(handler, conn_state, msg_id=21, filter_el=eq_filter)
        assert ("cn", "John") in received_terms

    def test_search_fn_error_returns_error(self):
        def failing_search(terms, requester=None):
            raise ConnectionError("CardDAV down")

        handler = LDAPRequestHandler(
            accounts=[HandlerAccount(bind_dn="", bind_password="", entries=[], search_fn=failing_search)],
            base_dn="dc=contacts,dc=local",
        )
        conn_state = _bind_and_get_state(handler)
        _, done = _search_entries(handler, conn_state, msg_id=22)
        assert len(done) == 1
        assert ber.decode_enumerated(done[0]["op"].value[0]) == 1

    def test_update_account_entries(self):
        conn_state = _bind_and_get_state(self.handler)
        self.handler.update_account_entries(0, [SAMPLE_ENTRIES[0]])
        entries, _ = _search_entries(self.handler, conn_state, msg_id=11)
        assert len(entries) == 1


class TestMultiUser:
    def setup_method(self):
        self.handler = LDAPRequestHandler(
            accounts=[
                HandlerAccount(bind_dn="cn=user1", bind_password="pass1", entries=SAMPLE_ENTRIES),
                HandlerAccount(bind_dn="cn=user2", bind_password="pass2", entries=SAMPLE_ENTRIES_2),
            ],
            base_dn="dc=contacts,dc=local",
        )

    def test_user1_sees_own_entries(self):
        conn_state = _bind_and_get_state(self.handler, "cn=user1", "pass1")
        entries, _ = _search_entries(self.handler, conn_state)
        assert len(entries) == 2

    def test_user2_sees_own_entries(self):
        conn_state = _bind_and_get_state(self.handler, "cn=user2", "pass2")
        entries, _ = _search_entries(self.handler, conn_state)
        assert len(entries) == 1

    def test_wrong_credentials_rejected(self):
        conn_state: dict = {}
        req = _build_bind_request(1, "cn=user1", "wrong")
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg, conn_state=conn_state)
        parsed = _parse_response(responses[0])
        assert ber.decode_enumerated(parsed[0]["op"].value[0]) == 49
        assert "account" not in conn_state

    def test_unknown_user_rejected(self):
        conn_state: dict = {}
        req = _build_bind_request(1, "cn=unknown", "pass")
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg, conn_state=conn_state)
        parsed = _parse_response(responses[0])
        assert ber.decode_enumerated(parsed[0]["op"].value[0]) == 49

    def test_rebind_switches_account(self):
        conn_state = _bind_and_get_state(self.handler, "cn=user1", "pass1")
        entries, _ = _search_entries(self.handler, conn_state)
        assert len(entries) == 2

        req = _build_bind_request(3, "cn=user2", "pass2")
        msg, _ = ber.read_ldap_message(req)
        self.handler.handle_message(msg, conn_state=conn_state)

        entries, _ = _search_entries(self.handler, conn_state, msg_id=4)
        assert len(entries) == 1

    def test_anonymous_rejected_when_no_anonymous_account(self):
        conn_state: dict = {}
        req = _build_bind_request(1)
        msg, _ = ber.read_ldap_message(req)
        responses = self.handler.handle_message(msg, conn_state=conn_state)
        parsed = _parse_response(responses[0])
        assert ber.decode_enumerated(parsed[0]["op"].value[0]) == 49

    def test_mixed_anonymous_and_auth(self):
        handler = LDAPRequestHandler(
            accounts=[
                HandlerAccount(bind_dn="", bind_password="", entries=SAMPLE_ENTRIES),
                HandlerAccount(bind_dn="cn=user2", bind_password="pass2", entries=SAMPLE_ENTRIES_2),
            ],
            base_dn="dc=contacts,dc=local",
        )
        anon_state = _bind_and_get_state(handler)
        entries, _ = _search_entries(handler, anon_state)
        assert len(entries) == 2

        auth_state = _bind_and_get_state(handler, "cn=user2", "pass2")
        entries, _ = _search_entries(handler, auth_state)
        assert len(entries) == 1


@pytest.mark.asyncio
class TestLDAPServerIntegration:
    async def test_server_bind_and_search(self):
        handler = LDAPRequestHandler(
            accounts=[_make_anonymous_account()],
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
            accounts=[_make_anonymous_account()],
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
            accounts=[_make_anonymous_account()],
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
            accounts=[_make_anonymous_account()],
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


class TestExtractFilterTerms:
    def test_equality(self):
        el = BERElement(TagClass.CONTEXT, True, 3, [
            encode_string("cn"),
            encode_string("John Doe"),
        ])
        terms = extract_filter_terms(el)
        assert terms == [("cn", "John Doe")]

    def test_substring(self):
        el = BERElement(TagClass.CONTEXT, True, 4, [
            encode_string("cn"),
            BERElement(TagClass.UNIVERSAL, True, 0x10, [
                BERElement(TagClass.CONTEXT, False, 1, b"Doe"),
            ]),
        ])
        terms = extract_filter_terms(el)
        assert terms == [("cn", "Doe")]

    def test_present_skipped(self):
        el = BERElement(TagClass.CONTEXT, False, 7, b"objectClass")
        terms = extract_filter_terms(el)
        assert terms == []

    def test_objectclass_equality_skipped(self):
        el = BERElement(TagClass.CONTEXT, True, 3, [
            encode_string("objectClass"),
            encode_string("inetOrgPerson"),
        ])
        terms = extract_filter_terms(el)
        assert terms == []

    def test_and_recurses(self):
        el = BERElement(TagClass.CONTEXT, True, 0, [
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("cn"),
                encode_string("John"),
            ]),
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("mail"),
                encode_string("john@"),
            ]),
        ])
        terms = extract_filter_terms(el)
        assert ("cn", "John") in terms
        assert ("mail", "john@") in terms

    def test_or_recurses(self):
        el = BERElement(TagClass.CONTEXT, True, 1, [
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("cn"),
                encode_string("John"),
            ]),
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("telephoneNumber"),
                encode_string("555"),
            ]),
        ])
        terms = extract_filter_terms(el)
        assert ("cn", "John") in terms
        assert ("telephoneNumber", "555") in terms

    def test_not_recurses(self):
        el = BERElement(TagClass.CONTEXT, True, 2, [
            BERElement(TagClass.CONTEXT, True, 3, [
                encode_string("cn"),
                encode_string("John"),
            ]),
        ])
        terms = extract_filter_terms(el)
        assert terms == [("cn", "John")]
