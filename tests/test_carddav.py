from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import pytest

from carddav_to_ldap.carddav import (
    _build_client, _discover_vcards, _fetch_vcards, fetch_contacts,
    build_carddav_filter, search_contacts, _user_agent_for_requester, USER_AGENT,
)
from carddav_to_ldap.ldap_server import RequesterInfo
from carddav_to_ldap.config import CardDAVConfig


PROPFIND_RESPONSE = """\
<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/contacts/</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype><d:collection/></d:resourcetype>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/contacts/john.vcf</d:href>
    <d:propstat>
      <d:prop>
        <d:getetag>"etag1"</d:getetag>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/contacts/jane.vcf</d:href>
    <d:propstat>
      <d:prop>
        <d:getetag>"etag2"</d:getetag>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"""

REPORT_RESPONSE = """\
<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/contacts/john.vcf</d:href>
    <d:propstat>
      <d:prop>
        <d:getetag>"etag1"</d:getetag>
        <c:address-data>BEGIN:VCARD
VERSION:3.0
FN:John Doe
N:Doe;John;;;
TEL:+1-555-0100
EMAIL:john@example.com
END:VCARD</c:address-data>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/contacts/jane.vcf</d:href>
    <d:propstat>
      <d:prop>
        <d:getetag>"etag2"</d:getetag>
        <c:address-data>BEGIN:VCARD
VERSION:3.0
FN:Jane Smith
TEL:+1-555-0200
END:VCARD</c:address-data>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"""


class TestBuildClient:
    def test_basic_auth(self):
        cfg = CardDAVConfig(url="https://x.com/", username="user", password="pass")
        client = _build_client(cfg)
        assert client._auth is not None

    def test_no_auth(self):
        cfg = CardDAVConfig(url="https://x.com/")
        client = _build_client(cfg)
        assert client._auth is None

    def test_no_verify(self):
        cfg = CardDAVConfig(url="https://x.com/", verify_ssl=False)
        client = _build_client(cfg)
        assert client._transport._pool._ssl_context.verify_mode == ssl.CERT_NONE

    def test_default_verify(self):
        cfg = CardDAVConfig(url="https://x.com/")
        client = _build_client(cfg)
        assert client._transport._pool._ssl_context.verify_mode == ssl.CERT_REQUIRED

    def test_http2_enabled(self):
        cfg = CardDAVConfig(url="https://x.com/")
        client = _build_client(cfg)
        assert client._transport._pool._http2

    def test_user_agent(self):
        cfg = CardDAVConfig(url="https://x.com/")
        client = _build_client(cfg)
        assert "carddav-to-ldap.mwllgr.at/" in client.headers["user-agent"]

    def test_ca_cert(self, tls_certs):
        cfg = CardDAVConfig(url="https://x.com/", ca_cert=tls_certs["ca_cert"])
        client = _build_client(cfg)
        assert isinstance(client._transport._pool._ssl_context, ssl.SSLContext)


class TestDiscoverVcards:
    def test_discover(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = PROPFIND_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_client.request.return_value = mock_response

        hrefs = _discover_vcards(mock_client, "https://dav.example.com/contacts/")
        assert len(hrefs) == 2
        assert "/contacts/john.vcf" in hrefs
        assert "/contacts/jane.vcf" in hrefs
        mock_client.request.assert_called_once()
        call_args = mock_client.request.call_args
        assert call_args[0][0] == "PROPFIND"
        assert call_args[0][1] == "https://dav.example.com/contacts/"

    def test_discover_no_vcf(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = """\
<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/contacts/</d:href>
  </d:response>
</d:multistatus>"""
        mock_response.raise_for_status = MagicMock()
        mock_client.request.return_value = mock_response

        hrefs = _discover_vcards(mock_client, "https://x.com/")
        assert hrefs == []


class TestFetchVcards:
    def test_fetch(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = REPORT_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_client.request.return_value = mock_response

        contacts = _fetch_vcards(
            mock_client,
            "https://dav.example.com/contacts/",
            ["/contacts/john.vcf", "/contacts/jane.vcf"],
        )
        assert len(contacts) == 2
        assert contacts[0].fn.value == "John Doe"
        assert contacts[1].fn.value == "Jane Smith"

    def test_fetch_empty(self):
        mock_client = MagicMock()
        contacts = _fetch_vcards(mock_client, "https://x.com/", [])
        assert contacts == []
        mock_client.request.assert_not_called()


class TestFetchContacts:
    @patch("carddav_to_ldap.carddav._fetch_vcards")
    @patch("carddav_to_ldap.carddav._discover_vcards")
    @patch("carddav_to_ldap.carddav._build_client")
    def test_integration(self, mock_build, mock_discover, mock_fetch):
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_discover.return_value = ["/john.vcf"]
        mock_fetch.return_value = [MagicMock()]

        cfg = CardDAVConfig(url="https://dav.example.com/contacts/")
        result = fetch_contacts(cfg)

        assert len(result) == 1
        mock_build.assert_called_once_with(cfg)
        mock_discover.assert_called_once_with(mock_client, cfg.url)
        mock_fetch.assert_called_once_with(mock_client, cfg.url, ["/john.vcf"])


class TestBuildCardDAVFilter:
    def test_empty_terms(self):
        assert build_carddav_filter([]) == ""

    def test_single_cn_term(self):
        result = build_carddav_filter([("cn", "John")])
        assert '<c:prop-filter name="FN">' in result
        assert '<c:text-match' in result
        assert "John" in result
        assert 'test="anyof"' in result

    def test_tel_term(self):
        result = build_carddav_filter([("telephoneNumber", "555")])
        assert '<c:prop-filter name="TEL">' in result
        assert "555" in result

    def test_multiple_terms(self):
        result = build_carddav_filter([("cn", "John"), ("mail", "john@")])
        assert '<c:prop-filter name="FN">' in result
        assert '<c:prop-filter name="EMAIL">' in result

    def test_deduplicates(self):
        result = build_carddav_filter([("cn", "John"), ("cn", "John")])
        assert result.count("prop-filter") == 2  # opening + closing

    def test_xml_escapes_special_chars(self):
        result = build_carddav_filter([("cn", "O&M <Corp>")])
        assert "&amp;" in result
        assert "&lt;" in result
        assert "&gt;" in result

    def test_unknown_attr_defaults_to_fn(self):
        result = build_carddav_filter([("unknownAttr", "test")])
        assert '<c:prop-filter name="FN">' in result


class TestSearchContacts:
    @patch("carddav_to_ldap.carddav._build_client")
    def test_search_sends_report(self, mock_build):
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_response = MagicMock()
        mock_response.text = REPORT_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_client.request.return_value = mock_response

        cfg = CardDAVConfig(url="https://dav.example.com/contacts/")
        result = search_contacts(cfg, [("cn", "John")])

        assert len(result) == 2
        call_args = mock_client.request.call_args
        assert call_args[0][0] == "REPORT"
        body = call_args[1].get("content") or call_args[0][2]
        assert "addressbook-query" in body
        assert "prop-filter" in body

    @patch("carddav_to_ldap.carddav._build_client")
    def test_search_empty_terms_fetches_all(self, mock_build):
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_response = MagicMock()
        mock_response.text = REPORT_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_client.request.return_value = mock_response

        cfg = CardDAVConfig(url="https://dav.example.com/contacts/")
        result = search_contacts(cfg, [])

        assert len(result) == 2
        call_args = mock_client.request.call_args
        body = call_args[1].get("content") or call_args[0][2]
        assert "prop-filter" not in body

    @patch("carddav_to_ldap.carddav._build_client")
    def test_search_forwards_requester(self, mock_build):
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_response = MagicMock()
        mock_response.text = REPORT_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_client.request.return_value = mock_response

        cfg = CardDAVConfig(url="https://dav.example.com/contacts/", forward_requester=True)
        requester = RequesterInfo(peer=("192.168.1.4", 82842), bind_dn="cn=user1")
        search_contacts(cfg, [("cn", "John")], requester=requester)

        call_args = mock_client.request.call_args
        headers = call_args[1].get("headers", {})
        assert headers["User-Agent"] == f"{USER_AGENT} @ cn=user1 192.168.1.4:82842"

    @patch("carddav_to_ldap.carddav._build_client")
    def test_search_no_forward_without_config(self, mock_build):
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_response = MagicMock()
        mock_response.text = REPORT_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_client.request.return_value = mock_response

        cfg = CardDAVConfig(url="https://dav.example.com/contacts/", forward_requester=False)
        requester = RequesterInfo(peer=("192.168.1.4", 82842), bind_dn="cn=user1")
        search_contacts(cfg, [("cn", "John")], requester=requester)

        call_args = mock_client.request.call_args
        headers = call_args[1].get("headers", {})
        assert "User-Agent" not in headers


class TestUserAgentForRequester:
    def test_with_peer_and_bind_dn(self):
        r = RequesterInfo(peer=("192.168.1.4", 82842), bind_dn="cn=user1")
        assert _user_agent_for_requester(r) == f"{USER_AGENT} @ cn=user1 192.168.1.4:82842"

    def test_with_peer_only(self):
        r = RequesterInfo(peer=("192.168.1.4", 82842))
        assert _user_agent_for_requester(r) == f"{USER_AGENT} @ 192.168.1.4:82842"

    def test_with_bind_dn_only(self):
        r = RequesterInfo(bind_dn="cn=user1")
        assert _user_agent_for_requester(r) == f"{USER_AGENT} @ cn=user1"

    def test_with_none(self):
        assert _user_agent_for_requester(None) == USER_AGENT

    def test_with_empty_requester(self):
        r = RequesterInfo()
        assert _user_agent_for_requester(r) == USER_AGENT

