from __future__ import annotations

from unittest.mock import MagicMock, patch
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import ssl

import pytest

from carddav_to_ldap.carddav import _build_session, _discover_vcards, _fetch_vcards, fetch_contacts
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


class TestBuildSession:
    def test_basic_auth(self):
        cfg = CardDAVConfig(url="https://x.com/", username="user", password="pass")
        session = _build_session(cfg)
        assert session.auth == ("user", "pass")

    def test_no_auth(self):
        cfg = CardDAVConfig(url="https://x.com/")
        session = _build_session(cfg)
        assert session.auth is None

    def test_client_cert(self):
        cfg = CardDAVConfig(
            url="https://x.com/",
            client_cert="/cert.pem",
            client_key="/key.pem",
        )
        session = _build_session(cfg)
        assert session.cert == ("/cert.pem", "/key.pem")

    def test_ca_cert(self):
        cfg = CardDAVConfig(url="https://x.com/", ca_cert="/ca.pem")
        session = _build_session(cfg)
        assert session.verify == "/ca.pem"

    def test_no_verify(self):
        cfg = CardDAVConfig(url="https://x.com/", verify_ssl=False)
        session = _build_session(cfg)
        assert session.verify is False

    def test_default_verify(self):
        cfg = CardDAVConfig(url="https://x.com/")
        session = _build_session(cfg)
        assert session.verify is True


class TestDiscoverVcards:
    def test_discover(self):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.text = PROPFIND_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_session.request.return_value = mock_response

        hrefs = _discover_vcards(mock_session, "https://dav.example.com/contacts/")
        assert len(hrefs) == 2
        assert "/contacts/john.vcf" in hrefs
        assert "/contacts/jane.vcf" in hrefs
        mock_session.request.assert_called_once()
        call_args = mock_session.request.call_args
        assert call_args[0][0] == "PROPFIND"
        assert call_args[0][1] == "https://dav.example.com/contacts/"

    def test_discover_no_vcf(self):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.text = """\
<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/contacts/</d:href>
  </d:response>
</d:multistatus>"""
        mock_response.raise_for_status = MagicMock()
        mock_session.request.return_value = mock_response

        hrefs = _discover_vcards(mock_session, "https://x.com/")
        assert hrefs == []


class TestFetchVcards:
    def test_fetch(self):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.text = REPORT_RESPONSE
        mock_response.raise_for_status = MagicMock()
        mock_session.request.return_value = mock_response

        contacts = _fetch_vcards(
            mock_session,
            "https://dav.example.com/contacts/",
            ["/contacts/john.vcf", "/contacts/jane.vcf"],
        )
        assert len(contacts) == 2
        assert contacts[0].fn.value == "John Doe"
        assert contacts[1].fn.value == "Jane Smith"

    def test_fetch_empty(self):
        mock_session = MagicMock()
        contacts = _fetch_vcards(mock_session, "https://x.com/", [])
        assert contacts == []
        mock_session.request.assert_not_called()


class TestFetchContacts:
    @patch("carddav_to_ldap.carddav._fetch_vcards")
    @patch("carddav_to_ldap.carddav._discover_vcards")
    @patch("carddav_to_ldap.carddav._build_session")
    def test_integration(self, mock_build, mock_discover, mock_fetch):
        mock_session = MagicMock()
        mock_build.return_value = mock_session
        mock_discover.return_value = ["/john.vcf"]
        mock_fetch.return_value = [MagicMock()]

        cfg = CardDAVConfig(url="https://dav.example.com/contacts/")
        result = fetch_contacts(cfg)

        assert len(result) == 1
        mock_build.assert_called_once_with(cfg)
        mock_discover.assert_called_once_with(mock_session, cfg.url)
        mock_fetch.assert_called_once_with(mock_session, cfg.url, ["/john.vcf"])


class TestCardDAVWithTLS:
    def test_session_with_mtls_config(self):
        cfg = CardDAVConfig(
            url="https://secure.example.com/",
            client_cert="/path/to/cert.pem",
            client_key="/path/to/key.pem",
            ca_cert="/path/to/ca.pem",
        )
        session = _build_session(cfg)
        assert session.cert == ("/path/to/cert.pem", "/path/to/key.pem")
        assert session.verify == "/path/to/ca.pem"
