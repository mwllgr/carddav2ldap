from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

import requests
import vobject

from .config import CardDAVConfig

logger = logging.getLogger(__name__)

DAV_NS = "DAV:"
CARDDAV_NS = "urn:ietf:params:xml:ns:carddav"


def _build_session(cfg: CardDAVConfig) -> requests.Session:
    session = requests.Session()
    if cfg.username:
        session.auth = (cfg.username, cfg.password)
    if cfg.client_cert and cfg.client_key:
        session.cert = (cfg.client_cert, cfg.client_key)
    elif cfg.client_cert:
        session.cert = cfg.client_cert
    if cfg.ca_cert:
        session.verify = cfg.ca_cert
    elif not cfg.verify_ssl:
        session.verify = False
    return session


ADDRESSBOOK_MULTIGET_BODY = """\
<?xml version="1.0" encoding="utf-8"?>
<c:addressbook-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:getetag/>
    <c:address-data/>
  </d:prop>
  {hrefs}
</c:addressbook-multiget>"""

PROPFIND_BODY = """\
<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:resourcetype/>
    <d:getetag/>
  </d:prop>
</d:propfind>"""


def _discover_vcards(session: requests.Session, url: str) -> list[str]:
    resp = session.request("PROPFIND", url, data=PROPFIND_BODY, headers={
        "Content-Type": "application/xml; charset=utf-8",
        "Depth": "1",
    })
    resp.raise_for_status()

    root = ET.fromstring(resp.text)
    hrefs: list[str] = []
    for response_el in root.iter(f"{{{DAV_NS}}}response"):
        href_el = response_el.find(f"{{{DAV_NS}}}href")
        if href_el is not None and href_el.text:
            href = href_el.text
            if href.endswith(".vcf"):
                hrefs.append(href)
    return hrefs


def _fetch_vcards(session: requests.Session, url: str, hrefs: list[str]) -> list[vobject.base.Component]:
    if not hrefs:
        return []

    href_xml = "\n".join(f'  <d:href>{h}</d:href>' for h in hrefs)
    body = ADDRESSBOOK_MULTIGET_BODY.format(hrefs=href_xml)

    resp = session.request("REPORT", url, data=body, headers={
        "Content-Type": "application/xml; charset=utf-8",
        "Depth": "1",
    })
    resp.raise_for_status()

    root = ET.fromstring(resp.text)
    contacts: list[vobject.base.Component] = []
    for response_el in root.iter(f"{{{DAV_NS}}}response"):
        data_el = response_el.find(f".//{{{CARDDAV_NS}}}address-data")
        if data_el is not None and data_el.text:
            try:
                contacts.append(vobject.readOne(data_el.text))
            except Exception:
                logger.warning("Failed to parse vCard from %s", url, exc_info=True)
    return contacts


def fetch_contacts(cfg: CardDAVConfig) -> list[vobject.base.Component]:
    session = _build_session(cfg)
    hrefs = _discover_vcards(session, cfg.url)
    logger.info("Discovered %d vCard resources", len(hrefs))
    return _fetch_vcards(session, cfg.url, hrefs)


LDAP_ATTR_TO_VCARD_PROPS: dict[str, list[str]] = {
    "cn": ["FN"],
    "sn": ["N"],
    "givenname": ["N"],
    "mail": ["EMAIL"],
    "telephonenumber": ["TEL"],
    "mobile": ["TEL"],
    "homephone": ["TEL"],
    "workphone": ["TEL"],
    "facsimiletelephonenumber": ["TEL"],
    "pager": ["TEL"],
    "o": ["ORG"],
    "title": ["TITLE"],
}

ADDRESSBOOK_QUERY_BODY = """\
<?xml version="1.0" encoding="utf-8"?>
<c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:getetag/>
    <c:address-data/>
  </d:prop>
  {filter}
</c:addressbook-query>"""


def _xml_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def build_carddav_filter(terms: list[tuple[str, str]]) -> str:
    if not terms:
        return ""

    prop_filters: list[str] = []
    seen: set[tuple[str, str]] = set()

    for attr, value in terms:
        vcard_props = LDAP_ATTR_TO_VCARD_PROPS.get(attr.lower(), ["FN"])
        for prop in vcard_props:
            key = (prop, value.lower())
            if key in seen:
                continue
            seen.add(key)
            escaped = _xml_escape(value)
            prop_filters.append(
                f'<c:prop-filter name="{prop}">'
                f'<c:text-match collation="i;unicode-casemap" match-type="contains">{escaped}</c:text-match>'
                f'</c:prop-filter>'
            )

    if not prop_filters:
        return ""

    return f'<c:filter test="anyof">{"".join(prop_filters)}</c:filter>'


def search_contacts(cfg: CardDAVConfig, terms: list[tuple[str, str]]) -> list[vobject.base.Component]:
    session = _build_session(cfg)
    carddav_filter = build_carddav_filter(terms)
    body = ADDRESSBOOK_QUERY_BODY.format(filter=carddav_filter)

    logger.debug("CardDAV addressbook-query with %d filter terms", len(terms))

    resp = session.request("REPORT", cfg.url, data=body, headers={
        "Content-Type": "application/xml; charset=utf-8",
        "Depth": "1",
    })
    resp.raise_for_status()

    root = ET.fromstring(resp.text)
    contacts: list[vobject.base.Component] = []
    for response_el in root.iter(f"{{{DAV_NS}}}response"):
        data_el = response_el.find(f".//{{{CARDDAV_NS}}}address-data")
        if data_el is not None and data_el.text:
            try:
                contacts.append(vobject.readOne(data_el.text))
            except Exception:
                logger.warning("Failed to parse vCard", exc_info=True)

    logger.debug("CardDAV returned %d contacts", len(contacts))
    return contacts
