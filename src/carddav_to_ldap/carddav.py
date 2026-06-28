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
