from __future__ import annotations

import vobject

from carddav_to_ldap.config import DEFAULT_ATTRIBUTE_MAPPING
from carddav_to_ldap.mapping import vcard_to_ldap_entry, _get_vcard_value, _escape_dn_value


class TestGetVcardValue:
    def test_fn(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "fn") == ["John Doe"]

    def test_n_family(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "n.family") == ["Doe"]

    def test_n_given(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "n.given") == ["John"]

    def test_email(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "email") == ["john@example.com"]

    def test_tel_all(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        vals = _get_vcard_value(vcard, "tel")
        assert "+1-555-0100" in vals
        assert "+1-555-0101" in vals
        assert "+1-555-0102" in vals
        assert len(vals) == 3

    def test_tel_cell(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "tel.cell") == ["+1-555-0101"]

    def test_tel_home(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "tel.home") == ["+1-555-0102"]

    def test_org(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "org") == ["Acme Inc."]

    def test_title(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "title") == ["Engineer"]

    def test_adr_street(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "adr.street") == ["123 Main St"]

    def test_adr_city(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "adr.city") == ["Springfield"]

    def test_missing_property(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "photo") == []

    def test_missing_sub_property(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "n.suffix") == []


class TestVcardToLdapEntry:
    def test_full_contact(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=carddav2ldap,dc=mwllgr,dc=at")
        assert entry is not None
        assert entry["dn"] == "cn=John Doe,dc=carddav2ldap,dc=mwllgr,dc=at"
        attrs = entry["attributes"]
        assert attrs["cn"] == ["John Doe"]
        assert attrs["sn"] == ["Doe"]
        assert attrs["givenName"] == ["John"]
        assert attrs["mail"] == ["john@example.com"]
        assert "+1-555-0100" in attrs["telephoneNumber"]
        assert "+1-555-0101" in attrs["telephoneNumber"]
        assert "+1-555-0102" in attrs["telephoneNumber"]
        assert attrs["mobile"] == ["+1-555-0101"]
        assert attrs["homePhone"] == ["+1-555-0102"]
        assert attrs["workPhone"] == ["+1-555-0100"]
        assert "inetOrgPerson" in attrs["objectClass"]

    def test_minimal_contact(self, sample_vcard_minimal):
        vcard = vobject.readOne(sample_vcard_minimal)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["cn"] == ["Jane Smith"]
        assert entry["attributes"]["sn"] == ["Smith"]

    def test_no_fn_uses_n(self, sample_vcard_no_fn):
        vcard = vobject.readOne(sample_vcard_no_fn)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["cn"] == ["Charlie Brown"]

    def test_completely_empty_vcard(self):
        vcard = vobject.readOne("BEGIN:VCARD\nVERSION:3.0\nEND:VCARD")
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is None

    def test_multiple_phones(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Multi Phone
TEL;TYPE=WORK:+1-111-0001
TEL;TYPE=WORK:+1-111-0002
TEL;TYPE=CELL:+1-111-0003
TEL;TYPE=CELL:+1-111-0004
TEL;TYPE=HOME:+1-111-0005
TEL:+1-111-0006
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        attrs = entry["attributes"]
        assert len(attrs["telephoneNumber"]) == 6
        assert attrs["mobile"] == ["+1-111-0003", "+1-111-0004"]
        assert attrs["homePhone"] == ["+1-111-0005"]

    def test_custom_mapping(self, sample_vcard_text):
        mapping = {"displayName": ["fn"], "phone": ["tel.cell"]}
        vcard = vobject.readOne(sample_vcard_text)
        entry = vcard_to_ldap_entry(vcard, mapping, "dc=test")
        assert entry is not None
        assert entry["attributes"]["displayName"] == ["John Doe"]
        assert entry["attributes"]["phone"] == ["+1-555-0101"]


class TestEscapeDnValue:
    def test_plain(self):
        assert _escape_dn_value("John Doe") == "John Doe"

    def test_comma(self):
        assert _escape_dn_value("Doe, John") == "Doe\\, John"

    def test_leading_space(self):
        assert _escape_dn_value(" John") == "\\ John"

    def test_trailing_space(self):
        assert _escape_dn_value("John ") == "John\\ "

    def test_special_chars(self):
        assert _escape_dn_value('a+b"c') == 'a\\+b\\"c'
