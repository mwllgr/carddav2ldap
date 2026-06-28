from __future__ import annotations

import vobject

from carddav2ldap.config import DEFAULT_ATTRIBUTE_MAPPING
from carddav2ldap.mapping import vcard_to_ldap_entry, _get_vcard_value, _escape_dn_value, _to_pascal_case


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

    def test_uid(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "uid") == ["42fd302c-d119-476c-b19e-18b8f60d18f1"]

    def test_prodid(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "prodid") == ["+//IDN bitfire.at//DAVx5/4.2.6-ose ez-vcard/0.11.3"]

    def test_rev(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "rev") == ["20230108T130105Z"]

    def test_bday(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "bday") == ["20031220"]

    def test_photo_binary(self):
        vcard_text = (
            "BEGIN:VCARD\r\n"
            "VERSION:3.0\r\n"
            "FN:Photo Person\r\n"
            "PHOTO;ENCODING=b;TYPE=JPEG:AQID\r\n"
            "END:VCARD"
        )
        vcard = vobject.readOne(vcard_text)
        vals = _get_vcard_value(vcard, "photo")
        assert len(vals) == 1
        import base64
        assert base64.b64decode(vals[0]) == b"\x01\x02\x03"

    def test_email(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        vals = _get_vcard_value(vcard, "email")
        assert "john@example.com" in vals
        assert "john.doe@home.example.com" in vals
        assert len(vals) == 2

    def test_email_work(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "email.work") == ["john@example.com"]

    def test_email_home(self, sample_vcard_text):
        vcard = vobject.readOne(sample_vcard_text)
        assert _get_vcard_value(vcard, "email.home") == ["john.doe@home.example.com"]

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
        assert _get_vcard_value(vcard, "org") == ["Acme Inc.", "Engineering"]

    def test_org_name_sub(self):
        vcard = vobject.readOne("BEGIN:VCARD\nVERSION:3.0\nFN:X\nORG:Compano;Departo\nEND:VCARD")
        assert _get_vcard_value(vcard, "org.name") == ["Compano"]

    def test_org_department_sub(self):
        vcard = vobject.readOne("BEGIN:VCARD\nVERSION:3.0\nFN:X\nORG:Compano;Departo\nEND:VCARD")
        assert _get_vcard_value(vcard, "org.department") == ["Departo"]

    def test_org_department_missing(self):
        vcard = vobject.readOne("BEGIN:VCARD\nVERSION:3.0\nFN:X\nORG:Compano\nEND:VCARD")
        assert _get_vcard_value(vcard, "org.department") == []

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
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "ou=Contacts,dc=carddav2ldap,dc=mwllgr,dc=at")
        assert entry is not None
        uid = "42fd302c-d119-476c-b19e-18b8f60d18f1"
        assert entry["dn"] == f"cn=John Doe ({uid}),ou=Contacts,dc=carddav2ldap,dc=mwllgr,dc=at"
        attrs = entry["attributes"]
        assert attrs["cn"] == [f"John Doe ({uid})"]
        assert attrs["displayName"] == ["John Doe"]
        assert attrs["sn"] == ["Doe"]
        assert attrs["givenName"] == ["John"]
        assert attrs["mail"] == ["john@example.com", "john.doe@home.example.com"]
        assert attrs["workEmail"] == ["john@example.com"]
        assert attrs["homeEmail"] == ["john.doe@home.example.com"]
        assert "+1-555-0100" in attrs["telephoneNumber"]
        assert "+1-555-0101" in attrs["telephoneNumber"]
        assert "+1-555-0102" in attrs["telephoneNumber"]
        assert attrs["mobile"] == ["+1-555-0101"]
        assert attrs["homePhone"] == ["+1-555-0102"]
        assert attrs["workPhone"] == ["+1-555-0100"]
        assert attrs["o"] == ["Acme Inc."]
        assert attrs["ou"] == ["Engineering"]
        assert attrs["title"] == ["Engineer"]
        assert "inetOrgPerson" in attrs["objectClass"]

    def test_minimal_contact_no_uid(self, sample_vcard_minimal):
        vcard = vobject.readOne(sample_vcard_minimal)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["cn"] == ["Jane Smith"]
        assert entry["attributes"]["displayName"] == ["Jane Smith"]
        assert entry["attributes"]["sn"] == ["?"]

    def test_no_fn_uses_n(self, sample_vcard_no_fn):
        vcard = vobject.readOne(sample_vcard_no_fn)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["cn"] == ["Charlie Brown"]
        assert entry["attributes"]["displayName"] == ["Charlie Brown"]

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
        mapping = {"cn": ["fn"], "phone": ["tel.cell"]}
        vcard = vobject.readOne(sample_vcard_text)
        entry = vcard_to_ldap_entry(vcard, mapping, "dc=test")
        assert entry is not None
        assert entry["attributes"]["displayName"] == ["John Doe"]
        assert entry["attributes"]["phone"] == ["+1-555-0101"]

    def test_labeled_telephone(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Labeled Person
ITEM1.X-ABLABEL:Mobile
ITEM1.TEL:+43 677 62951924
TEL;TYPE=HOME:+1-555-0100
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        attrs = entry["attributes"]
        assert "+43 677 62951924" in attrs["telephoneNumber"]
        assert "+1-555-0100" in attrs["telephoneNumber"]
        assert attrs["customTelephoneMobile"] == ["+43 677 62951924"]

    def test_labeled_email(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Labeled Person
ITEM1.X-ABLABEL:Office
ITEM1.EMAIL:office@example.com
EMAIL;TYPE=HOME:home@example.com
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        attrs = entry["attributes"]
        assert "office@example.com" in attrs["mail"]
        assert "home@example.com" in attrs["mail"]
        assert attrs["customEmailOffice"] == ["office@example.com"]

    def test_labeled_address(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Labeled Person
ITEM1.X-ABLABEL:Vacation Home
ITEM1.ADR:;;42 Beach Rd;Miami;FL;33101;US
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        attrs = entry["attributes"]
        assert attrs["customAddressVacationHome"] == ["42 Beach Rd, Miami, FL, 33101, US"]

    def test_labeled_multi_word_pascal_case(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Labeled Person
ITEM1.X-ABLABEL:work mobile
ITEM1.TEL:+1-555-9999
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["customTelephoneWorkMobile"] == ["+1-555-9999"]

    def test_labeled_special_chars_sanitized(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Labeled Person
ITEM1.X-ABLABEL:My Phone #1!
ITEM1.TEL:+1-555-8888
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["customTelephoneMyPhone1"] == ["+1-555-8888"]

    def test_multiple_labeled_groups(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Multi Label
ITEM1.X-ABLABEL:Cabin
ITEM1.TEL:+1-111-0001
ITEM2.X-ABLABEL:Boat
ITEM2.TEL:+1-111-0002
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        attrs = entry["attributes"]
        assert attrs["customTelephoneCabin"] == ["+1-111-0001"]
        assert attrs["customTelephoneBoat"] == ["+1-111-0002"]
        assert "+1-111-0001" in attrs["telephoneNumber"]
        assert "+1-111-0002" in attrs["telephoneNumber"]


    def test_org_name_and_department(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Org Person
ORG:Compano;Departo
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["o"] == ["Compano"]
        assert entry["attributes"]["ou"] == ["Departo"]

    def test_org_name_only(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Org Person
ORG:Compano
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["o"] == ["Compano"]
        assert "ou" not in entry["attributes"]

    def test_nickname(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Jonathan Doe
NICKNAME:Johnny
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["nickName"] == ["Johnny"]

    def test_url(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Web Person
URL:https://example.com
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["labeledURI"] == ["https://example.com"]

    def test_phonetic_names(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Test Person
X-PHONETIC-FIRST-NAME:Yoh-han
X-PHONETIC-LAST-NAME:Doh
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["phoneticFirstName"] == ["Yoh-han"]
        assert entry["attributes"]["phoneticLastName"] == ["Doh"]

    def test_related_typed(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Related Person
RELATED;TYPE=spouse;VALUE=text:Jane Doe
RELATED;TYPE=assistant;VALUE=text:Alice
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["relatedSpouse"] == ["Jane Doe"]
        assert entry["attributes"]["relatedAssistant"] == ["Alice"]

    def test_related_multi_type(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Related Person
RELATED;TYPE=assistant,co-worker;VALUE=text:CoWorkerName
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["relatedAssistant"] == ["CoWorkerName"]
        assert entry["attributes"]["relatedCoWorker"] == ["CoWorkerName"]

    def test_related_untyped(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Related Person
RELATED;VALUE=text:Someone
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["relatedPerson"] == ["Someone"]

    def test_cn_includes_uid(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:John Doe
UID:abc-123
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        assert entry["attributes"]["cn"] == ["John Doe (abc-123)"]
        assert entry["attributes"]["displayName"] == ["John Doe"]
        assert entry["dn"] == "cn=John Doe (abc-123),dc=test"


    def test_unmapped_properties(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Unmapped Person
X-CUSTOM-FIELD:custom value
X-ANOTHER:another value
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        attrs = entry["attributes"]
        assert attrs["vcfUnmappedXCustomField"] == ["custom value"]
        assert attrs["vcfUnmappedXAnother"] == ["another value"]

    def test_unmapped_skips_mapped_properties(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Test Person
TEL:+1-555-0100
X-WEIRD:weird value
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        attrs = entry["attributes"]
        assert "vcfUnmappedTel" not in attrs
        assert "vcfUnmappedFn" not in attrs
        assert "vcfUnmappedVersion" not in attrs
        assert attrs["vcfUnmappedXWeird"] == ["weird value"]

    def test_unmapped_skips_grouped_properties(self):
        vcard_text = """\
BEGIN:VCARD
VERSION:3.0
FN:Test Person
ITEM1.X-ABLABEL:Custom
ITEM1.TEL:+1-555-0100
X-SOLO:solo value
END:VCARD"""
        vcard = vobject.readOne(vcard_text)
        entry = vcard_to_ldap_entry(vcard, DEFAULT_ATTRIBUTE_MAPPING, "dc=test")
        assert entry is not None
        attrs = entry["attributes"]
        assert "vcfUnmappedXAblabel" not in attrs
        assert attrs["vcfUnmappedXSolo"] == ["solo value"]


class TestToPascalCase:
    def test_single_word(self):
        assert _to_pascal_case("mobile") == "Mobile"

    def test_multi_word(self):
        assert _to_pascal_case("work mobile") == "WorkMobile"

    def test_special_chars(self):
        assert _to_pascal_case("my phone #1!") == "MyPhone1"

    def test_already_capitalized(self):
        assert _to_pascal_case("Office") == "Office"

    def test_mixed_separators(self):
        assert _to_pascal_case("home-office_phone") == "HomeOfficePhone"


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
