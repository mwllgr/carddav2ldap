from __future__ import annotations

import base64
import logging
from typing import Any

import vobject

logger = logging.getLogger(__name__)


def _get_vcard_value(vcard: vobject.base.Component, path: str) -> list[str]:
    parts = path.split(".", 1)
    prop_name = parts[0].lower()

    matching = [c for c in vcard.getChildren() if c.name.lower() == prop_name]
    if not matching:
        return []

    if len(parts) == 1:
        values: list[str] = []
        for child in matching:
            val = child.value
            if isinstance(val, bytes):
                values.append(base64.b64encode(val).decode("ascii"))
            elif isinstance(val, str) and val.strip():
                values.append(val.strip())
            elif isinstance(val, list):
                values.extend(v.strip() for v in val if isinstance(v, str) and v.strip())
        return values

    sub = parts[1].lower()

    if prop_name in ("tel", "email"):
        type_map = {"cell": "CELL", "home": "HOME", "work": "WORK"}
        target_type = type_map.get(sub, sub.upper())
        values = []
        for child in matching:
            type_params = [p.upper() for p in child.params.get("TYPE", [])]
            if target_type in type_params:
                val = child.value if isinstance(child.value, str) else str(child.value)
                if val.strip():
                    values.append(val.strip())
        return values

    if prop_name == "n":
        field_map = {"family": 0, "given": 1, "additional": 2, "prefix": 3, "suffix": 4}
        idx = field_map.get(sub)
        if idx is not None:
            for child in matching:
                n = child.value
                val = getattr(n, sub, "") if hasattr(n, sub) else ""
                if isinstance(val, str) and val.strip():
                    return [val.strip()]
        return []

    if prop_name == "org":
        field_map = {"name": 0, "department": 1}
        idx = field_map.get(sub)
        if idx is not None:
            for child in matching:
                val = child.value
                if isinstance(val, list) and len(val) > idx:
                    v = val[idx].strip() if isinstance(val[idx], str) else ""
                    if v:
                        return [v]
        return []

    if prop_name == "adr":
        field_map = {
            "pobox": "box", "extended": "extended", "street": "street",
            "city": "city", "region": "region", "code": "code", "country": "country",
        }
        attr = field_map.get(sub, sub)
        for child in matching:
            adr = child.value
            val = getattr(adr, attr, "") if hasattr(adr, attr) else ""
            if isinstance(val, str) and val.strip():
                return [val.strip()]
        return []

    return []


def vcard_to_ldap_entry(
    vcard: vobject.base.Component,
    attribute_mapping: dict[str, list[str]],
    base_dn: str,
) -> dict[str, Any] | None:
    attrs: dict[str, list[str]] = {}

    for ldap_attr, vcard_paths in attribute_mapping.items():
        values: list[str] = []
        for path in vcard_paths:
            values.extend(_get_vcard_value(vcard, path))
        if values:
            attrs[ldap_attr] = values

    if not attrs.get("cn"):
        fn_children = [c for c in vcard.getChildren() if c.name.lower() == "fn"]
        if fn_children:
            fn_val = fn_children[0].value
            if isinstance(fn_val, str) and fn_val.strip():
                attrs["cn"] = [fn_val.strip()]

    if not attrs.get("cn"):
        parts = []
        if attrs.get("givenName"):
            parts.append(attrs["givenName"][0])
        if attrs.get("sn"):
            parts.append(attrs["sn"][0])
        if parts:
            attrs["cn"] = [" ".join(parts)]

    if not attrs.get("cn"):
        return None

    display_name = attrs["cn"][0]
    attrs["displayName"] = [display_name]

    uid_val = attrs.get("uid", [""])[0]
    cn = f"{display_name} ({uid_val})" if uid_val else display_name
    attrs["cn"] = [cn]

    dn = f"cn={_escape_dn_value(cn)},{base_dn}"

    attrs["objectClass"] = ["top", "person", "organizationalPerson", "inetOrgPerson"]

    if "sn" not in attrs:
        attrs["sn"] = ["?"]

    _apply_labeled_groups(vcard, attrs)
    _apply_related(vcard, attrs)
    _apply_unmapped(vcard, attribute_mapping, attrs)

    return {"dn": dn, "attributes": attrs}


_LABELED_PROP_PREFIXES = {
    "TEL": "customTelephone",
    "EMAIL": "customEmail",
    "ADR": "customAddress",
}


def _to_pascal_case(label: str) -> str:
    import re
    words = re.split(r'[^a-zA-Z0-9]+', label)
    return "".join(w.capitalize() for w in words if w)


def _format_adr(adr: object) -> str:
    parts = []
    for attr in ("street", "city", "region", "code", "country"):
        val = getattr(adr, attr, "")
        if isinstance(val, str) and val.strip():
            parts.append(val.strip())
    return ", ".join(parts)


def _apply_labeled_groups(vcard: vobject.base.Component, attrs: dict[str, list[str]]) -> None:
    children = list(vcard.getChildren())

    labels: dict[str, str] = {}
    for c in children:
        if c.group and c.name.upper() == "X-ABLABEL":
            val = c.value if isinstance(c.value, str) else ""
            if val.strip():
                labels[c.group.upper()] = val.strip()

    for c in children:
        if not c.group:
            continue
        group_key = c.group.upper()
        label = labels.get(group_key)
        if not label:
            continue
        prop = c.name.upper()
        prefix = _LABELED_PROP_PREFIXES.get(prop)
        if not prefix:
            continue

        pascal_label = _to_pascal_case(label)
        attr_name = f"{prefix}{pascal_label}"

        if prop == "ADR":
            val = _format_adr(c.value)
        elif isinstance(c.value, str):
            val = c.value.strip()
        else:
            val = str(c.value).strip()

        if val:
            attrs.setdefault(attr_name, []).append(val)


def _apply_related(vcard: vobject.base.Component, attrs: dict[str, list[str]]) -> None:
    for child in vcard.getChildren():
        if child.name.upper() != "RELATED":
            continue
        val = child.value if isinstance(child.value, str) else str(child.value)
        val = val.strip()
        if not val:
            continue
        types = [t.lower() for t in child.params.get("TYPE", [])]
        types = [t for t in types if t != "text"]
        if types:
            for t in types:
                attr_name = f"related{_to_pascal_case(t)}"
                attrs.setdefault(attr_name, []).append(val)
        else:
            attrs.setdefault("relatedPerson", []).append(val)


_SKIP_UNMAPPED = {"VERSION", "FN", "N", "X-ABLABEL", "RELATED"}


def _apply_unmapped(
    vcard: vobject.base.Component,
    attribute_mapping: dict[str, list[str]],
    attrs: dict[str, list[str]],
) -> None:
    mapped_props: set[str] = set()
    for vcard_paths in attribute_mapping.values():
        for path in vcard_paths:
            mapped_props.add(path.split(".")[0].lower())

    for child in vcard.getChildren():
        if child.group:
            continue
        prop = child.name.upper()
        if prop in _SKIP_UNMAPPED:
            continue
        if child.name.lower() in mapped_props:
            continue

        attr_name = f"vcfUnmapped{_to_pascal_case(child.name)}"
        val = child.value
        if isinstance(val, bytes):
            text = base64.b64encode(val).decode("ascii")
        elif isinstance(val, str):
            text = val.strip()
        elif isinstance(val, list):
            text = ", ".join(v.strip() for v in val if isinstance(v, str) and v.strip())
        else:
            text = str(val).strip()

        if text:
            attrs.setdefault(attr_name, []).append(text)


def _escape_dn_value(val: str) -> str:
    special = {',', '+', '"', '\\', '<', '>', ';', '#', '='}
    result = []
    for i, c in enumerate(val):
        if c == '\x00':
            result.append('\\00')
        elif c in special or (i == 0 and c == ' ') or (i == len(val) - 1 and c == ' '):
            result.append(f"\\{c}")
        else:
            result.append(c)
    return "".join(result)
