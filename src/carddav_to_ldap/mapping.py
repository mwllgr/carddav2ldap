from __future__ import annotations

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
            if isinstance(val, str) and val.strip():
                values.append(val.strip())
            elif isinstance(val, list):
                values.extend(v.strip() for v in val if isinstance(v, str) and v.strip())
        return values

    sub = parts[1].lower()

    if prop_name == "tel":
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

    cn = attrs["cn"][0]
    dn = f"cn={_escape_dn_value(cn)},{base_dn}"

    attrs["objectClass"] = ["top", "person", "organizationalPerson", "inetOrgPerson"]

    if "sn" not in attrs:
        attrs["sn"] = [cn.split()[-1] if " " in cn else cn]

    return {"dn": dn, "attributes": attrs}


def _escape_dn_value(val: str) -> str:
    special = {',', '+', '"', '\\', '<', '>', ';', '#', '='}
    result = []
    for i, c in enumerate(val):
        if c in special or (i == 0 and c == ' ') or (i == len(val) - 1 and c == ' '):
            result.append(f"\\{c}")
        else:
            result.append(c)
    return "".join(result)
