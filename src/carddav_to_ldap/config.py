from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import yaml


ENV_PREFIX_CARDDAV = "CARDDAV_"
ENV_PREFIX_LDAP = "LDAP_"


def _env_override(prefix: str, field_name: str, field_type: type, current: object) -> object:
    env_key = prefix + field_name.upper()
    val = os.environ.get(env_key)
    if val is None:
        return current
    if field_type is bool:
        return val.lower() in ("1", "true", "yes")
    if field_type is int:
        return int(val)
    if field_type is float:
        return float(val)
    return val


@dataclasses.dataclass
class CardDAVConfig:
    url: str = ""
    username: str = ""
    password: str = ""
    ca_cert: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    verify_ssl: bool = True
    refresh_interval: int = 300
    realtime: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> CardDAVConfig:
        inst = cls(**{k: v for k, v in d.items() if k in {f.name for f in dataclasses.fields(cls)}})
        inst._apply_env()
        return inst

    def _apply_env(self) -> None:
        for f in dataclasses.fields(self):
            origin = f.type
            base = _unwrap_optional(origin)
            new_val = _env_override(ENV_PREFIX_CARDDAV, f.name, base, getattr(self, f.name))
            setattr(self, f.name, new_val)


@dataclasses.dataclass
class LDAPServerConfig:
    host: str = "0.0.0.0"
    port: int = 0
    base_dn: str = "dc=carddav2ldap,dc=mwllgr,dc=at"
    bind_dn: str = ""
    bind_password: str = ""
    tls_cert: str | None = None
    tls_key: str | None = None
    tls_ca: str | None = None
    require_client_cert: bool = False
    allowed_client_cns: list[str] = dataclasses.field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> LDAPServerConfig:
        inst = cls(**{k: v for k, v in d.items() if k in {f.name for f in dataclasses.fields(cls)}})
        inst._apply_env()
        return inst

    @property
    def effective_port(self) -> int:
        if self.port != 0:
            return self.port
        return 636 if self.tls_cert else 389

    def _apply_env(self) -> None:
        for f in dataclasses.fields(self):
            if f.name == "allowed_client_cns":
                val = os.environ.get("LDAP_ALLOWED_CLIENT_CNS")
                if val is not None:
                    self.allowed_client_cns = [cn.strip() for cn in val.split(",") if cn.strip()]
                continue
            origin = f.type
            base = _unwrap_optional(origin)
            new_val = _env_override(ENV_PREFIX_LDAP, f.name, base, getattr(self, f.name))
            setattr(self, f.name, new_val)


def _unwrap_optional(type_hint: object) -> type:
    """Best-effort extraction of the base type from 'str | None' style hints stored as strings."""
    if isinstance(type_hint, str):
        cleaned = type_hint.replace(" ", "")
        if cleaned.endswith("|None") or cleaned.startswith("None|"):
            cleaned = cleaned.replace("|None", "").replace("None|", "")
        type_map = {"str": str, "int": int, "float": float, "bool": bool}
        return type_map.get(cleaned, str)
    return type_hint if isinstance(type_hint, type) else str


DEFAULT_ATTRIBUTE_MAPPING = {
    "cn": ["fn"],
    "sn": ["n.family"],
    "givenName": ["n.given"],
    "mail": ["email"],
    "telephoneNumber": ["tel"],
    "mobile": ["tel.cell"],
    "homePhone": ["tel.home"],
    "workPhone": ["tel.work"],
    "facsimileTelephoneNumber": ["tel.fax"],
    "pager": ["tel.pager"],
    "title": ["title"],
    "o": ["org"],
    "street": ["adr.street"],
    "l": ["adr.city"],
    "st": ["adr.region"],
    "postalCode": ["adr.code"],
    "c": ["adr.country"],
}


@dataclasses.dataclass
class Config:
    carddav: CardDAVConfig
    ldap: LDAPServerConfig
    attribute_mapping: dict[str, list[str]]

    @classmethod
    def from_dict(cls, d: dict) -> Config:
        carddav = CardDAVConfig.from_dict(d.get("carddav", {}))
        ldap = LDAPServerConfig.from_dict(d.get("ldap", {}))
        mapping = d.get("attribute_mapping", DEFAULT_ATTRIBUTE_MAPPING)
        return cls(carddav=carddav, ldap=ldap, attribute_mapping=mapping)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        with open(path) as f:
            return cls.from_dict(yaml.safe_load(f) or {})

    @classmethod
    def from_env(cls) -> Config:
        return cls.from_dict({})
