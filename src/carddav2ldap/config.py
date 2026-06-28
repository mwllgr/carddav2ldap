from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import yaml


ENV_PREFIX_CARDDAV = "C2L_CARDDAV_"
ENV_PREFIX_LDAP = "C2L_LDAP_"


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
    http3: bool = False
    forward_requester: bool = True

    @classmethod
    def from_dict(cls, d: dict, apply_env: bool = True) -> CardDAVConfig:
        inst = cls(**{k: v for k, v in d.items() if k in {f.name for f in dataclasses.fields(cls)}})
        if apply_env:
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
    base_dn: str = "ou=Contacts,dc=carddav2ldap,dc=mwllgr,dc=at"
    tls_cert: str | None = None
    tls_key: str | None = None
    tls_ca: str | None = None
    require_client_cert: bool = False
    allowed_client_cns: list[str] = dataclasses.field(default_factory=list)
    plaintext_port: int = 0

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
                val = os.environ.get("C2L_LDAP_ALLOWED_CLIENT_CNS")
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
    "uid": ["uid"],
    "cn": ["fn"],
    "sn": ["n.family"],
    "givenName": ["n.given"],
    "middleName": ["n.additional"],
    "namePrefix": ["n.prefix"],
    "nameSuffix": ["n.suffix"],
    "nickName": ["nickname"],
    "phoneticFirstName": ["x-phonetic-first-name"],
    "phoneticLastName": ["x-phonetic-last-name"],
    "mail": ["email"],
    "workEmail": ["email.work"],
    "homeEmail": ["email.home"],
    "telephoneNumber": ["tel"],
    "mobile": ["tel.cell"],
    "homePhone": ["tel.home"],
    "workPhone": ["tel.work"],
    "facsimileTelephoneNumber": ["tel.fax"],
    "pager": ["tel.pager"],
    "title": ["title"],
    "o": ["org.name"],
    "ou": ["org.department"],
    "labeledURI": ["url"],
    "street": ["adr.street"],
    "l": ["adr.city"],
    "st": ["adr.region"],
    "postalCode": ["adr.code"],
    "c": ["adr.country"],
    "rev": ["rev"],
    "createdByApplication": ["prodid"],
    "businessCategory": ["categories"],
    "description": ["note"],
    "birthday": ["bday"],
    "jpegPhoto": ["photo"],
}


@dataclasses.dataclass
class Account:
    bind_dn: str = ""
    bind_password: str = ""
    carddav: CardDAVConfig = dataclasses.field(default_factory=CardDAVConfig)

    _NON_INHERITABLE = {"url", "username", "password"}

    @classmethod
    def from_dict(cls, d: dict, carddav_defaults: CardDAVConfig) -> Account:
        default_dict = {
            f.name: getattr(carddav_defaults, f.name)
            for f in dataclasses.fields(CardDAVConfig)
            if f.name not in cls._NON_INHERITABLE
        }
        merged = {**default_dict, **d.get("carddav", {})}
        carddav = CardDAVConfig.from_dict(merged, apply_env=False)
        return cls(
            bind_dn=d.get("bind_dn", ""),
            bind_password=d.get("bind_password", ""),
            carddav=carddav,
        )


_ACCOUNT_CARDDAV_FIELDS: dict[str, str] = {
    "URL": "url",
    "USERNAME": "username",
    "PASSWORD": "password",
    "CA_CERT": "ca_cert",
    "CLIENT_CERT": "client_cert",
    "CLIENT_KEY": "client_key",
    "VERIFY_SSL": "verify_ssl",
    "REFRESH_INTERVAL": "refresh_interval",
    "REALTIME": "realtime",
    "HTTP3": "http3",
    "FORWARD_REQUESTER": "forward_requester",
}


def _accounts_from_env(carddav_defaults: CardDAVConfig) -> list[Account]:
    indices: set[int] = set()
    prefix = "C2L_ACCOUNT_"
    for key in os.environ:
        if key.startswith(prefix):
            rest = key[len(prefix):]
            parts = rest.split("_", 1)
            if parts[0].isdigit():
                indices.add(int(parts[0]))

    if not indices:
        return []

    accounts: list[Account] = []
    for idx in sorted(indices):
        p = f"{prefix}{idx}_"
        bind_dn = os.environ.get(f"{p}BIND_DN", "")
        bind_password = os.environ.get(f"{p}BIND_PASSWORD", "")

        carddav_overrides: dict = {}
        carddav_field_types = {f.name: _unwrap_optional(f.type) for f in dataclasses.fields(CardDAVConfig)}
        for env_suffix, field_name in _ACCOUNT_CARDDAV_FIELDS.items():
            val = os.environ.get(f"{p}CARDDAV_{env_suffix}")
            if val is not None:
                ft = carddav_field_types.get(field_name, str)
                if ft is bool:
                    carddav_overrides[field_name] = val.lower() in ("1", "true", "yes")
                elif ft is int:
                    carddav_overrides[field_name] = int(val)
                else:
                    carddav_overrides[field_name] = val

        default_dict = {
            f.name: getattr(carddav_defaults, f.name)
            for f in dataclasses.fields(CardDAVConfig)
            if f.name not in Account._NON_INHERITABLE
        }
        merged = {**default_dict, **carddav_overrides}
        carddav = CardDAVConfig.from_dict(merged, apply_env=False)

        accounts.append(Account(bind_dn=bind_dn, bind_password=bind_password, carddav=carddav))

    return accounts


@dataclasses.dataclass
class Config:
    carddav: CardDAVConfig
    ldap: LDAPServerConfig
    attribute_mapping: dict[str, list[str]]
    accounts: list[Account]

    @classmethod
    def from_dict(cls, d: dict) -> Config:
        carddav = CardDAVConfig.from_dict(d.get("carddav", {}))
        ldap = LDAPServerConfig.from_dict(d.get("ldap", {}))
        mapping = d.get("attribute_mapping", DEFAULT_ATTRIBUTE_MAPPING)

        if "accounts" in d:
            accounts = [Account.from_dict(a, carddav) for a in d["accounts"]]
        else:
            accounts = []

        env_accounts = _accounts_from_env(carddav)
        if env_accounts:
            accounts = env_accounts

        return cls(carddav=carddav, ldap=ldap, attribute_mapping=mapping, accounts=accounts)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        with open(path) as f:
            return cls.from_dict(yaml.safe_load(f) or {})

    @classmethod
    def from_env(cls) -> Config:
        return cls.from_dict({})
