from __future__ import annotations

from pathlib import Path

import yaml

from carddav_to_ldap.config import CardDAVConfig, Config, LDAPServerConfig, DEFAULT_ATTRIBUTE_MAPPING


class TestCardDAVConfig:
    def test_from_dict_full(self):
        cfg = CardDAVConfig.from_dict({
            "url": "https://dav.example.com/contacts/",
            "username": "user",
            "password": "pass",
            "ca_cert": "/path/to/ca.crt",
            "client_cert": "/path/to/client.crt",
            "client_key": "/path/to/client.key",
            "verify_ssl": False,
            "refresh_interval": 600,
        })
        assert cfg.url == "https://dav.example.com/contacts/"
        assert cfg.username == "user"
        assert cfg.ca_cert == "/path/to/ca.crt"
        assert cfg.client_cert == "/path/to/client.crt"
        assert cfg.verify_ssl is False
        assert cfg.refresh_interval == 600

    def test_from_dict_minimal(self):
        cfg = CardDAVConfig.from_dict({"url": "https://dav.example.com/"})
        assert cfg.url == "https://dav.example.com/"
        assert cfg.username == ""
        assert cfg.ca_cert is None
        assert cfg.verify_ssl is True
        assert cfg.refresh_interval == 300

    def test_ignores_unknown_keys(self):
        cfg = CardDAVConfig.from_dict({"url": "https://x.com/", "unknown_key": "val"})
        assert cfg.url == "https://x.com/"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("CARDDAV_URL", "https://env.example.com/")
        monkeypatch.setenv("CARDDAV_USERNAME", "envuser")
        monkeypatch.setenv("CARDDAV_PASSWORD", "envpass")
        monkeypatch.setenv("CARDDAV_VERIFY_SSL", "false")
        monkeypatch.setenv("CARDDAV_REFRESH_INTERVAL", "120")
        cfg = CardDAVConfig.from_dict({"url": "https://yaml.example.com/"})
        assert cfg.url == "https://env.example.com/"
        assert cfg.username == "envuser"
        assert cfg.password == "envpass"
        assert cfg.verify_ssl is False
        assert cfg.refresh_interval == 120

    def test_env_override_partial(self, monkeypatch):
        monkeypatch.setenv("CARDDAV_USERNAME", "fromenv")
        cfg = CardDAVConfig.from_dict({"url": "https://yaml.example.com/"})
        assert cfg.url == "https://yaml.example.com/"
        assert cfg.username == "fromenv"

    def test_env_override_ca_cert(self, monkeypatch):
        monkeypatch.setenv("CARDDAV_CA_CERT", "/env/ca.crt")
        cfg = CardDAVConfig.from_dict({})
        assert cfg.ca_cert == "/env/ca.crt"

    def test_env_override_client_cert(self, monkeypatch):
        monkeypatch.setenv("CARDDAV_CLIENT_CERT", "/env/client.crt")
        monkeypatch.setenv("CARDDAV_CLIENT_KEY", "/env/client.key")
        cfg = CardDAVConfig.from_dict({})
        assert cfg.client_cert == "/env/client.crt"
        assert cfg.client_key == "/env/client.key"


class TestLDAPServerConfig:
    def test_defaults(self):
        cfg = LDAPServerConfig.from_dict({})
        assert cfg.host == "0.0.0.0"
        assert cfg.port == 0
        assert cfg.effective_port == 389
        assert cfg.base_dn == "dc=carddav2ldap,dc=mwllgr,dc=at"
        assert cfg.tls_cert is None
        assert cfg.require_client_cert is False
        assert cfg.allowed_client_cns == []

    def test_effective_port_ldap(self):
        cfg = LDAPServerConfig.from_dict({})
        assert cfg.effective_port == 389

    def test_effective_port_ldaps(self):
        cfg = LDAPServerConfig.from_dict({"tls_cert": "/cert.pem"})
        assert cfg.effective_port == 636

    def test_effective_port_explicit_overrides(self):
        cfg = LDAPServerConfig.from_dict({"tls_cert": "/cert.pem", "port": 3890})
        assert cfg.effective_port == 3890

    def test_effective_port_explicit_no_tls(self):
        cfg = LDAPServerConfig.from_dict({"port": 1389})
        assert cfg.effective_port == 1389

    def test_full(self):
        cfg = LDAPServerConfig.from_dict({
            "host": "127.0.0.1",
            "port": 636,
            "tls_cert": "/cert.pem",
            "tls_key": "/key.pem",
            "tls_ca": "/ca.pem",
            "require_client_cert": True,
            "allowed_client_cns": ["phone1", "phone2"],
        })
        assert cfg.port == 636
        assert cfg.tls_cert == "/cert.pem"
        assert cfg.require_client_cert is True
        assert cfg.allowed_client_cns == ["phone1", "phone2"]

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("LDAP_HOST", "127.0.0.1")
        monkeypatch.setenv("LDAP_PORT", "636")
        monkeypatch.setenv("LDAP_BASE_DN", "dc=example,dc=com")
        monkeypatch.setenv("LDAP_BIND_DN", "cn=admin")
        monkeypatch.setenv("LDAP_BIND_PASSWORD", "secret")
        monkeypatch.setenv("LDAP_REQUIRE_CLIENT_CERT", "true")
        cfg = LDAPServerConfig.from_dict({})
        assert cfg.host == "127.0.0.1"
        assert cfg.port == 636
        assert cfg.base_dn == "dc=example,dc=com"
        assert cfg.bind_dn == "cn=admin"
        assert cfg.bind_password == "secret"
        assert cfg.require_client_cert is True

    def test_env_override_tls(self, monkeypatch):
        monkeypatch.setenv("LDAP_TLS_CERT", "/env/server.crt")
        monkeypatch.setenv("LDAP_TLS_KEY", "/env/server.key")
        monkeypatch.setenv("LDAP_TLS_CA", "/env/ca.crt")
        cfg = LDAPServerConfig.from_dict({})
        assert cfg.tls_cert == "/env/server.crt"
        assert cfg.tls_key == "/env/server.key"
        assert cfg.tls_ca == "/env/ca.crt"

    def test_env_override_allowed_cns(self, monkeypatch):
        monkeypatch.setenv("LDAP_ALLOWED_CLIENT_CNS", "phone1,phone2, phone3")
        cfg = LDAPServerConfig.from_dict({})
        assert cfg.allowed_client_cns == ["phone1", "phone2", "phone3"]

    def test_env_overrides_yaml(self, monkeypatch):
        monkeypatch.setenv("LDAP_PORT", "3890")
        cfg = LDAPServerConfig.from_dict({"port": 636})
        assert cfg.port == 3890


class TestConfig:
    def test_from_dict_defaults(self):
        cfg = Config.from_dict({"carddav": {"url": "https://x.com/"}})
        assert cfg.carddav.url == "https://x.com/"
        assert cfg.ldap.effective_port == 389
        assert cfg.attribute_mapping == DEFAULT_ATTRIBUTE_MAPPING

    def test_from_dict_custom_mapping(self):
        cfg = Config.from_dict({
            "carddav": {"url": "https://x.com/"},
            "attribute_mapping": {"cn": ["fn"], "phone": ["tel"]},
        })
        assert cfg.attribute_mapping == {"cn": ["fn"], "phone": ["tel"]}

    def test_from_yaml(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "carddav": {"url": "https://dav.example.com/"},
            "ldap": {"port": 3890},
        }))
        cfg = Config.from_yaml(config_file)
        assert cfg.carddav.url == "https://dav.example.com/"
        assert cfg.ldap.port == 3890

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("CARDDAV_URL", "https://env.example.com/")
        monkeypatch.setenv("LDAP_PORT", "3891")
        cfg = Config.from_env()
        assert cfg.carddav.url == "https://env.example.com/"
        assert cfg.ldap.port == 3891

    def test_env_overrides_yaml(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CARDDAV_USERNAME", "env_user")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "carddav": {"url": "https://dav.example.com/", "username": "yaml_user"},
        }))
        cfg = Config.from_yaml(config_file)
        assert cfg.carddav.url == "https://dav.example.com/"
        assert cfg.carddav.username == "env_user"
