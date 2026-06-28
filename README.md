# carddav-to-ldap

Bridge that fetches contacts from a CardDAV server and serves them over LDAP. Useful for IP phones and other devices that support LDAP phonebook lookup but not CardDAV.

## Features

- Connects to any CardDAV server (Nextcloud, Radicale, Baikal, etc.)
- Serves contacts via a built-in LDAP server
- HTTPS with custom CA certificates for CardDAV
- LDAPS (TLS) for the LDAP server
- Mutual TLS (mTLS) on both CardDAV and LDAP sides
- Client certificate CN whitelisting
- Configurable vCard-to-LDAP attribute mapping
- Periodic background refresh of contacts
- Configuration via YAML file, environment variables, or both

## Installation

```bash
pip install .
```

## Usage

### With a config file

```bash
carddav-to-ldap config.yaml
```

See [config.example.yaml](config.example.yaml) for all options.

### With environment variables only

```bash
export CARDDAV_URL=https://dav.example.com/addressbooks/user/contacts/
export CARDDAV_USERNAME=user@example.com
export CARDDAV_PASSWORD=secret
carddav-to-ldap
```

### With Docker

```bash
docker build -t carddav-to-ldap .

docker run -p 389:389 \
  -e CARDDAV_URL=https://dav.example.com/addressbooks/user/contacts/ \
  -e CARDDAV_USERNAME=user@example.com \
  -e CARDDAV_PASSWORD=secret \
  carddav-to-ldap
```

Or use the example Compose file:

```bash
cp docker-compose.example.yml docker-compose.yml
# Edit docker-compose.yml with your settings
docker compose up -d
```

### Nextcloud example

The CardDAV URL for Nextcloud follows the pattern `https://<host>/remote.php/dav/addressbooks/users/<username>/<addressbook>/`. The default address book is called `contacts`:

```bash
export CARDDAV_URL=https://cloud.example.com/remote.php/dav/addressbooks/users/alice/contacts/
export CARDDAV_USERNAME=alice
export CARDDAV_PASSWORD=my-app-password
carddav-to-ldap
```

Or with a config file:

```yaml
carddav:
  url: https://cloud.example.com/remote.php/dav/addressbooks/users/alice/contacts/
  username: alice
  password: my-app-password
```

> **Tip:** Use an [app password](https://docs.nextcloud.com/server/latest/user_manual/en/session_management.html#managing-devices) instead of your login password, especially if you have two-factor authentication enabled.

### Verbose logging

```bash
carddav-to-ldap -v config.yaml
```

## Configuration

All settings can be provided via a YAML config file, environment variables, or both. Environment variables take precedence over YAML values.

### CardDAV settings

| YAML key | Env var | Default | Description |
|---|---|---|---|
| `carddav.url` | `CARDDAV_URL` | *(required)* | CardDAV address book URL |
| `carddav.username` | `CARDDAV_USERNAME` | `""` | HTTP Basic Auth username |
| `carddav.password` | `CARDDAV_PASSWORD` | `""` | HTTP Basic Auth password |
| `carddav.ca_cert` | `CARDDAV_CA_CERT` | system CAs | Path to CA bundle for verifying the CardDAV server |
| `carddav.client_cert` | `CARDDAV_CLIENT_CERT` | — | Client certificate for mTLS to the CardDAV server |
| `carddav.client_key` | `CARDDAV_CLIENT_KEY` | — | Client key for mTLS to the CardDAV server |
| `carddav.verify_ssl` | `CARDDAV_VERIFY_SSL` | `true` | Whether to verify the server's TLS certificate |
| `carddav.refresh_interval` | `CARDDAV_REFRESH_INTERVAL` | `300` | Seconds between contact re-fetches |

### LDAP server settings

| YAML key | Env var | Default | Description |
|---|---|---|---|
| `ldap.host` | `LDAP_HOST` | `0.0.0.0` | Listen address |
| `ldap.port` | `LDAP_PORT` | auto | Listen port (389 for LDAP, 636 when TLS is configured) |
| `ldap.base_dn` | `LDAP_BASE_DN` | `dc=carddav2ldap,dc=mwllgr,dc=at` | Base DN for LDAP entries |
| `ldap.bind_dn` | `LDAP_BIND_DN` | `""` | Required bind DN (empty = anonymous bind allowed) |
| `ldap.bind_password` | `LDAP_BIND_PASSWORD` | `""` | Required bind password |
| `ldap.tls_cert` | `LDAP_TLS_CERT` | — | Server certificate for LDAPS |
| `ldap.tls_key` | `LDAP_TLS_KEY` | — | Server key for LDAPS |
| `ldap.tls_ca` | `LDAP_TLS_CA` | — | CA certificate for verifying client certs (mTLS) |
| `ldap.require_client_cert` | `LDAP_REQUIRE_CLIENT_CERT` | `false` | Require client certificate (mTLS) |
| `ldap.allowed_client_cns` | `LDAP_ALLOWED_CLIENT_CNS` | `[]` | Comma-separated list of allowed client cert CNs |

### Attribute mapping

The `attribute_mapping` section maps LDAP attribute names to vCard property paths. Paths use dot notation for sub-properties and typed values:

| Path | Meaning |
|---|---|
| `fn` | Full name (FN property) |
| `n.family` | Family name from N property |
| `n.given` | Given name from N property |
| `email` | All email addresses |
| `tel` | All phone numbers |
| `tel.cell` | Mobile phone numbers (TEL with TYPE=CELL) |
| `tel.home` | Home phone numbers (TEL with TYPE=HOME) |
| `tel.work` | Work phone numbers (TEL with TYPE=WORK) |
| `org` | Organization |
| `title` | Job title |
| `adr.street` | Street address |
| `adr.city` | City |
| `adr.region` | State/region |
| `adr.code` | Postal code |
| `adr.country` | Country |

The default mapping produces standard `inetOrgPerson` entries. Contacts with multiple phone numbers will have all numbers included in the `telephoneNumber` attribute.

Attribute mapping is only configurable via the YAML config file, not via environment variables.

## LDAPS and mTLS

### LDAPS (server TLS)

Set `tls_cert` and `tls_key` to enable LDAPS. The port defaults to 636 when TLS is configured.

```yaml
ldap:
  tls_cert: /path/to/server.crt
  tls_key: /path/to/server.key
```

### mTLS for LDAP clients

Require and verify client certificates, optionally restricting by CN:

```yaml
ldap:
  tls_cert: /path/to/server.crt
  tls_key: /path/to/server.key
  tls_ca: /path/to/ca.crt
  require_client_cert: true
  allowed_client_cns:
    - phone1.example.com
    - phone2.example.com
```

### mTLS for CardDAV

Authenticate to the CardDAV server with a client certificate:

```yaml
carddav:
  url: https://dav.example.com/contacts/
  client_cert: /path/to/client.crt
  client_key: /path/to/client.key
  ca_cert: /path/to/ca-bundle.crt
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
