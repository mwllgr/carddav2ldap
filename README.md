# carddav-to-ldap

Bridge that fetches contacts from a CardDAV server and serves them over LDAP. Useful for IP phones and other devices that support LDAP phonebook lookup but not CardDAV.

## Features

- Connects to any CardDAV server (Nextcloud, Radicale, Baikal, etc.)
- Serves contacts via a built-in read-only LDAP server
- HTTP/2 by default, optional HTTP/3 (QUIC) support
- HTTPS with custom CA certificates for CardDAV
- LDAPS (TLS) for the LDAP server
- Mutual TLS (mTLS) on both CardDAV and LDAP sides with CN whitelisting
- Configurable vCard-to-LDAP attribute mapping
- Multi-user: different LDAP bind DNs serve different CardDAV phonebooks
- Cached mode with periodic background refresh, or real-time mode with CardDAV server-side filtering per LDAP search
- Optional LDAP requester forwarding (bind DN + IP) in the User-Agent for real-time searches
- Configuration via YAML file, environment variables, or both
- Docker-ready with rootless container and configurable UID

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
| `carddav.realtime` | `CARDDAV_REALTIME` | `false` | Fetch from CardDAV on each LDAP search (see below) |
| `carddav.http3` | `CARDDAV_HTTP3` | `false` | Enable HTTP/3 (QUIC) for CardDAV connections (see below) |
| `carddav.forward_requester` | `CARDDAV_FORWARD_REQUESTER` | `true` | Append LDAP requester info (bind DN, IP:port) to User-Agent in real-time mode |

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

### Docker settings

| Env var | Default | Description |
|---|---|---|
| `PUID` | `1006` | UID of the unprivileged user inside the container |

The container runs rootless by default. The entrypoint creates a user with the given `PUID` and drops privileges before starting the application. Override it to match a host UID if you need access to bind-mounted files (e.g. TLS certificates).

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
| `tel.fax` | Fax numbers (TEL with TYPE=FAX) |
| `tel.pager` | Pager numbers (TEL with TYPE=PAGER) |
| `org` | Organization |
| `title` | Job title |
| `adr.street` | Street address |
| `adr.city` | City |
| `adr.region` | State/region |
| `adr.code` | Postal code |
| `adr.country` | Country |

The default mapping produces standard `inetOrgPerson` entries. Contacts with multiple phone numbers will have all numbers included in the `telephoneNumber` attribute.

Attribute mapping is only configurable via the YAML config file, not via environment variables.

## Multi-user mode

Different LDAP bind DNs can serve different CardDAV phonebooks. Each account has its own bind credentials and CardDAV connection settings. The top-level `carddav` section provides defaults that accounts inherit and can override.

```yaml
carddav:
  verify_ssl: true
  refresh_interval: 300

accounts:
  - bind_dn: cn=phone1,dc=carddav2ldap,dc=mwllgr,dc=at
    bind_password: pass1
    carddav:
      url: https://cloud.example.com/remote.php/dav/addressbooks/users/alice/contacts/
      username: alice
      password: alices-app-password
  - bind_dn: cn=phone2,dc=carddav2ldap,dc=mwllgr,dc=at
    bind_password: pass2
    carddav:
      url: https://cloud.example.com/remote.php/dav/addressbooks/users/bob/contacts/
      username: bob
      password: bobs-app-password
      realtime: true  # this account uses real-time mode
```

When `accounts` is present, `ldap.bind_dn` / `ldap.bind_password` are ignored. Without `accounts`, a single implicit account is created from the top-level `carddav` + `ldap.bind_dn`/`ldap.bind_password` (backward compatible).

An account with empty `bind_dn` and `bind_password` allows anonymous access. If no anonymous account is defined, unauthenticated clients are rejected.

### Multi-user via environment variables

Accounts can also be configured via environment variables using the `ACCOUNT_<N>_` prefix. The top-level `CARDDAV_*` vars serve as defaults:

```bash
# Defaults inherited by all accounts
export CARDDAV_VERIFY_SSL=true

# Account 1
export ACCOUNT_1_BIND_DN=cn=phone1,dc=carddav2ldap,dc=mwllgr,dc=at
export ACCOUNT_1_BIND_PASSWORD=pass1
export ACCOUNT_1_CARDDAV_URL=https://cloud.example.com/remote.php/dav/addressbooks/users/alice/contacts/
export ACCOUNT_1_CARDDAV_USERNAME=alice
export ACCOUNT_1_CARDDAV_PASSWORD=alices-app-password

# Account 2
export ACCOUNT_2_BIND_DN=cn=phone2,dc=carddav2ldap,dc=mwllgr,dc=at
export ACCOUNT_2_BIND_PASSWORD=pass2
export ACCOUNT_2_CARDDAV_URL=https://cloud.example.com/remote.php/dav/addressbooks/users/bob/contacts/
export ACCOUNT_2_CARDDAV_USERNAME=bob
export ACCOUNT_2_CARDDAV_PASSWORD=bobs-app-password
export ACCOUNT_2_CARDDAV_REALTIME=true
```

Account numbers don't need to be sequential. When `ACCOUNT_*` env vars are present, they override any YAML-defined accounts.

Available per-account env vars: `ACCOUNT_<N>_BIND_DN`, `ACCOUNT_<N>_BIND_PASSWORD`, `ACCOUNT_<N>_CARDDAV_URL`, `ACCOUNT_<N>_CARDDAV_USERNAME`, `ACCOUNT_<N>_CARDDAV_PASSWORD`, `ACCOUNT_<N>_CARDDAV_CA_CERT`, `ACCOUNT_<N>_CARDDAV_CLIENT_CERT`, `ACCOUNT_<N>_CARDDAV_CLIENT_KEY`, `ACCOUNT_<N>_CARDDAV_VERIFY_SSL`, `ACCOUNT_<N>_CARDDAV_REFRESH_INTERVAL`, `ACCOUNT_<N>_CARDDAV_REALTIME`, `ACCOUNT_<N>_CARDDAV_HTTP3`, `ACCOUNT_<N>_CARDDAV_FORWARD_REQUESTER`.

## Real-time mode

By default, contacts are fetched from CardDAV at startup and refreshed periodically in the background. In real-time mode, the server queries CardDAV on every LDAP search request instead.

LDAP search filters are translated to CardDAV `addressbook-query` prop-filters, so the CardDAV server only returns matching contacts rather than the full address book. The LDAP filter is still applied on the results for exact matching.

```yaml
carddav:
  realtime: true
```

Or via environment variable:

```bash
export CARDDAV_REALTIME=true
```

Real-time mode is useful when the address book changes frequently and you want instant visibility, or when the address book is very large and you prefer not to cache it. The trade-off is higher latency per search (a CardDAV round-trip) and more load on the CardDAV server.

When real-time mode is enabled, `refresh_interval` is ignored.

### Requester forwarding

In real-time mode, the LDAP requester's bind DN and IP address are included in the `User-Agent` header sent to the CardDAV server. This is useful for debugging or access logging on the CardDAV side.

```yaml
carddav:
  realtime: true
  forward_requester: true
```

This produces a User-Agent like:

```
carddav-to-ldap.mwllgr.at/0.4.0 @ cn=phone1,dc=carddav2ldap,dc=mwllgr,dc=at 192.168.1.4:82842
```

Enabled by default. Only applies to real-time searches — cached/background refreshes always use the plain User-Agent. Set `forward_requester: false` to disable.

## HTTP/3

By default, the CardDAV client uses HTTP/2 (with HTTP/1.1 fallback). HTTP/3 (QUIC) can be enabled for lower latency connections, but requires an additional dependency:

```bash
pip install carddav-to-ldap[http3]
```

Then enable it in config:

```yaml
carddav:
  http3: true
```

Or via environment variable:

```bash
export CARDDAV_HTTP3=true
```

HTTP/3 uses [`curl_cffi`](https://github.com/lexiforest/curl_cffi) under the hood. The CardDAV server must support HTTP/3 for this to have any effect.

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
