# carddav2ldap

Bridge that fetches contacts from a CardDAV server and serves them over LDAP. Useful for IP phones and other devices that support LDAP phonebook lookup but not CardDAV.

> **Note:** This project was developed extensively with the help of AI (Claude) and has undergone a security audit. It is intended for use in trusted network environments (e.g., a local LAN serving IP phones). The built-in LDAP server is read-only and has no write operations.

## Features

- Connects to any CardDAV server (Nextcloud, Radicale, Baikal, etc.)
- Serves contacts via a built-in read-only LDAP server
- HTTP/2 by default, optional HTTP/3 (QUIC) support
- HTTPS with custom CA certificates for CardDAV
- LDAPS (TLS) for the LDAP server
- Mutual TLS (mTLS) on both CardDAV and LDAP sides with CN whitelisting
- Simultaneous LDAPS and plaintext LDAP listeners
- Configurable vCard-to-LDAP attribute mapping with automatic custom-label and related-person support
- Unmapped vCard properties automatically preserved as `vcfUnmapped*` attributes
- Per-account LDAP bind DNs serving different CardDAV phonebooks
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
carddav2ldap config.yaml
```

See [config.example.yaml](config.example.yaml) for all options.

### With environment variables only

```bash
export C2L_ACCOUNT_1_BIND_DN=cn=phone,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at
export C2L_ACCOUNT_1_BIND_PASSWORD=secret
export C2L_ACCOUNT_1_CARDDAV_URL=https://dav.example.com/addressbooks/user/contacts/
export C2L_ACCOUNT_1_CARDDAV_USERNAME=user@example.com
export C2L_ACCOUNT_1_CARDDAV_PASSWORD=secret
carddav2ldap
```

### With Docker

```bash
docker run -p 389:389 \
  -e C2L_ACCOUNT_1_BIND_DN=cn=phone,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at \
  -e C2L_ACCOUNT_1_BIND_PASSWORD=secret \
  -e C2L_ACCOUNT_1_CARDDAV_URL=https://dav.example.com/addressbooks/user/contacts/ \
  -e C2L_ACCOUNT_1_CARDDAV_USERNAME=user@example.com \
  -e C2L_ACCOUNT_1_CARDDAV_PASSWORD=secret \
  ghcr.io/mwllgr/carddav2ldap
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
export C2L_ACCOUNT_1_BIND_DN=cn=phone,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at
export C2L_ACCOUNT_1_BIND_PASSWORD=secret
export C2L_ACCOUNT_1_CARDDAV_URL=https://cloud.example.com/remote.php/dav/addressbooks/users/alice/contacts/
export C2L_ACCOUNT_1_CARDDAV_USERNAME=alice
export C2L_ACCOUNT_1_CARDDAV_PASSWORD=my-app-password
carddav2ldap
```

Or with a config file:

```yaml
accounts:
  - bind_dn: cn=phone,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at
    bind_password: secret
    carddav:
      url: https://cloud.example.com/remote.php/dav/addressbooks/users/alice/contacts/
      username: alice
      password: my-app-password
```

> **Tip:** Use an [app password](https://docs.nextcloud.com/server/latest/user_manual/en/session_management.html#managing-devices) instead of your login password, especially if you have two-factor authentication enabled.

### Verbose logging

```bash
carddav2ldap -v config.yaml
```

## Configuration

All settings can be provided via a YAML config file, environment variables, or both. Environment variables take precedence over YAML values.

### CardDAV defaults

The optional top-level `carddav` section (or `C2L_CARDDAV_*` env vars) provides shared defaults inherited by all accounts. Accounts can override any of these individually.

| YAML key | Env var | Default | Description |
|---|---|---|---|
| `carddav.ca_cert` | `C2L_CARDDAV_CA_CERT` | system CAs | Path to CA bundle for verifying the CardDAV server |
| `carddav.client_cert` | `C2L_CARDDAV_CLIENT_CERT` | — | Client certificate for mTLS to the CardDAV server |
| `carddav.client_key` | `C2L_CARDDAV_CLIENT_KEY` | — | Client key for mTLS to the CardDAV server |
| `carddav.verify_ssl` | `C2L_CARDDAV_VERIFY_SSL` | `true` | Whether to verify the server's TLS certificate |
| `carddav.refresh_interval` | `C2L_CARDDAV_REFRESH_INTERVAL` | `300` | Seconds between contact re-fetches |
| `carddav.realtime` | `C2L_CARDDAV_REALTIME` | `false` | Fetch from CardDAV on each LDAP search (see below) |
| `carddav.http3` | `C2L_CARDDAV_HTTP3` | `false` | Enable HTTP/3 (QUIC) for CardDAV connections (see below) |
| `carddav.forward_requester` | `C2L_CARDDAV_FORWARD_REQUESTER` | `true` | Append LDAP requester info (bind DN, IP:port) to User-Agent in real-time mode |

### LDAP server settings

| YAML key | Env var | Default | Description |
|---|---|---|---|
| `ldap.host` | `C2L_LDAP_HOST` | `0.0.0.0` | Listen address |
| `ldap.port` | `C2L_LDAP_PORT` | auto | Listen port (389 for LDAP, 636 when TLS is configured) |
| `ldap.base_dn` | `C2L_LDAP_BASE_DN` | `ou=Contacts,dc=carddav2ldap,dc=mwllgr,dc=at` | Base DN for LDAP entries |
| `ldap.tls_cert` | `C2L_LDAP_TLS_CERT` | — | Server certificate for LDAPS |
| `ldap.tls_key` | `C2L_LDAP_TLS_KEY` | — | Server key for LDAPS |
| `ldap.tls_ca` | `C2L_LDAP_TLS_CA` | — | CA certificate for verifying client certs (mTLS) |
| `ldap.require_client_cert` | `C2L_LDAP_REQUIRE_CLIENT_CERT` | `false` | Require client certificate (mTLS) |
| `ldap.allowed_client_cns` | `C2L_LDAP_ALLOWED_CLIENT_CNS` | `[]` | Comma-separated list of allowed client cert CNs |
| `ldap.plaintext_port` | `C2L_LDAP_PLAINTEXT_PORT` | — | Also listen on this port without TLS (when LDAPS is enabled) |

### Account settings

At least one account must be configured via the `accounts` YAML section or `C2L_ACCOUNT_<N>_*` env vars. Each account has its own bind credentials and CardDAV settings.

| YAML key | Env var | Default | Description |
|---|---|---|---|
| `accounts[n].bind_dn` | `C2L_ACCOUNT_<N>_BIND_DN` | `""` | Bind DN for this account |
| `accounts[n].bind_password` | `C2L_ACCOUNT_<N>_BIND_PASSWORD` | `""` | Bind password for this account |
| `accounts[n].carddav.url` | `C2L_ACCOUNT_<N>_CARDDAV_URL` | *(required)* | CardDAV address book URL |
| `accounts[n].carddav.username` | `C2L_ACCOUNT_<N>_CARDDAV_USERNAME` | `""` | HTTP Basic Auth username |
| `accounts[n].carddav.password` | `C2L_ACCOUNT_<N>_CARDDAV_PASSWORD` | `""` | HTTP Basic Auth password |
| `accounts[n].carddav.ca_cert` | `C2L_ACCOUNT_<N>_CARDDAV_CA_CERT` | inherited | CA bundle path |
| `accounts[n].carddav.client_cert` | `C2L_ACCOUNT_<N>_CARDDAV_CLIENT_CERT` | inherited | Client certificate for mTLS |
| `accounts[n].carddav.client_key` | `C2L_ACCOUNT_<N>_CARDDAV_CLIENT_KEY` | inherited | Client key for mTLS |
| `accounts[n].carddav.verify_ssl` | `C2L_ACCOUNT_<N>_CARDDAV_VERIFY_SSL` | inherited | Verify TLS certificate |
| `accounts[n].carddav.refresh_interval` | `C2L_ACCOUNT_<N>_CARDDAV_REFRESH_INTERVAL` | inherited | Refresh interval (seconds) |
| `accounts[n].carddav.realtime` | `C2L_ACCOUNT_<N>_CARDDAV_REALTIME` | inherited | Real-time mode for this account |
| `accounts[n].carddav.http3` | `C2L_ACCOUNT_<N>_CARDDAV_HTTP3` | inherited | HTTP/3 for this account |
| `accounts[n].carddav.forward_requester` | `C2L_ACCOUNT_<N>_CARDDAV_FORWARD_REQUESTER` | inherited | Requester forwarding for this account |

Per-account CardDAV settings default to the values from the [CardDAV defaults](#carddav-defaults) table above. An account with empty `bind_dn` and `bind_password` allows anonymous LDAP access.

### Docker settings

| Env var | Default | Description |
|---|---|---|
| `C2L_PUID` | `1006` | UID of the unprivileged user inside the container (must be a non-zero positive integer) |

The container runs rootless by default. The entrypoint creates a user with the given `C2L_PUID` and drops privileges before starting the application. Override it to match a host UID if you need access to bind-mounted files (e.g. TLS certificates). Setting `C2L_PUID=0` is rejected to prevent accidental root execution.

### Attribute mapping

See [MAPPINGS.md](MAPPINGS.md) for the full list of default and automatic vCard-to-LDAP attribute mappings, including related persons, custom-labeled properties, and unmapped property handling.

Attribute mapping is configurable via the `attribute_mapping` section in the YAML config file. See [config.example.yaml](config.example.yaml) for the full default mapping.

## Accounts

Each account maps an LDAP bind DN to a CardDAV phonebook. Different LDAP clients can authenticate with different credentials and see different contact lists. The top-level `carddav` section provides shared defaults that accounts inherit and can override.

```yaml
carddav:
  verify_ssl: true
  refresh_interval: 300

accounts:
  - bind_dn: cn=phone1,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at
    bind_password: pass1
    carddav:
      url: https://cloud.example.com/remote.php/dav/addressbooks/users/alice/contacts/
      username: alice
      password: alices-app-password
  - bind_dn: cn=phone2,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at
    bind_password: pass2
    carddav:
      url: https://cloud.example.com/remote.php/dav/addressbooks/users/bob/contacts/
      username: bob
      password: bobs-app-password
      realtime: true  # this account uses real-time mode
```

An account with empty `bind_dn` and `bind_password` allows anonymous access. If no anonymous account is defined, unauthenticated clients are rejected.

### Accounts via environment variables

Accounts can also be configured via environment variables using the `C2L_ACCOUNT_<N>_` prefix. The top-level `C2L_CARDDAV_*` vars serve as defaults:

```bash
# Defaults inherited by all accounts
export C2L_CARDDAV_VERIFY_SSL=true

# Account 1
export C2L_ACCOUNT_1_BIND_DN=cn=phone1,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at
export C2L_ACCOUNT_1_BIND_PASSWORD=pass1
export C2L_ACCOUNT_1_CARDDAV_URL=https://cloud.example.com/remote.php/dav/addressbooks/users/alice/contacts/
export C2L_ACCOUNT_1_CARDDAV_USERNAME=alice
export C2L_ACCOUNT_1_CARDDAV_PASSWORD=alices-app-password

# Account 2
export C2L_ACCOUNT_2_BIND_DN=cn=phone2,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at
export C2L_ACCOUNT_2_BIND_PASSWORD=pass2
export C2L_ACCOUNT_2_CARDDAV_URL=https://cloud.example.com/remote.php/dav/addressbooks/users/bob/contacts/
export C2L_ACCOUNT_2_CARDDAV_USERNAME=bob
export C2L_ACCOUNT_2_CARDDAV_PASSWORD=bobs-app-password
export C2L_ACCOUNT_2_CARDDAV_REALTIME=true
```

Account numbers don't need to be sequential. When `C2L_ACCOUNT_*` env vars are present, they override any YAML-defined accounts. See the [Account settings](#account-settings) table for all available per-account env vars.

## Real-time mode

By default, contacts are fetched from CardDAV at startup and refreshed periodically in the background. In real-time mode, the server queries CardDAV on every LDAP search request instead.

LDAP search filters are translated to CardDAV `addressbook-query` prop-filters, so the CardDAV server only returns matching contacts rather than the full address book. The LDAP filter is still applied on the results for exact matching.

Set `realtime: true` on an account's CardDAV config, or as a shared default:

```yaml
accounts:
  - bind_dn: cn=phone,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at
    bind_password: secret
    carddav:
      url: https://cloud.example.com/remote.php/dav/addressbooks/users/alice/contacts/
      username: alice
      password: alices-app-password
      realtime: true
```

Or via environment variable:

```bash
export C2L_ACCOUNT_1_CARDDAV_REALTIME=true
```

Real-time mode is useful when the address book changes frequently and you want instant visibility, or when the address book is very large and you prefer not to cache it. The trade-off is higher latency per search (a CardDAV round-trip) and more load on the CardDAV server. Each account can independently use cached or real-time mode.

When real-time mode is enabled, `refresh_interval` is ignored for that account.

### Requester forwarding

In real-time mode, the LDAP requester's bind DN and IP address are included in the `User-Agent` header sent to the CardDAV server. This is useful for debugging or access logging on the CardDAV side.

```yaml
carddav:
  forward_requester: true  # shared default for all accounts
```

This produces a User-Agent like:

```
carddav2ldap.mwllgr.at/0.4.0 (192.168.1.4:82842 - cn=phone1,ou=Users,dc=carddav2ldap,dc=mwllgr,dc=at)
```

Enabled by default. Only applies to real-time searches — cached/background refreshes always use the plain User-Agent. Set `forward_requester: false` to disable.

## HTTP/3

By default, the CardDAV client uses HTTP/2 (with HTTP/1.1 fallback). HTTP/3 (QUIC) can be enabled for lower latency connections, but requires an additional dependency:

```bash
pip install carddav2ldap[http3]
```

Then enable it as a shared default or per account:

```yaml
carddav:
  http3: true  # all accounts use HTTP/3
```

Or per account via environment variable:

```bash
export C2L_ACCOUNT_1_CARDDAV_HTTP3=true
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

To serve both LDAPS and plaintext LDAP simultaneously, set `plaintext_port`:

```yaml
ldap:
  tls_cert: /path/to/server.crt
  tls_key: /path/to/server.key
  plaintext_port: 389  # also listen without TLS on this port
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

Authenticate to the CardDAV server with a client certificate (as shared default or per account):

```yaml
carddav:
  client_cert: /path/to/client.crt
  client_key: /path/to/client.key
  ca_cert: /path/to/ca-bundle.crt
```

## Compatibility

Successfully tested with the following devices:

- [Grandstream WP826](DEVICES.md#grandstream-wp826)
- [Snom D785](DEVICES.md#snom-d785)

See [DEVICES.md](DEVICES.md) for configuration screenshots and setup instructions.

## Security

The LDAP server enforces the following limits to mitigate abuse:

| Limit | Value |
|---|---|
| Max simultaneous connections per client IP | 20 |
| Idle read timeout | 60 seconds |
| Max receive buffer per connection | 1 MB |
| Max consecutive failed bind attempts before closing | 5 |
| Delay after each failed bind | 0.5 seconds |

These values are not currently configurable. If you are deploying behind a load balancer or NAT (where all traffic shares a single source IP), the per-IP connection limit may need to be taken into account.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
