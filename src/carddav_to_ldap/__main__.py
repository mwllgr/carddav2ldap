from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import time

from .carddav import fetch_contacts, search_contacts
from .config import Account, CardDAVConfig, Config
from .ldap_server import HandlerAccount, LDAPRequestHandler, LDAPServer, create_ssl_context
from .mapping import vcard_to_ldap_entry

logger = logging.getLogger("carddav_to_ldap")


def _build_entries(carddav: CardDAVConfig, mapping: dict, base_dn: str) -> list[dict]:
    vcards = fetch_contacts(carddav)
    entries = []
    for vcard in vcards:
        entry = vcard_to_ldap_entry(vcard, mapping, base_dn)
        if entry:
            entries.append(entry)
    logger.info("Loaded %d contacts from CardDAV (%s)", len(entries), carddav.url)
    return entries


def _make_search_fn(carddav: CardDAVConfig, mapping: dict, base_dn: str):
    def search_fn(terms: list[tuple[str, str]], requester: object | None = None) -> list[dict]:
        vcards = search_contacts(carddav, terms, requester)
        entries = []
        for vcard in vcards:
            entry = vcard_to_ldap_entry(vcard, mapping, base_dn)
            if entry:
                entries.append(entry)
        return entries
    return search_fn


def _build_handler_accounts(cfg: Config) -> list[HandlerAccount]:
    handler_accounts: list[HandlerAccount] = []
    for account in cfg.accounts:
        carddav = account.carddav
        search_fn = None
        if carddav.realtime:
            search_fn = _make_search_fn(carddav, cfg.attribute_mapping, cfg.ldap.base_dn)
            entries: list[dict] = []
        else:
            entries = _build_entries(carddav, cfg.attribute_mapping, cfg.ldap.base_dn)
        handler_accounts.append(HandlerAccount(
            bind_dn=account.bind_dn,
            bind_password=account.bind_password,
            entries=entries,
            search_fn=search_fn,
        ))
    return handler_accounts


async def _refresh_loop(cfg: Config, handler: LDAPRequestHandler) -> None:
    while True:
        interval = min(
            (a.carddav.refresh_interval for a in cfg.accounts if not a.carddav.realtime),
            default=300,
        )
        await asyncio.sleep(interval)
        for i, account in enumerate(cfg.accounts):
            if account.carddav.realtime:
                continue
            try:
                entries = _build_entries(account.carddav, cfg.attribute_mapping, cfg.ldap.base_dn)
                handler.update_account_entries(i, entries)
            except Exception:
                logger.exception("Failed to refresh contacts for account %s", account.bind_dn or "(anonymous)")


async def _run(cfg: Config) -> None:
    if not cfg.accounts:
        raise SystemExit(
            "No accounts configured. Define accounts via the 'accounts' YAML section "
            "or C2L_ACCOUNT_<N>_* environment variables."
        )

    for account in cfg.accounts:
            try:
                import curl_cffi  # noqa: F401
            except ImportError:
                raise SystemExit(
                    "HTTP/3 support requires curl_cffi. "
                    "Install it with: pip install carddav-to-ldap[http3]"
                )
            break

    handler_accounts = _build_handler_accounts(cfg)

    if len(cfg.accounts) > 1:
        logger.info("Multi-user mode: %d accounts configured", len(cfg.accounts))
    for account in cfg.accounts:
        if account.carddav.realtime:
            logger.info("Real-time mode for account %s", account.bind_dn or "(anonymous)")

    handler = LDAPRequestHandler(
        accounts=handler_accounts,
        base_dn=cfg.ldap.base_dn,
    )

    ssl_context = None
    if cfg.ldap.tls_cert and cfg.ldap.tls_key:
        ssl_context = create_ssl_context(
            certfile=cfg.ldap.tls_cert,
            keyfile=cfg.ldap.tls_key,
            ca_certfile=cfg.ldap.tls_ca,
            require_client_cert=cfg.ldap.require_client_cert,
        )

    allowed_cns = cfg.ldap.allowed_client_cns if cfg.ldap.allowed_client_cns else None

    server = LDAPServer(
        handler=handler,
        host=cfg.ldap.host,
        port=cfg.ldap.effective_port,
        ssl_context=ssl_context,
        allowed_client_cns=allowed_cns,
    )

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.ensure_future(server.stop()))

    has_cached = any(not a.carddav.realtime for a in cfg.accounts)
    refresh_task = None
    if has_cached:
        refresh_task = asyncio.create_task(_refresh_loop(cfg, handler))
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        if refresh_task:
            refresh_task.cancel()


def main() -> None:
    parser = argparse.ArgumentParser(description="CardDAV to LDAP bridge")
    parser.add_argument("config", nargs="?", default=None, help="Path to YAML configuration file (optional if using env vars)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if args.config:
        cfg = Config.from_yaml(args.config)
    else:
        cfg = Config.from_env()
    asyncio.run(_run(cfg))


if __name__ == "__main__":
    main()
