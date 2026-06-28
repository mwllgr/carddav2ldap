from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import time

from .carddav import fetch_contacts
from .config import Config
from .ldap_server import LDAPRequestHandler, LDAPServer, create_ssl_context
from .mapping import vcard_to_ldap_entry

logger = logging.getLogger("carddav_to_ldap")


def _build_entries(cfg: Config) -> list[dict]:
    vcards = fetch_contacts(cfg.carddav)
    entries = []
    for vcard in vcards:
        entry = vcard_to_ldap_entry(vcard, cfg.attribute_mapping, cfg.ldap.base_dn)
        if entry:
            entries.append(entry)
    logger.info("Loaded %d contacts from CardDAV", len(entries))
    return entries


async def _refresh_loop(cfg: Config, handler: LDAPRequestHandler) -> None:
    while True:
        await asyncio.sleep(cfg.carddav.refresh_interval)
        try:
            entries = _build_entries(cfg)
            handler.update_entries(entries)
        except Exception:
            logger.exception("Failed to refresh contacts from CardDAV")


async def _run(cfg: Config) -> None:
    entries = _build_entries(cfg)

    handler = LDAPRequestHandler(
        entries=entries,
        base_dn=cfg.ldap.base_dn,
        bind_dn=cfg.ldap.bind_dn,
        bind_password=cfg.ldap.bind_password,
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

    refresh_task = asyncio.create_task(_refresh_loop(cfg, handler))
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
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
