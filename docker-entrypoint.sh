#!/bin/sh
set -e

if [ "$(id -u)" = "0" ]; then
  adduser -D -H -u "${C2L_PUID}" appuser 2>/dev/null || true
  exec su-exec appuser carddav-to-ldap "$@"
fi

exec carddav-to-ldap "$@"
