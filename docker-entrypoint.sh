#!/bin/sh
set -e

if [ "$(id -u)" = "0" ]; then
  case "${C2L_PUID}" in
    ''|*[!0-9]*)
      echo "ERROR: C2L_PUID must be a positive integer, got: '${C2L_PUID}'" >&2
      exit 1
      ;;
  esac
  if [ "${C2L_PUID}" -eq 0 ]; then
    echo "ERROR: C2L_PUID must not be 0 (would run as root)" >&2
    exit 1
  fi
  adduser -D -H -u "${C2L_PUID}" appuser 2>/dev/null || true
  exec su-exec appuser carddav2ldap "$@"
fi

exec carddav2ldap "$@"
