from __future__ import annotations

import os
import ssl
import subprocess
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_vcard_text():
    return """\
BEGIN:VCARD
VERSION:3.0
FN:John Doe
N:Doe;John;;;
TEL;TYPE=WORK:+1-555-0100
TEL;TYPE=CELL:+1-555-0101
TEL;TYPE=HOME:+1-555-0102
EMAIL:john@example.com
ORG:Acme Inc.
TITLE:Engineer
ADR;TYPE=WORK:;;123 Main St;Springfield;IL;62701;US
END:VCARD"""


@pytest.fixture
def sample_vcard_minimal():
    return """\
BEGIN:VCARD
VERSION:3.0
FN:Jane Smith
TEL:+1-555-0200
END:VCARD"""


@pytest.fixture
def sample_vcard_no_fn():
    return """\
BEGIN:VCARD
VERSION:3.0
N:Brown;Charlie;;;
TEL:+1-555-0300
END:VCARD"""


@pytest.fixture
def tls_certs(tmp_path):
    """Generate self-signed CA, server, and client certs for testing."""
    ca_key = tmp_path / "ca.key"
    ca_cert = tmp_path / "ca.crt"
    server_key = tmp_path / "server.key"
    server_cert = tmp_path / "server.crt"
    server_csr = tmp_path / "server.csr"
    client_key = tmp_path / "client.key"
    client_cert = tmp_path / "client.crt"
    client_csr = tmp_path / "client.csr"

    ca_ext = tmp_path / "ca_ext.cnf"
    ca_ext.write_text(
        "[v3_ca]\n"
        "basicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
    )
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-keyout", str(ca_key), "-out", str(ca_cert),
        "-days", "1", "-nodes", "-subj", "/CN=Test CA",
        "-extensions", "v3_ca", "-config", str(ca_ext),
    ], check=True, capture_output=True)

    subprocess.run([
        "openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-keyout", str(server_key), "-out", str(server_csr),
        "-nodes", "-subj", "/CN=localhost",
    ], check=True, capture_output=True)
    subprocess.run([
        "openssl", "x509", "-req", "-in", str(server_csr),
        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(server_cert), "-days", "1",
        "-extfile", "/dev/stdin",
    ], input=b"subjectAltName=DNS:localhost,IP:127.0.0.1", check=True, capture_output=True)

    subprocess.run([
        "openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-keyout", str(client_key), "-out", str(client_csr),
        "-nodes", "-subj", "/CN=test-client",
    ], check=True, capture_output=True)
    subprocess.run([
        "openssl", "x509", "-req", "-in", str(client_csr),
        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(client_cert), "-days", "1",
    ], check=True, capture_output=True)

    return {
        "ca_cert": str(ca_cert),
        "server_cert": str(server_cert),
        "server_key": str(server_key),
        "client_cert": str(client_cert),
        "client_key": str(client_key),
    }
