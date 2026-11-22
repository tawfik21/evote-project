"""Runs the real server over HTTPS (TLS 1.3) on a local port."""

import os
import ssl
import threading

import pytest
from werkzeug.serving import make_server

from evote.clients import attacks, voter
from evote.clients.api import HttpsTransport

from conftest import PASS


@pytest.fixture
def https_server(election):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(os.path.join(election.data_dir, "tls_cert.pem"),
                        os.path.join(election.data_dir, "tls_key.pem"), password=PASS)
    server = make_server("127.0.0.1", 0, election.app, ssl_context=ctx, threaded=True)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    trust = dict(election.trust, server_url=f"https://localhost:{port}")
    yield trust, port
    server.shutdown()


def test_pinned_certificate_connects(https_server):
    trust, _ = https_server
    transport = HttpsTransport(trust)
    manifest, state = voter.fetch_manifest(transport, trust)
    assert state == "open" and manifest["election_id"] == trust["election_id"]
    transport.close()


def test_connection_is_tls13(https_server):
    trust, port = https_server
    ctx = ssl.create_default_context(cadata=trust["tls_certificate_pem"])
    import socket
    with socket.create_connection(("127.0.0.1", port)) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
            assert tls.version() == "TLSv1.3"


def test_unpinned_certificate_rejected(https_server):
    trust, _ = https_server
    blocked, msg = attacks.fake_certificate(trust)
    assert blocked, msg


def test_environment_ca_bundle_cannot_override_pin(https_server, tmp_path, monkeypatch):
    """Regression: REQUESTS_CA_BUNDLE used to silently replace the pinned certificate."""
    trust, _ = https_server
    from evote.core import tls
    pem = tls.generate_certificate(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"), PASS, ["localhost"], [])
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "c.pem"))   # attacker-controlled bundle
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")               # and a hostile proxy
    transport = HttpsTransport(trust)
    voter.fetch_manifest(transport, trust)                                # still uses the pin, no proxy
    transport.close()
    assert pem


def test_plain_http_url_refused(election):
    with pytest.raises(ValueError):
        HttpsTransport(dict(election.trust, server_url="http://localhost:8443"))
