"""HTTP transport used by every client.

``HttpsTransport`` talks to a real server over TLS and trusts *only* the
certificate in the voter's trust bundle (certificate pinning).
``FlaskTransport`` runs the same client code against an in-process Flask app,
which is how the integration tests work without opening network sockets.
"""

import json
import os
import ssl
import tempfile


class ServerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"server returned {status}: {message}")
        self.status = status
        self.message = message


def load_trust(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


class HttpsTransport:
    def __init__(self, trust: dict, server_url: str | None = None, timeout: float = 15.0):
        import requests

        self.base = (server_url or trust["server_url"]).rstrip("/")
        if not self.base.startswith("https://"):
            raise ValueError("the server URL must use https://")
        # requests needs the pinned certificate as a file on disk.
        fd, self._ca_file = tempfile.mkstemp(prefix="evote-pin-", suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(trust["tls_certificate_pem"])
        self.session = requests.Session()
        # SECURITY: requests normally reads HTTPS_PROXY and REQUESTS_CA_BUNDLE from the
        # environment, and an environment CA bundle silently *overrides* session.verify -
        # which would defeat the pinning. Ignore the environment completely.
        self.session.trust_env = False
        self.session.verify = self._ca_file      # trust ONLY this certificate
        self.timeout = timeout
        self._requests = requests

    def _handle(self, resp):
        try:
            data = resp.json()
        except ValueError:
            data = {"error": resp.text[:200]}
        if resp.status_code >= 400:
            raise ServerError(resp.status_code, data.get("error", "unknown error"))
        return data

    def get(self, path: str) -> dict:
        return self._handle(self.session.get(self.base + path, timeout=self.timeout, verify=self._ca_file))

    def post(self, path: str, payload: dict, token: str | None = None) -> dict:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self._handle(self.session.post(self.base + path, json=payload, headers=headers,
                                              timeout=self.timeout, verify=self._ca_file))

    def close(self):
        self.session.close()
        try:
            os.unlink(self._ca_file)
        except OSError:
            pass


class FlaskTransport:
    """Same interface, backed by Flask's test client (for automated tests)."""

    def __init__(self, app):
        self.client = app.test_client()

    def _handle(self, resp):
        data = resp.get_json(silent=True) or {}
        if resp.status_code >= 400:
            raise ServerError(resp.status_code, data.get("error", "unknown error"))
        return data

    def get(self, path: str) -> dict:
        return self._handle(self.client.get(path))

    def post(self, path: str, payload: dict, token: str | None = None) -> dict:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self._handle(self.client.post(path, json=payload, headers=headers))

    def close(self):
        pass


def tls_error_types():
    """Exception types that indicate a TLS failure (used by the fake-cert demo)."""
    import requests

    return (requests.exceptions.SSLError, ssl.SSLError)
