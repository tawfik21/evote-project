import os
from types import SimpleNamespace

import pytest

from evote.clients import authority, voter
from evote.clients.api import FlaskTransport
from evote.server.app import create_app, initialise, load_server_key

# Lighter Argon2id settings so the test suite runs quickly. Production default is 64 MiB.
FAST_KDF = {"iterations": 1, "lanes": 1, "memory_cost": 8 * 1024}
PASS = "correct horse battery staple"
CANDIDATES = ["Alice", "Bob", "Carol"]


@pytest.fixture
def election(tmp_path):
    voter_ids = [f"v{i}" for i in range(1, 9)]
    auth_dir = tmp_path / "authority"
    package, codes = authority.setup(str(auth_dir), "Test election", CANDIDATES, voter_ids, PASS, FAST_KDF)
    data_dir = tmp_path / "server"
    trust = initialise(str(data_dir), package, PASS, "https://localhost:8443", ["localhost"], ["127.0.0.1"], FAST_KDF)
    app = create_app(str(data_dir), load_server_key(str(data_dir), PASS))
    return SimpleNamespace(
        tmp=tmp_path, trust=trust, codes=codes, app=app, transport=FlaskTransport(app),
        authority_key=str(auth_dir / "authority.key"), db=str(data_dir / "server.db"), data_dir=str(data_dir),
    )


def enrol(e, voter_id: str):
    keyfile = os.path.join(e.tmp, f"{voter_id}.key")
    voter.enrol(e.transport, e.trust, voter_id, e.codes[voter_id], keyfile, PASS, FAST_KDF)
    return voter.load_keys(keyfile, PASS)
