"""The --explain output runs the real protocol and every check it prints is TRUE."""

from evote.clients import authority, explain

from conftest import PASS, enrol


def test_explained_vote_and_tally(election, capsys):
    keys = enrol(election, "v1")
    receipt, _ = explain.vote(election.transport, election.trust, keys, "Bob")
    authority.close(election.transport, election.trust, election.authority_key, PASS)
    body = explain.tally(election.transport, election.trust, election.authority_key, PASS)
    out = capsys.readouterr().out
    assert "FALSE" not in out
    assert out.count("TRUE") == 14     # 10 checks while voting + 4 while tallying
    assert body["counts"] == [0, 1, 0]
    assert receipt["body"]["voter_id"] == "v1"
