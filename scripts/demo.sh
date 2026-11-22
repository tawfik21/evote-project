#!/usr/bin/env bash
# Full scripted demo on one machine: authority, server, 3 voters, auditor, attacks.
# Passphrases come from environment variables ONLY because this is a scripted demo;
# run the commands by hand (without --passphrase-env) to be prompted instead.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"
DEMO=${DEMO_DIR:-demo_run}
PORT=${PORT:-8443}
rm -rf "$DEMO" && mkdir -p "$DEMO"
cd "$DEMO"

export AUTH_PASS="authority-demo-passphrase"
export SERVER_PASS="server-demo-passphrase"
export VOTER_PASS="voter-demo-passphrase"
E="python3 -m evote"
step() { printf '\n\033[1;35m==> %s\033[0m\n' "$*"; }

step "1. Authority creates the election (offline)"
$E authority setup --out authority --title "Student Council 2026" \
   --candidates "Alice,Bob,Carol" --voters "v1,v2,v3,mallory" --passphrase-env AUTH_PASS
cat authority/enrolment_codes.txt
code() { awk -v id="$1" '$1==id {print $2}' authority/enrolment_codes.txt; }

step "2. Server operator initialises the server and starts it (HTTPS, TLS 1.3)"
$E server init --data-dir server --package authority/election_package.json \
   --url "https://localhost:$PORT" --passphrase-env SERVER_PASS
$E server run --data-dir server --port "$PORT" --passphrase-env SERVER_PASS > server_stdout.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 2
T="--trust server/trust.json"

step "3. Voters enrol with their one-time codes"
for v in v1 v2 v3 mallory; do
  $E voter enrol $T --voter-id $v --code "$(code $v)" --keyfile $v.key --passphrase-env VOTER_PASS
done

step "4. Voters log in with a Schnorr ZKP and cast encrypted ballots"
$E voter vote $T --keyfile v1.key --choice Alice --passphrase-env VOTER_PASS
$E voter vote $T --keyfile v2.key --choice Bob   --passphrase-env VOTER_PASS
$E voter vote $T --keyfile v3.key --choice Alice --passphrase-env VOTER_PASS

step "5. Voter v1 checks the receipt against the public board"
$E voter check $T --receipt receipt-v1.json

step "6. Attacks by a dishonest voter (mallory) and a network attacker"
$E attack overvote     $T --keyfile mallory.key --passphrase-env VOTER_PASS
$E attack copy-ballot  $T --keyfile mallory.key --passphrase-env VOTER_PASS
$E attack replay-login $T --keyfile mallory.key --passphrase-env VOTER_PASS
$E attack double-vote  $T --keyfile mallory.key --choice Carol --passphrase-env VOTER_PASS
$E attack fake-cert    $T

step "7. Authority closes the election and tallies (only the totals are decrypted)"
$E authority close $T --keyfile authority/authority.key --passphrase-env AUTH_PASS
$E authority tally $T --keyfile authority/authority.key --passphrase-env AUTH_PASS

step "8. Anyone audits the whole election"
$E audit $T --save board_copy.json

step "9. A dishonest authority tries to announce a false result"
$E attack fake-result $T --keyfile authority/authority.key --passphrase-env AUTH_PASS

step "10. A dishonest server admin rewrites a ballot in the database"
$E attack tamper-db --db server/server.db
$E audit $T || echo "(audit failed, as it should)"
$E voter check $T --receipt receipt-v1.json || echo "(receipt check failed, as it should)"

step "Server log (no keys, codes, tokens or votes are logged)"
cat server/server.log
