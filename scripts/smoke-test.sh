#!/usr/bin/env bash
# End-to-end smoke test: runs the built binary and exercises the HTTP surface
# and the CLI subcommands. Usage: scripts/smoke-test.sh [path-to-binary]
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/${1:-kyguard-server}"
[ -x "$BIN" ] || BIN="${1:?binary not found; build with 'make build'}"

WORK="$(mktemp -d)"
PORT="${KY_SMOKE_PORT:-18080}"
BASE="http://127.0.0.1:${PORT}"
SERVER_PID=""
FAILURES=0

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || :
    wait "$SERVER_PID" 2>/dev/null || :
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { printf '  [ok]   %s\n' "$1"; }
fail() { printf '  [FAIL] %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

check() { # check <description> <actual> <expected>
  if [ "$2" = "$3" ]; then pass "$1 ($2)"; else fail "$1: got '$2', want '$3'"; fi
}

contains() { # contains <description> <haystack> <needle>
  case "$2" in
  *"$3"*) pass "$1" ;;
  *) fail "$1: missing '$3'" ;;
  esac
}

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# totp <base32 secret> [step offset]: the RFC 6238 code, stdlib only.
totp() {
  python3 -c 'import base64,hashlib,hmac,struct,sys,time
s=sys.argv[1]; k=base64.b32decode(s+"="*(-len(s)%8)); c=int(time.time())//30+int(sys.argv[2])
h=hmac.new(k,struct.pack(">Q",c),hashlib.sha1).digest(); o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' "$1" "${2:-0}"
}

# wrong_totp <base32 secret>: a well-formed code that matches no step near now (a fixed one,
# 000000 included, is sometimes valid).
wrong_totp() {
  near=" $(for o in -3 -2 -1 0 1 2 3; do totp "$1" "$o"; done | tr '\n' ' ')"
  n=0
  while case "$near" in *" $(printf '%06d' "$n") "*) true ;; *) false ;; esac; do n=$((n + 1)); done
  printf '%06d\n' "$n"
}

login_body() { # login_body <username> <password> <code>
  printf '{"username":"%s","password":"%s","totp_code":"%s"}' "$1" "$2" "$3"
}

start_server() { # start_server <captcha-provider>
  KY_PORT="$PORT" \
    KY_HOST=127.0.0.1 \
    KY_DATA_DIR="$WORK/data" \
    KY_BACKUP_DIR="$WORK/backups" \
    KY_DB_DRIVER=sqlite \
    KY_CAPTCHA_PROVIDER="$1" \
    KY_SCIM_ENABLED=true \
    "$BIN" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  curl -s -o /dev/null --retry 30 --retry-delay 1 --retry-all-errors "$BASE/" ||
    { cat "$WORK/server.log"; fail "server did not come up"; exit 1; }
}

stop_server() {
  kill "$SERVER_PID"
  if wait "$SERVER_PID"; then pass "graceful shutdown on SIGTERM"; else fail "unclean shutdown"; fi
  SERVER_PID=""
}

echo "==> CLI subcommands"
check "version exits 0" "$("$BIN" version >/dev/null 2>&1 && echo 0 || echo 1)" "0"
contains "version prints name" "$("$BIN" version)" "kyguard-server"

# The drill seals to a throwaway key and reopens it, so the pipeline runs even unpaired.
# Whether the suite key is pinned is the status route's report, not the drill's.
DRILL_OUT="$(KY_DATA_DIR="$WORK/data" KY_PORT="$PORT" KY_DB_DRIVER=sqlite "$BIN" backup-drill)"
contains "backup-drill seals and reopens the payload" "$DRILL_OUT" "extracted into a 0700 sandbox"
contains "backup-drill verifies the required files" "$DRILL_OUT" "required files verified"
contains "backup-drill checks database integrity" "$DRILL_OUT" "integrity_check passed"
contains "backup-drill passes on a complete payload" "$DRILL_OUT" "Status:   PASSED"

check "init-admin is gone" \
  "$(KY_DATA_DIR="$WORK/cli" KY_DB_DRIVER=sqlite "$BIN" init-admin -password SmokeTestAdminPass123! >/dev/null 2>&1 && echo 0 || echo 1)" "1"
check "break-glass create refuses a bad name" \
  "$(KY_DATA_DIR="$WORK/cli" KY_DB_DRIVER=sqlite "$BIN" break-glass create -username 'a b' >/dev/null 2>&1 && echo 0 || echo 1)" "1"

echo "==> HTTP with default PoW captcha"
start_server pow
check "GET / serves the PWA" "$(status "$BASE/")" "200"
contains "index.html has react root" "$(curl -s "$BASE/")" 'id="root"'
check "SPA fallback for unknown route" "$(status "$BASE/settings/deep/link")" "200"
check "login blocked without captcha token" \
  "$(status -X POST -H 'Content-Type: application/json' -d "$(login_body admin SmokeTestAdminPass123! 000000)" "$BASE/api/auth/login")" "403"
check "malformed login body rejected" \
  "$(status -X POST -H 'Content-Type: application/json' -d 'not-json' "$BASE/api/auth/login")" "400"
check "login rejects GET" "$(status "$BASE/api/auth/login")" "405"
check "pow challenge issued" "$(status "$BASE/api/auth/pow-challenge")" "200"
contains "unauthenticated /me reports not authenticated" "$(curl -s "$BASE/api/auth/me")" '"authenticated":false' 
check "scim rejects missing bearer" "$(status "$BASE/scim/v2/Users")" "401"
check "anonymous cannot export the capsule" "$(status -X POST "$BASE/api/backup/export-capsule")" "401"
check "anonymous cannot run backup drill" "$(status -X POST "$BASE/api/backup/drill")" "401"
check "anonymous cannot pair remote recovery" "$(status -X POST "$BASE/api/backup/pair-remote")" "401"
check "anonymous cannot read backup status" "$(status "$BASE/api/backup/status")" "401"
check "anonymous cannot pin a key" "$(status -X POST "$BASE/api/backup/pin-key")" "401"
check "anonymous cannot set the schedule" "$(status -X PUT "$BASE/api/backup/schedule")" "401"
check "anonymous cannot unpair" "$(status -X DELETE "$BASE/api/backup/pairing")" "401"
check "QR device pairing is gone" \
  "$(if curl -s -X POST -H 'Content-Type: application/json' -d '{"secret":"x"}' "$BASE/api/devices/pair/verify" | grep -q 'pairing'; then echo present; else echo gone; fi)" "gone"
check "local MFA sign-in is gone" \
  "$(if curl -s -X POST -H 'Content-Type: application/json' -d '{"mfa_token":"x","code":"000000"}' "$BASE/api/auth/mfa/totp" | grep -q 'MFA'; then echo present; else echo gone; fi)" "gone"
check "anonymous cannot list accounts" "$(status "$BASE/api/admin/users")" "401"
check "anonymous cannot set site theme" "$(status -X POST -H 'Content-Type: application/json' -d '{"theme":"oled"}' "$BASE/api/settings/theme")" "401"
check "scim rejects wrong bearer" "$(status -H 'Authorization: Bearer wrong' "$BASE/scim/v2/Users")" "401"
check "SAML metadata is gone" "$(status "$BASE/saml/metadata")" "404"
stop_server

echo "==> Break-glass accounts (host only)"
check "an empty database has no account" \
  "$(python3 -c 'import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute("SELECT COUNT(*) FROM users").fetchone()[0])' "$WORK/data/ky_server.db")" "0"
CREATED="$(KY_DATA_DIR="$WORK/data" KY_DB_DRIVER=sqlite "$BIN" break-glass create -username admin)"
contains "break-glass create prints the TOTP URI once" "$CREATED" "otpauth://totp/"
ADMIN_PASS="$(printf '%s\n' "$CREATED" | sed -n 's/^Password: //p')"
SECRET="$(printf '%s\n' "$CREATED" | sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p')"
check "generated password has at least 16 characters" "$([ "${#ADMIN_PASS}" -ge 16 ] && echo yes || echo no)" "yes"

echo "==> HTTP auth flow (captcha disabled)"
start_server none
check "wrong password is 401" \
  "$(status -X POST -H 'Content-Type: application/json' -d "$(login_body admin wrong-password-0123 "$(totp "$SECRET")")" "$BASE/api/auth/login")" "401"
check "unknown user is 401" \
  "$(status -X POST -H 'Content-Type: application/json' -d "$(login_body nobody "$ADMIN_PASS" 000000)" "$BASE/api/auth/login")" "401"
check "password without a code is refused" \
  "$(status -X POST -H 'Content-Type: application/json' -d '{"username":"admin","password":"'"$ADMIN_PASS"'"}' "$BASE/api/auth/login")" "400"
check "wrong code is 401" \
  "$(status -X POST -H 'Content-Type: application/json' -d "$(login_body admin "$ADMIN_PASS" "$(wrong_totp "$SECRET")")" "$BASE/api/auth/login")" "401"

LOGIN_HEADERS="$WORK/login.headers"
LOGIN_BODY="$(curl -s -D "$LOGIN_HEADERS" -c "$WORK/cookies" -X POST -H 'Content-Type: application/json' \
  -d "$(login_body admin "$ADMIN_PASS" "$(totp "$SECRET")")" "$BASE/api/auth/login")"
contains "break-glass login succeeds" "$LOGIN_BODY" '"authenticated":true'
contains "session cookie is HttpOnly" "$(grep -i '^set-cookie' "$LOGIN_HEADERS")" "HttpOnly"
contains "session cookie is SameSite" "$(grep -i '^set-cookie' "$LOGIN_HEADERS")" "SameSite"
contains "password hash never leaves the server" \
  "$(if echo "$LOGIN_BODY" | grep -q 'argon2'; then echo leaked; else echo clean; fi)" "clean"

ME="$(curl -s -b "$WORK/cookies" "$BASE/api/auth/me")"
contains "/me returns the session user" "$ME" '"username":"admin"'
contains "/me carries the break-glass banner" "$ME" '"break_glass":{'
ANON_SETTINGS="$(curl -s "$BASE/api/settings")"
contains "anonymous settings keep login fields" "$ANON_SETTINGS" '"app_name"'
contains "anonymous settings hide extra_settings" \
  "$(if echo "$ANON_SETTINGS" | grep -q 'extra_settings'; then echo leaked; else echo hidden; fi)" "hidden"
contains "anonymous settings hide db_driver" \
  "$(if echo "$ANON_SETTINGS" | grep -q 'db_driver'; then echo leaked; else echo hidden; fi)" "hidden"
check "no privileged action before a reason" "$(status -b "$WORK/cookies" "$BASE/api/backup/status")" "403"
CSRF="$(awk '$6 == "ky_csrf" { print $7 }' "$WORK/cookies")"
check "password change requires CSRF" "$(status -b "$WORK/cookies" -X POST "$BASE/api/auth/change-password")" "403"
check "password change requires a code" \
  "$(status -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
    -d '{"current_password":"'"$ADMIN_PASS"'","new_password":"ReplacementSmokePass456!","totp_code":"'"$(wrong_totp "$SECRET")"'"}' "$BASE/api/auth/change-password")" "401"
check "password change with a code succeeds" \
  "$(status -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
    -d '{"current_password":"'"$ADMIN_PASS"'","new_password":"ReplacementSmokePass456!","totp_code":"'"$(totp "$SECRET" 1)"'"}' "$BASE/api/auth/change-password")" "200"
contains "password change revoked the session" "$(curl -s -b "$WORK/cookies" "$BASE/api/auth/me")" '"authenticated":false'
check "old password stops working" \
  "$(status -H 'Content-Type: application/json' -d "$(login_body admin "$ADMIN_PASS" 000000)" "$BASE/api/auth/login")" "401"
RESET="$(KY_DATA_DIR="$WORK/data" KY_DB_DRIVER=sqlite "$BIN" break-glass reset-totp -username admin)"
contains "reset-totp prints a new URI" "$RESET" "otpauth://totp/"
OLD_SECRET="$SECRET"
SECRET="$(printf '%s\n' "$RESET" | sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p')"
check "the old secret stops working" \
  "$(status -H 'Content-Type: application/json' -d "$(login_body admin ReplacementSmokePass456! "$(totp "$OLD_SECRET" 1)")" "$BASE/api/auth/login")" "401"
LOGIN_BODY="$(curl -s -c "$WORK/cookies" -H 'Content-Type: application/json' \
  -d "$(login_body admin ReplacementSmokePass456! "$(totp "$SECRET")")" "$BASE/api/auth/login")"
contains "new password and new secret sign in" "$LOGIN_BODY" '"authenticated":true'
CSRF="$(awk '$6 == "ky_csrf" { print $7 }' "$WORK/cookies")"
check "break-glass reason is recorded" \
  "$(status -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{"reason":"smoke test"}' "$BASE/api/auth/break-glass/reason")" "200"
contains "admin settings include db_driver" "$(curl -s -b "$WORK/cookies" "$BASE/api/settings")" '"db_driver"'
check "deposit CLI refuses without a key" \
  "$(KY_DATA_DIR="$WORK/cli" KY_DB_DRIVER=sqlite "$BIN" deposit >/dev/null 2>&1 && echo 0 || echo 1)" "1"
CSRF="$(awk '$6 == "ky_csrf" { print $7 }' "$WORK/cookies")"
# No key pinned, so the honest assertion is the documented refusal. 412 cannot come from the
# SPA fallback, which answers 200 for anything it does not recognise.
check "export-capsule is a POST behind CSRF" "$(status -b "$WORK/cookies" -X POST "$BASE/api/backup/export-capsule")" "403"
check "admin export-capsule refuses without a key" \
  "$(status -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/backup/export-capsule")" "412"
contains "export-capsule says why it refused" \
  "$(curl -s -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/backup/export-capsule")" "No recovery key"
STATUS_JSON="$(curl -s -b "$WORK/cookies" "$BASE/api/backup/status")"
contains "backup status reports no key" "$STATUS_JSON" '"key_pinned":false'
contains "backup status names the local directory" "$STATUS_JSON" "$WORK/backups"
check "backup status never carries a token" \
  "$(if printf '%s' "$STATUS_JSON" | grep -qi 'token'; then echo leaked; else echo clean; fi)" "clean"
check "pin-key refuses garbage" \
  "$(status -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{"public_key":"AAAA","threshold":2,"total_shares":3}' -X POST "$BASE/api/backup/pin-key")" "400"
check "schedule refuses below the floor" \
  "$(status -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{"interval_sec":60}' -X PUT "$BASE/api/backup/schedule")" "400"
check "schedule accepts off" \
  "$(status -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{"interval_sec":0}' -X PUT "$BASE/api/backup/schedule")" "200"
contains "status reads the schedule back" "$(curl -s -b "$WORK/cookies" "$BASE/api/backup/status")" '"interval_sec":0'
check "run refuses without a key" "$(status -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/backup/deposit")" "412"
check "unpair refuses while unpaired" "$(status -b "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -X DELETE "$BASE/api/backup/pairing")" "412"
check "cookie write rejects missing CSRF" "$(status -b "$WORK/cookies" -X POST "$BASE/api/backup/deposit")" "403"
check "logout succeeds" "$(status -b "$WORK/cookies" -c "$WORK/cookies" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/auth/logout")" "200"
contains "session dead after logout" "$(curl -s -b "$WORK/cookies" "$BASE/api/auth/me")" '"authenticated":false' 
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "smoke test: all checks passed"
else
  echo "smoke test: $FAILURES check(s) failed"
  exit 1
fi
