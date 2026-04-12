#!/usr/bin/env bash
# Cullis demo network — one-command smoke test.
#
#   ./smoke.sh up        build images, start network, run bootstrap, send 1 msg
#   ./smoke.sh check     assert checker received the sender's nonce (exit 0/1)
#   ./smoke.sh down      stop network + delete all volumes
#   ./smoke.sh logs [S]  tail compose logs (all services, or one)
#   ./smoke.sh dashboard print URLs for manual inspection
#   ./smoke.sh full      = down -v + up + check + down -v   (CI-style)
#
# The smoke passes iff the checker's /last-message endpoint returns the
# same nonce that this script injected into the sender at `up`. That single
# assertion proves: TLS resolves, broker accepts onboarding via both
# /join and /attach-ca paths, org secret rotation works, agent x509 auth
# works, session open+accept works, E2E encryption works, message routing
# cross-org works.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

SERVICES_ON_FAILURE=(broker proxy-a proxy-b bootstrap sender checker)
COMPOSE="docker compose"
NONCE_FILE="$HERE/.last-nonce"

# ANSI colors (fall back to no-op when not a TTY)
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi

say()  { printf "${BOLD}%s${RESET}\n" "$*" >&2; }
ok()   { printf "${GREEN}✓${RESET} %s\n" "$*" >&2; }
warn() { printf "${YELLOW}!${RESET} %s\n" "$*" >&2; }
die()  { printf "${RED}✗${RESET} %s\n" "$*" >&2; exit 1; }

gen_nonce() {
    # 32-char random token — covers the "stale last-message from previous run"
    # failure mode that a plain timestamp cannot. openssl avoids the
    # tr|head SIGPIPE trap that breaks pipefail scripts.
    openssl rand -hex 16
}

dump_failure_logs() {
    warn "dumping last 100 lines per service for post-mortem:"
    for svc in "${SERVICES_ON_FAILURE[@]}"; do
        echo "---- ${svc} ----" >&2
        $COMPOSE logs --tail=100 "$svc" 2>&1 >&2 || true
    done
}

cmd_up() {
    local nonce; nonce="$(gen_nonce)"
    echo "$nonce" > "$NONCE_FILE"
    say "demo_network: starting with SMOKE_NONCE=$nonce"
    # --wait blocks until healthchecks pass or a one-shot exits. If the
    # bootstrap or sender crashes, compose returns non-zero and we surface
    # logs immediately.
    if ! SMOKE_NONCE="$nonce" $COMPOSE up -d --build --wait 2>&1; then
        dump_failure_logs
        die "demo_network: services failed to reach healthy state"
    fi
    ok "demo_network: up (nonce persisted to $NONCE_FILE)"
}

cmd_check() {
    [[ -f "$NONCE_FILE" ]] || die "no nonce file — run '$0 up' first"
    local expected; expected="$(cat "$NONCE_FILE")"
    say "demo_network: asserting checker received nonce=$expected"

    # Pull the last-message via Traefik (exercises the full TLS path too).
    local got
    got="$(docker run --rm --network cullis-demo-net \
          -v demo_network_test-certs:/certs:ro \
          curlimages/curl:8.10.1 \
          -s --max-time 10 --cacert /certs/ca.crt \
          https://checker.cullis.test:8443/last-message || true)"

    if [[ -z "$got" ]]; then
        dump_failure_logs
        die "checker /last-message returned empty body"
    fi

    # Parse the nonce out of the JSON with a lean regex — avoids a jq dep.
    local actual
    actual="$(echo "$got" | grep -oE '"nonce"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"

    if [[ "$actual" != "$expected" ]]; then
        warn "expected nonce: $expected"
        warn "actual payload: $got"
        dump_failure_logs
        die "nonce mismatch"
    fi
    ok "smoke PASS: message round-trip succeeded (nonce=$expected)"
}

cmd_down() {
    $COMPOSE down -v --remove-orphans 2>&1 | tail -5 >&2 || true
    rm -f "$NONCE_FILE"
    ok "demo_network: down"
}

cmd_logs() {
    if [[ $# -ge 1 ]]; then
        $COMPOSE logs -f "$1"
    else
        $COMPOSE logs -f
    fi
}

cmd_dashboard() {
    cat <<EOF
Cullis demo network — dashboards (add these to /etc/hosts or use curl --resolve):

    127.0.0.1 broker.cullis.test proxy-a.cullis.test proxy-b.cullis.test checker.cullis.test

Broker dashboard:    https://broker.cullis.test:8443/dashboard
  admin secret:      demo-admin-secret-change-me
  (test CA for your browser: demo_network/certs/ca.crt — docker volume test-certs)

Proxy A dashboard:   https://proxy-a.cullis.test:8443/proxy
  admin secret:      demo-proxy-admin-a

Proxy B dashboard:   https://proxy-b.cullis.test:8443/proxy
  admin secret:      demo-proxy-admin-b

Checker last msg:    https://checker.cullis.test:8443/last-message
EOF
}

cmd_full() {
    cmd_down || true
    cmd_up
    cmd_check
    cmd_down
}

main() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        up)        cmd_up "$@" ;;
        check)     cmd_check "$@" ;;
        down)      cmd_down "$@" ;;
        logs)      cmd_logs "$@" ;;
        dashboard) cmd_dashboard "$@" ;;
        full)      cmd_full "$@" ;;
        "" | help | -h | --help)
            grep -E '^#' "$0" | sed 's/^# ?//' | head -20
            ;;
        *)
            die "unknown command: $sub (try '$0 help')"
            ;;
    esac
}

main "$@"
