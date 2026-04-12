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
    cmd_dashboard
}

cmd_check() {
    [[ -f "$NONCE_FILE" ]] || die "no nonce file — run '$0 up' first"
    local expected; expected="$(cat "$NONCE_FILE")"
    say "demo_network: asserting checker received nonce=$expected"

    # The checker's poll loop runs every 1s; sender may have just exited
    # and the message hasn't been decoded + stored yet. Retry for up to 20s
    # before declaring failure.
    local got="" actual=""
    local attempts=20
    for ((i=1; i<=attempts; i++)); do
        got="$(docker run --rm --network cullis-demo-net \
              -v demo_network_test-certs:/certs:ro \
              curlimages/curl:8.10.1 \
              -s --max-time 5 --cacert /certs/ca.crt \
              https://checker.cullis.test:8443/last-message 2>/dev/null || true)"
        # Same grep -m1 trick as before — avoid head/pipefail SIGPIPE trap.
        actual="$(echo "$got" | grep -m1 -oE '"nonce"[[:space:]]*:[[:space:]]*"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/')" || actual=""
        if [[ "$actual" == "$expected" ]]; then
            ok "smoke PASS: message round-trip succeeded (nonce=$expected)"
            return 0
        fi
        sleep 1
    done

    warn "expected nonce: $expected"
    warn "actual body after ${attempts}s of polling: $got"
    dump_failure_logs
    die "nonce mismatch or checker never delivered"
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

=== Cullis demo network — endpoints & credentials ===

One-time host mapping (so the browser and curl reach Traefik):
    sudo tee -a /etc/hosts <<< "127.0.0.1 broker.cullis.test proxy-a.cullis.test proxy-b.cullis.test checker.cullis.test"

Export the test CA (trust it in your browser or pass to curl):
    docker cp demo_network-traefik-1:/certs/ca.crt /tmp/cullis-demo-ca.crt
    # then: curl --cacert /tmp/cullis-demo-ca.crt https://...

Broker dashboard  → https://broker.cullis.test:8443/dashboard/login
    username:       admin
    password:       demo-admin-secret-change-me

Broker admin API  → https://broker.cullis.test:8443/v1/admin/...
    header:         x-admin-secret: demo-admin-secret-change-me

Proxy A dashboard → https://proxy-a.cullis.test:8443/proxy
    admin secret:   demo-proxy-admin-a

Proxy B dashboard → https://proxy-b.cullis.test:8443/proxy
    admin secret:   demo-proxy-admin-b

Checker (smoke)   → https://checker.cullis.test:8443/last-message
                    (returns the last payload the checker decoded)

Handy from the host (no /etc/hosts edit needed):
    curl --cacert /tmp/cullis-demo-ca.crt --resolve broker.cullis.test:8443:127.0.0.1 \\
         https://broker.cullis.test:8443/health

Logs:       ./smoke.sh logs [service]
Teardown:   ./smoke.sh down
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
