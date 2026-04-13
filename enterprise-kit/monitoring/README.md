# Cullis — Monitoring Kit

Drop-in Prometheus alert rules for Cullis. The broker exposes metrics in
two ways:

1. **OTLP/gRPC push** to a collector (Jaeger / Tempo / OTel Collector) —
   always on when `OTEL_ENABLED=true`.
2. **Prometheus scrape** at `/metrics` — opt-in, set `PROMETHEUS_ENABLED=true`.

For the alert rules in this directory, use the Prometheus scrape path.

## Enabling the /metrics endpoint

In your `.env` (or Helm `values.yaml`):

```
PROMETHEUS_ENABLED=true
```

Restart the broker. Verify:

```
curl -sS https://broker.your.domain/metrics | head
```

You should see lines starting with `# HELP atn_auth_success_total` etc.

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: cullis-broker
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets:
          - broker.your.domain:443

  - job_name: cullis-readyz
    metrics_path: /readyz
    scheme: https
    static_configs:
      - targets:
          - broker.your.domain:443
```

## Alert rules

`cullis-alerts.yml` contains three groups:

| Group | Severity | Routing |
|---|---|---|
| `cullis_security_critical` | critical | PagerDuty / Opsgenie / SIEM |
| `cullis_operational` | warning | Slack / email |
| `cullis_liveness` | critical | PagerDuty |

Validate locally:

```
promtool check rules cullis-alerts.yml
```

Then load it via your `prometheus.yml`:

```yaml
rule_files:
  - /etc/prometheus/rules/cullis-alerts.yml
```

## What the metrics signal

| Metric | Meaning | Why it matters |
|---|---|---|
| `atn_cert_pinning_mismatch_total` | Agent presented a cert whose thumbprint differs from the pinned one | Possible compromise or rogue CA. Investigate immediately. |
| `atn_audit_chain_verify_failed_total` | Audit log hash chain broken | Tampering or DB corruption. Stop accepting traffic and investigate. |
| `atn_revoked_token_use_attempt_total` | A revoked credential was presented | Compromised key still in use by an attacker. |
| `atn_dpop_jti_replay_attempt_total` | DPoP proof replay attempt | SDK bug regenerating JTI, OR captured proofs being replayed. |
| `atn_policy_dual_org_mismatch_total` | One PDP allowed, the other denied | Federated policy desynchronization. |
| `atn_kms_seal_check_failed_total` | Vault sealed or unreachable | Broker keeps running on cached keys but cannot rotate. |

The other metrics (auth success/deny, session created/denied, policy
allow/deny, rate-limit reject, PDP webhook latency) drive the operational
alerts and are straightforward operational signals.

## Grafana dashboard

`cullis-session-reliability.json` is a drop-in Grafana dashboard covering
the Session Reliability Layer (M1 + M2 + M3): offline message queue,
WebSocket heartbeat, session resume, and sweeper activity.

Import via **Dashboards → New → Import → Upload JSON file**, then pick
your Prometheus datasource when prompted (the dashboard exposes a
`$datasource` variable so you can point it at the right instance without
editing the file).

## SIEM integration

Cullis emits structured JSON logs when `LOG_FORMAT=json` is set. Combine
the alert rules above with log shipping to your SIEM (Loki, Splunk,
Elastic, Datadog) for full incident response context.
