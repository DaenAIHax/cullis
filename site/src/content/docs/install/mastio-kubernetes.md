---
title: "Mastio on Kubernetes"
description: "Deploy the Cullis Mastio on a Kubernetes cluster with the official Helm chart — ingress, BYOCA, dev vs. prod values."
category: "Install"
order: 30
updated: "2026-05-23"
---

# Mastio on Kubernetes

**Who this is for**: an operator deploying Cullis Mastio on a managed or self-hosted Kubernetes cluster. For a single-host deploy on `docker compose`, see [Mastio bundle](mastio-bundle) instead.

Tested against: `kind`, `k3d`, and managed Kubernetes (EKS / GKE / AKS — pending customer validation at scale).

## Prerequisites

- Kubernetes ≥ v1.28 with `kubectl` context configured
- Helm ≥ v3.14
- An Ingress controller — `ingress-nginx` recommended; the chart annotations are written for it
- `openssl` on the host (for generating the BYOCA demo material; in production your security team provides the PEMs)

## Scope

**In scope**

- Deploying the Mastio via `helm install`
- Wiring a customer-provided PKI (BYOCA) into the Mastio
- Exposing the Mastio behind `ingress-nginx`
- `/healthz` → 200 and `/readyz` → ready

**Out of scope** (covered elsewhere)

- Production hardening (TLS at the Ingress, Vault auto-unseal, secret rotation) — see [Runbook](../operate/runbook)
- External Postgres / Redis / Vault — flip `*.internal` in `values.yaml` to `false` and point env vars at your managed services

## 1. Install `ingress-nginx`

Skip if your cluster already has one. Otherwise:

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm install ingress-nginx ingress-nginx/ingress-nginx \
    --namespace ingress-nginx --create-namespace \
    --set controller.service.type=LoadBalancer \
    --wait
```

## 2. Provide an Org CA

The Mastio signs agent leaf certificates from an Org CA. Pick one of the two paths below.

### A. Auto-bootstrap (evaluation / dev clusters)

`values-dev.yaml` enables this by default. The chart renders a post-install Job that generates a self-signed Org CA, writes it into a Secret the Mastio Deployment mounts, and pushes the PEMs into the in-cluster Vault so `MCP_PROXY_SECRET_BACKEND=vault` resolves on first boot — no manual `kubectl exec` required.

```bash
kubectl create namespace cullis
```

### B. Bring Your Own CA (production-preferred)

```bash
mkdir -p /tmp/cullis-pki && cd /tmp/cullis-pki
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -subj "/CN=Your Org Cullis CA/O=Your Org" -out ca.crt

kubectl create namespace cullis
kubectl -n cullis create secret generic mastio-pki \
    --from-file=org-ca.pem=ca.crt \
    --from-file=org-ca-key.pem=ca.key
```

At install time, pass `--set mastio.pki.bootstrap.enabled=false --set mastio.pki.existingSecret=mastio-pki` to disable auto-bootstrap and mount your Secret instead.

## 3. Install the Mastio chart

Dev-ergonomic deployment (Postgres / Redis / Vault spun up inline, Vault in dev mode, auto-bootstrapped CA — evaluation only):

```bash
helm install cullis-mastio deploy/helm/cullis-mastio/ \
    --namespace cullis \
    --values deploy/helm/cullis-mastio/values-dev.yaml \
    --set ingress.host=mastio.your-org.com \
    --wait --timeout 5m
```

Replace `mastio.your-org.com` with a hostname resolvable to your cluster's Ingress IP. For local k3d / kind runs, `mastio.127.0.0.1.nip.io` works without editing `/etc/hosts`.

For Option B (BYOCA), extend:

```bash
helm install cullis-mastio deploy/helm/cullis-mastio/ \
    --namespace cullis \
    --values deploy/helm/cullis-mastio/values-dev.yaml \
    --set mastio.pki.bootstrap.enabled=false \
    --set mastio.pki.existingSecret=mastio-pki \
    --set ingress.host=mastio.your-org.com \
    --wait --timeout 5m
```

### Verify

```bash
kubectl -n cullis get pods
# cullis-mastio-xxx       1/1 Running
# cullis-postgres-0       1/1 Running
# cullis-redis-0          1/1 Running
# cullis-vault-0          1/1 Running

curl -H "Host: mastio.your-org.com" http://<INGRESS-IP>/healthz
# {"status":"ok"}

curl -H "Host: mastio.your-org.com" http://<INGRESS-IP>/readyz
# {"status":"ready","checks":{"database":"ok","redis":"ok","kms":"ok"}}
```

## 4. Switching to production values

Once the dev stack proves viable, replace the inline StatefulSets with managed services:

```yaml
# values-prod.yaml (sketch — adapt to your environment)

mastio:
  environment: production
  logFormat: json
  replicaCount: 3
  pki:
    existingSecret: mastio-pki          # from your secret manager
  # VAULT_ALLOW_HTTP is NOT set — production requires Vault HTTPS

postgres:
  internal: false                       # point env at RDS / Cloud SQL / etc.

redis:
  internal: false                       # ElastiCache / Memorystore

vault:
  internal: false                       # external Vault

ingress:
  tls:
    enabled: true
    certManagerIssuer: letsencrypt-prod  # or your internal issuer

networkPolicy:
  enabled: true
```

Full `values.yaml` options are documented inline in the chart at `deploy/helm/cullis-mastio/values.yaml`.

## Troubleshoot

**`/readyz` stuck at 503 with `kms: error: Vault address must use https://`**
: You're on `values-dev.yaml` (Vault dev HTTP). Confirm `VAULT_ALLOW_HTTP=true` is set via `mastio.extraEnv`. From chart version post-#7 `values-dev.yaml` sets this automatically.

**`/readyz` stuck at 503 with `kms: error: Vault secret ... missing 'ca_cert_pem'`**
: The PKI bootstrap Job failed or didn't run. Check its logs:

  ```bash
  kubectl -n cullis get jobs -l app.kubernetes.io/component=mastio-pki-bootstrap
  kubectl -n cullis logs job/cullis-mastio-pki-bootstrap
  ```

  Common causes: Vault StatefulSet still coming up (the Job retries for ~2 min), or `mastio.pki.bootstrap.pushToVault=false` when `vault.kmsBackend=vault`.

**Mastio pod `CrashLoopBackOff` with no `certs/org-ca.pem`**
: `mastio.pki.existingSecret` is empty or the Secret doesn't carry `org-ca.pem` + `org-ca-key.pem`. Inspect with `kubectl -n cullis get secret mastio-pki -o yaml`.

**Everything else**
: Dump pod logs:

  ```bash
  kubectl -n cullis logs deploy/cullis-mastio --tail=200
  kubectl -n cullis get events --sort-by='.lastTimestamp' | tail -30
  ```

## Next

- [Enroll agents via BYOCA](../enroll/byoca) — on a k8s cluster, BYOCA is usually the right enrollment method for agent workloads
- [Enroll agents via SPIRE](../enroll/spire) — if SPIRE is already part of your workload identity fabric
- [Runbook](../operate/runbook) — production incident response
- [Mastio bundle](mastio-bundle) — the single-host alternative
