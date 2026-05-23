# Contributing to Cullis

Thank you for your interest in contributing to Cullis. This guide is for contributors to the public repo (`cullis-security/cullis`), which hosts **Cullis Mastio** (org gateway) and the **Python SDK** (`cullis-sdk`).

## Development Setup

```bash
# Clone
git clone https://github.com/cullis-security/cullis.git
cd cullis

# Virtualenv
python3.11 -m venv .venv
source .venv/bin/activate

# Dependencies
pip install -r requirements.txt
```

### Run the Mastio locally

The fastest path is the bundle, which boots the Mastio + nginx TLS sidecar via `docker compose`:

```bash
cd packaging/mastio-bundle
./deploy.sh
# https://localhost:9443/proxy/login
```

For a hand-rolled run against your local source tree, look at `packaging/mastio-bundle/docker-compose.yml` and `proxy.env.example`.

### Iterate on the SDK

```bash
pip install -e cullis_sdk
python -c "from cullis_sdk import CullisClient; print(CullisClient)"
```

The SDK quickstart at [cullis.io/docs/quickstart/sdk](https://cullis.io/docs/quickstart/sdk/) walks through enrolling an agent identity and making the first authenticated call.

## Frontend Assets (Mastio Dashboard)

The Mastio dashboard ships compiled Tailwind CSS and a bundled copy of htmx — no CDN at runtime. Generated CSS is gitignored; build it once before running outside Docker:

```bash
# Tailwind standalone CLI, no Node/npm install required
./scripts/build_frontend.sh
./scripts/build_frontend.sh --watch    # iterate on templates
```

The `mcp_proxy/Dockerfile` runs the build in a dedicated stage, so the published image already includes the CSS.

## Code Conventions

- **Async:** all DB and HTTP code uses `async`/`await`
- **Type hints:** required on public functions
- **Pydantic:** every endpoint has request + response schemas
- **Logging:** use the `logging` module, never `print`
- **Tests:** every new feature ships with tests

## Pull Request Process

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-feature`.
3. Make your changes following the conventions above.
4. Add tests for new functionality.
5. Commit with a clear message describing the change. **All commits must be signed off** (`git commit -s`, see DCO below).
6. Push to your fork and open a Pull Request against `main`.

## PR Checklist

Before submitting, verify:

- [ ] All commits signed off (`git commit -s`)
- [ ] Type hints on new public functions
- [ ] No secrets, private keys, or credentials in the diff
- [ ] New endpoints have Pydantic schemas
- [ ] CHANGELOG entry under `## [Unreleased]` if user-visible

## What to Contribute

Look at issues labelled [`good-first-issue`](https://github.com/cullis-security/cullis/labels/good-first-issue) and [`help-wanted`](https://github.com/cullis-security/cullis/labels/help-wanted).

Areas where contributions are especially welcome:

- **Mastio**: hardening, observability, ergonomic admin endpoints
- **Python SDK**: ergonomic primitives, retries, examples for popular agent frameworks
- **Documentation**: tutorials, deployment guides, audit-trail walkthroughs
- **Helm chart**: production hardening for `deploy/helm/cullis-mastio/`
- **MCP tool packs**: builtin tools under `mcp_proxy/tools/builtins/`

## Security Issues

**Do not open a public issue for security vulnerabilities.** Email [security@cullis.io](mailto:security@cullis.io) directly, or use GitHub's private vulnerability reporting. See [SECURITY.md](SECURITY.md) for the full disclosure policy.

## Questions

- General questions: [hello@cullis.io](mailto:hello@cullis.io) or a [GitHub Discussion](https://github.com/cullis-security/cullis/discussions) in the Q&A category.
- Security questions: [security@cullis.io](mailto:security@cullis.io) (private channel).

## License

Cullis uses a split licensing model. By contributing, you agree that your contribution is licensed under the same terms as the component you are modifying:

- Contributions to `mcp_proxy/` (Cullis Mastio) are licensed under [FSL-1.1-Apache-2.0](LICENSE).
- Contributions to `cullis_sdk/` (Python SDK) are licensed under the [Apache License 2.0](cullis_sdk/LICENSE).

See [NOTICE](NOTICE) for the full component map.

## Developer Certificate of Origin (DCO)

Every commit must be signed off to certify you have the right to submit it under the applicable license. This is a lightweight alternative to a formal CLA, used by the Linux kernel and many other projects.

Add the sign-off automatically with:

```bash
git commit -s -m "Your commit message"
```

This appends a line like `Signed-off-by: Your Name <you@example.com>` to your commit message. The full text of the DCO is at [developercertificate.org](https://developercertificate.org/).

Pull requests whose commits are not signed off will be asked to amend and re-push.
