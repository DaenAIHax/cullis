# Rotating the at-rest master key, Cullis Mastio

`MCP_PROXY_DB_ENCRYPTION_KEY` is the at-rest master: it derives (PBKDF2-HMAC-
SHA256, 600k iterations) the Fernet key that encrypts the Mastio's secrets on
disk. Two stores depend on it:

| Store | What | Envelope |
|---|---|---|
| `mastio_keys` | the LocalIssuer signing key (mints LOCAL_TOKEN / session JWTs) | `enc:sec:v1:` |
| `pki_key_store` | the Org Root CA + Mastio Intermediate CA private keys | `enc:pki:v1:` |

## Why you cannot just change the value

Changing `MCP_PROXY_DB_ENCRYPTION_KEY` and restarting does **not** re-encrypt
anything. The existing rows are still sealed under the old passphrase, so the
new master cannot open them: the LocalIssuer fails to load its signing key and
the verifier fails to load the CA. The Mastio fails closed and **signing
halts**. This is correct (it never silently serves a wrong key) but it means a
naive rotation takes the org down.

A clean rotation re-encrypts every row from the old passphrase to the new one
in one pass, with the Mastio stopped.

## Procedure

1. **Back up first.** `./scripts/pg-backup.sh` and (Vault deploys)
   `./scripts/vault-ca-backup.sh`. A failed rotation must be recoverable.
2. **Stop the Mastio.** No process should write to the stores during the
   rewrap.
3. **Run the rewrap** with the OLD key in the environment and the NEW key as
   an argument:

   ```bash
   MCP_PROXY_DATABASE_URL=postgresql+asyncpg://... \
   MCP_PROXY_DB_ENCRYPTION_KEY=<OLD> \
     python scripts/cullis-rotate-db-encryption-key.py --new-key <NEW>
   ```

   It decrypts every row under `<OLD>` first (a wrong OLD aborts before any
   write, leaving the store untouched), then re-encrypts under `<NEW>` and
   writes, in a single transaction. It prints the per-store row counts.

   Generate a strong NEW value with `openssl rand -hex 48`.

4. **Pin the new value.** Set `MCP_PROXY_DB_ENCRYPTION_KEY=<NEW>` in
   `proxy.env` (replacing the old value).
5. **Start the Mastio** and confirm `readyz` is green and an agent login
   succeeds (the LocalIssuer logs `LocalIssuer initialized`).

## Scope and limits

- **`ai_provider_credentials` is NOT rotated here.** Those rows are encrypted
  under a separate key, `MCP_PROXY_SECRET_ENCRYPTION_KEY_B64`, with its own
  `enc:v1:` envelope. Rotate it independently if needed.
- **Vault-backed CA (`kms=vault`).** When the CA lives in Vault rather than
  `pki_key_store`, Vault holds the CA under its own seal; the rewrap only
  touches the rows present in `pki_key_store` (typically the `mastio_keys`
  signing key in that case). Rotating Vault's own keys is a Vault operation.
- **Roll forward, not back.** Once rewrapped, the rows are sealed under the
  NEW key. Keep the OLD value until you have confirmed the new deploy is
  healthy; to roll back you would re-run the tool with OLD/NEW swapped.
- **Re-running is safe.** If the rows are already sealed under the key you
  pass as OLD, the tool decrypts and re-encrypts them under NEW as usual;
  running it again with the now-current key on both ends is rejected by the
  `--new-key == old` guard, so you cannot accidentally double-rotate.
