// Cross-language interop harness driven by tests/test_ts_interop.py.
// Modes:
//   encrypt --curve=ec|rsa --input=<path>  → read {recipient_pub_pem, payload, sig, session, sender, seq}
//                                              write {blob} to stdout as JSON
//   decrypt --input=<path>                 → read {recipient_priv_pem, blob, session, sender, seq}
//                                              write {payload, inner_signature} to stdout
import { readFileSync } from "node:fs";
import {
  encryptForAgent,
  decryptFromAgent,
  signMessage,
  verifyMessageSignature,
} from "../../sdk-ts/dist/crypto.js";
import { canonicalJson, computePayloadHash } from "../../sdk-ts/dist/utils.js";

const args = Object.fromEntries(
  process.argv.slice(3).map((a) => {
    const [k, v] = a.replace(/^--/, "").split("=");
    return [k, v];
  }),
);
const mode = process.argv[2];
const data = JSON.parse(readFileSync(args.input, "utf-8"));

if (mode === "encrypt") {
  const blob = encryptForAgent(
    data.payload,
    data.recipient_pub_pem,
    data.session_id,
    data.sender_agent_id,
    data.inner_signature,
    data.client_seq ?? null,
  );
  process.stdout.write(JSON.stringify({ blob }));
} else if (mode === "decrypt") {
  const [payload, inner_signature] = decryptFromAgent(
    data.blob,
    data.recipient_priv_pem,
    data.session_id,
    data.sender_agent_id,
    data.client_seq ?? null,
  );
  process.stdout.write(JSON.stringify({ payload, inner_signature }));
} else if (mode === "sign") {
  const signature = signMessage(
    data.sender_priv_pem,
    data.session_id,
    data.sender_agent_id,
    data.nonce,
    data.timestamp,
    data.payload,
    data.client_seq ?? null,
  );
  process.stdout.write(JSON.stringify({ signature }));
} else if (mode === "verify") {
  try {
    verifyMessageSignature(
      data.sender_pub_pem,
      data.signature,
      data.session_id,
      data.sender_agent_id,
      data.nonce,
      data.timestamp,
      data.payload,
      data.client_seq ?? null,
    );
    process.stdout.write(JSON.stringify({ valid: true }));
  } catch (err) {
    process.stdout.write(JSON.stringify({ valid: false, error: String(err) }));
  }
} else if (mode === "canonical") {
  // Emit canonical JSON string + SHA-256 hex for the given payload.
  // Used by tests/test_ts_interop.py to assert cross-language byte parity.
  const canonical = canonicalJson(data.payload);
  const hash = computePayloadHash(data.payload);
  process.stdout.write(JSON.stringify({ canonical, hash }));
} else {
  process.stderr.write(`unknown mode: ${mode}\n`);
  process.exit(2);
}
