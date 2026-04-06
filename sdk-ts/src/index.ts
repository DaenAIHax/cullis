/**
 * @agent-trust/sdk — TypeScript SDK for Cullis.
 *
 * Main entry point: re-exports the public API.
 */

// Client
export { BrokerClient } from "./client.js";

// Auth helpers
export {
  createClientAssertion,
  createDPoPProof,
  generateDPoPKeyPair,
  computeJwkThumbprint,
} from "./auth.js";
export type { DPoPKeyPair, DPoPProofOptions } from "./auth.js";

// Crypto helpers
export {
  signMessage,
  verifyMessageSignature,
  encryptForAgent,
  decryptFromAgent,
} from "./crypto.js";

// Utilities
export {
  canonicalJson,
  base64url,
  base64urlDecode,
  computePayloadHash,
} from "./utils.js";

// Types
export type {
  TokenPayload,
  TokenRequest,
  TokenResponse,
  SessionStatusValue,
  SessionRequest,
  SessionResponse,
  SessionStatus,
  MessageEnvelope,
  InboxMessage,
  CipherBlob,
  RfqRequest,
  RfqResponse,
  RfqQuote,
  RfqRespondRequest,
  TransactionTokenRequest,
  TransactionTokenResponse,
  AgentResponse,
  AgentListResponse,
  BrokerClientOptions,
} from "./types.js";
