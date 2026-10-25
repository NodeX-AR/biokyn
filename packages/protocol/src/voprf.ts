/**
 * RFC 9497 VOPRF (mode 0x01, ciphersuite ristretto255-SHA512): public façade.
 *
 *   Blind:    T = HashToGroup(x);  r ←$ Z_q*;  A = r·T
 *   Evaluate: B = k·A;  π = DLEQ(G, k·G, A, B)   (Fiat–Shamir, SHA-512 transcript)
 *   Finalize: verify π;  N = r⁻¹·B = k·T;  y = H(x, N, "Finalize")
 *
 * The DLEQ proof convinces the client that every evaluation used the SAME key as the published
 * public key, so an issuer cannot watermark clients with per-user keys without being caught.
 */
export { blind, finalize, deriveKeyPair, generateKeyPair, VoprfServer } from './ristretto/oprf.js';
export type { BlindResult, Evaluation } from './ristretto/oprf.js';
export { generateProof, verifyProof, PROOF_LENGTH } from './ristretto/dleq.js';
export {
  ORDER, GENERATOR, IDENTITY, deserializeElement, deserializeScalar, serializeElement, serializeScalar,
  randomScalar, smul, modN, invN,
} from './ristretto/group.js';
export type { Element } from './ristretto/group.js';
export { expandMessageXmd, hashToGroup, hashToScalar, contextString, MODE_VOPRF, IDENTIFIER } from './ristretto/hash.js';
