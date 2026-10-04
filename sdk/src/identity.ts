// sdk/src/identity.ts
//
// Helper utilities for the `identity_commitment` circuit
// (circuits/identity_commitment/circuit.circom).
//
// The circuit proves knowledge of a `secret` whose double Poseidon hash
// matches a public `commitment2`:
//   inner = Poseidon(secret)         — first-level commitment (also public)
//   outer = Poseidon(inner)          — on-chain anchor (commitment2)
//
// These helpers let callers:
//   1. Derive the public identity anchor from a secret
//      (buildIdentityCommitment).
//   2. Assemble the exact circuit input object snarkjs expects
//      (identityCircuitInputs).
//   3. Verify an outer commitment matches a known inner commitment off-chain
//      (verifyIdentityCommitment).
//   4. Build a "registration payload" — the two public values to persist
//      on-chain or in a Merkle tree (identityRegistrationPayload).

import { poseidon } from "./poseidon.js";
import { SorobanZkError, SorobanZkErrorCode } from "./types.js";

// ---------------------------------------------------------------------------
// IdentityCommitment
// ---------------------------------------------------------------------------

/**
 * The two public values derived from a secret for the
 * `identity_commitment` circuit.
 */
export interface IdentityCommitment {
  /**
   * First-level commitment: `Poseidon(secret)`.
   * Exposed as a public input so a verifier can confirm the first-level
   * anchor without learning `secret`.
   */
  inner: bigint;
  /**
   * Second-level commitment (on-chain anchor): `Poseidon(inner)`.
   * This is the value stored on-chain or in a Merkle tree.
   */
  outer: bigint;
}

// ---------------------------------------------------------------------------
// buildIdentityCommitment
// ---------------------------------------------------------------------------

/**
 * Derive the {@link IdentityCommitment} for a `secret`.
 *
 * @example
 * ```ts
 * const secret = 0xdeadbeefn;
 * const { inner, outer } = buildIdentityCommitment(secret);
 * // Store `outer` on-chain as the identity anchor.
 * // Store `inner` as an intermediate commitment for first-level proofs.
 * ```
 */
export function buildIdentityCommitment(secret: bigint): IdentityCommitment {
  if (typeof secret !== "bigint") {
    throw new SorobanZkError(
      "buildIdentityCommitment: secret must be a bigint",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  const inner = poseidon([secret]);
  const outer = poseidon([inner]);
  return { inner, outer };
}

// ---------------------------------------------------------------------------
// identityCircuitInputs
// ---------------------------------------------------------------------------

/**
 * Build the circuit input object for `circuits/identity_commitment/circuit.circom`
 * in the exact shape `snarkjs.groth16.fullProve` expects.
 *
 * Circuit interface:
 *   Private inputs: `secret`
 *   Public inputs:  `inner` (= Poseidon(secret)), `commitment2` (= Poseidon(inner))
 *
 * @example
 * ```ts
 * const inputs = identityCircuitInputs(secret);
 * const { proof, publicSignals } = await snarkjs.groth16.fullProve(
 *   inputs,
 *   "circuits/identity_commitment/build/circuit_js/circuit.wasm",
 *   "circuits/identity_commitment/setup/circuit.zkey",
 * );
 * ```
 */
export function identityCircuitInputs(secret: bigint): Record<string, string> {
  const { inner, outer } = buildIdentityCommitment(secret);
  return {
    secret: secret.toString(),
    inner: inner.toString(),
    commitment2: outer.toString(),
  };
}

// ---------------------------------------------------------------------------
// verifyIdentityCommitment
// ---------------------------------------------------------------------------

/**
 * Off-chain check: verify that a given `outer` commitment was derived from
 * the supplied `inner` commitment via `Poseidon(inner) === outer`.
 *
 * This does NOT verify the zero-knowledge proof — it only checks the
 * public-input relationship that the circuit enforces. Use it to confirm
 * that a claimed `inner` matches a stored `outer` before submitting the
 * full ZK proof on-chain.
 *
 * @example
 * ```ts
 * if (!verifyIdentityCommitment(claimedInner, storedOuter)) {
 *   throw new Error("Inner commitment does not match the registered anchor.");
 * }
 * ```
 */
export function verifyIdentityCommitment(inner: bigint, outer: bigint): boolean {
  if (typeof inner !== "bigint" || typeof outer !== "bigint") {
    throw new SorobanZkError(
      "verifyIdentityCommitment: inner and outer must be bigints",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }
  return poseidon([inner]) === outer;
}

// ---------------------------------------------------------------------------
// identityRegistrationPayload
// ---------------------------------------------------------------------------

/**
 * A structured payload suitable for persisting or broadcasting when
 * registering a new identity in a system backed by the
 * `identity_commitment` circuit.
 */
export interface IdentityRegistrationPayload {
  /**
   * The on-chain anchor to store (e.g. in a Merkle tree or smart contract
   * mapping). This is `Poseidon(Poseidon(secret))`.
   */
  anchor: string;
  /**
   * The first-level commitment to publish alongside the anchor so a
   * verifier can check the two-level relationship. This is `Poseidon(secret)`.
   */
  innerCommitment: string;
  /** ISO-8601 timestamp of when this payload was created. */
  createdAt: string;
}

/**
 * Build a registration payload from a secret. The secret itself is NOT
 * included in the returned object — callers are responsible for storing
 * it securely off-chain.
 *
 * @example
 * ```ts
 * const payload = identityRegistrationPayload(secret);
 * await contract.registerIdentity(payload.anchor);
 * ```
 */
export function identityRegistrationPayload(secret: bigint): IdentityRegistrationPayload {
  const { inner, outer } = buildIdentityCommitment(secret);
  return {
    anchor: outer.toString(),
    innerCommitment: inner.toString(),
    createdAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// parseIdentityPublicSignals
// ---------------------------------------------------------------------------

/**
 * Parse the `publicSignals` array returned by snarkjs after running the
 * `identity_commitment` circuit into named fields.
 *
 * snarkjs orders public outputs in the order they appear as public inputs
 * in the circuit. For `identity_commitment`:
 *   publicSignals[0] = inner  (= Poseidon(secret))
 *   publicSignals[1] = outer  (= Poseidon(inner), the on-chain anchor)
 *
 * @throws {@link SorobanZkError} if the array has fewer than 2 elements.
 *
 * @example
 * ```ts
 * const { proof, publicSignals } = await snarkjs.groth16.fullProve(...);
 * const { inner, outer } = parseIdentityPublicSignals(publicSignals);
 * ```
 */
export function parseIdentityPublicSignals(
  publicSignals: string[]
): { inner: bigint; outer: bigint } {
  if (!Array.isArray(publicSignals) || publicSignals.length < 2) {
    throw new SorobanZkError(
      "parseIdentityPublicSignals: expected at least 2 public signals " +
        `(inner, outer), got ${Array.isArray(publicSignals) ? publicSignals.length : typeof publicSignals}`,
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  return {
    inner: BigInt(publicSignals[0]),
    outer: BigInt(publicSignals[1]),
  };
}
