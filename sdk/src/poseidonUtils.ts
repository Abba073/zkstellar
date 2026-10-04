// sdk/src/poseidonUtils.ts
//
// Higher-level Poseidon utilities built on top of the low-level poseidon()
// function in poseidon.ts:
//
//   - poseidonBatch()         — hash a list of bigints all at once, chaining
//                               multi-input calls where needed.
//   - domainSeparatedHash()   — Poseidon(domain_tag || ...inputs) for
//                               domain-separation in multi-context systems.
//   - poseidonCommit()        — convenience: hash a single secret to its
//                               public commitment, as the poseidon_preimage
//                               circuit expects.
//   - poseidonCommitDouble()  — double Poseidon hash for the
//                               identity_commitment circuit.

import { poseidon } from "./poseidon.js";
import { SorobanZkError, SorobanZkErrorCode } from "./types.js";

/** Maximum arity for a single Poseidon call (matches poseidon.ts). */
const MAX_ARITY = 16;

// ---------------------------------------------------------------------------
// poseidonBatch
// ---------------------------------------------------------------------------

/**
 * Hash an arbitrarily long list of bigints with Poseidon by folding them
 * into a binary tree of `MAX_ARITY`-input calls.
 *
 * For lists that fit in a single call (≤ {@link MAX_ARITY} inputs), this
 * is identical to calling {@link poseidon} directly. For longer lists, the
 * inputs are split into chunks of `MAX_ARITY`, each chunk is hashed, and
 * the resulting hashes are hashed again recursively until a single value
 * remains.
 *
 * This makes the hash deterministic, collision-resistant (assuming Poseidon
 * is), and independent of how the inputs were originally chunked.
 *
 * @param inputs - One or more bigint field elements.
 * @returns A single bigint digest.
 *
 * @example
 * ```ts
 * const digest = poseidonBatch([a, b, c, d, e, f, g, h,
 *                               i, j, k, l, m, n, o, p, q]);
 * ```
 */
export function poseidonBatch(inputs: bigint[]): bigint {
  if (!Array.isArray(inputs) || inputs.length === 0) {
    throw new SorobanZkError(
      "poseidonBatch: inputs must be a non-empty array",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  for (let i = 0; i < inputs.length; i++) {
    if (typeof inputs[i] !== "bigint") {
      throw new SorobanZkError(
        `poseidonBatch: inputs[${i}] must be a bigint`,
        SorobanZkErrorCode.INVALID_PUBLIC_INPUT
      );
    }
  }

  // Base case: fits in a single call.
  if (inputs.length <= MAX_ARITY) {
    return poseidon(inputs);
  }

  // Recursive case: chunk → hash each chunk → recurse on digests.
  const digests: bigint[] = [];
  for (let i = 0; i < inputs.length; i += MAX_ARITY) {
    digests.push(poseidon(inputs.slice(i, i + MAX_ARITY)));
  }
  return poseidonBatch(digests);
}

// ---------------------------------------------------------------------------
// domainSeparatedHash
// ---------------------------------------------------------------------------

/**
 * Compute a domain-separated Poseidon hash:
 *   `Poseidon(domain_tag, input_0, input_1, ...)`
 *
 * The `domainTag` is prepended as the first input, preventing inputs
 * intended for one context from colliding with identically-valued inputs
 * in another context (e.g. "commitment" vs "nullifier" use-cases).
 *
 * The tag is a `bigint` so callers can choose any encoding they like —
 * e.g. `BigInt("0x" + Buffer.from("commitment").toString("hex"))`.
 *
 * Total input count (1 tag + N inputs) must not exceed {@link MAX_ARITY}.
 * For longer input lists, combine with {@link poseidonBatch}.
 *
 * @param domainTag - A non-zero bigint distinguishing this hash's purpose.
 * @param inputs    - The payload field elements.
 *
 * @example
 * ```ts
 * const COMMITMENT_TAG = 1n;
 * const NULLIFIER_TAG  = 2n;
 *
 * const commitment = domainSeparatedHash(COMMITMENT_TAG, [secret]);
 * const nullifier  = domainSeparatedHash(NULLIFIER_TAG,  [secret]);
 * // commitment !== nullifier even though inputs are identical
 * ```
 */
export function domainSeparatedHash(domainTag: bigint, inputs: bigint[]): bigint {
  if (typeof domainTag !== "bigint") {
    throw new SorobanZkError(
      "domainSeparatedHash: domainTag must be a bigint",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  if (!Array.isArray(inputs) || inputs.length === 0) {
    throw new SorobanZkError(
      "domainSeparatedHash: inputs must be a non-empty array",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  const total = 1 + inputs.length;
  if (total > MAX_ARITY) {
    throw new SorobanZkError(
      `domainSeparatedHash: domainTag + ${inputs.length} inputs exceeds the ` +
        `maximum Poseidon arity of ${MAX_ARITY}. ` +
        "Pre-hash inputs with poseidonBatch() first.",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  return poseidon([domainTag, ...inputs]);
}

// ---------------------------------------------------------------------------
// poseidonCommit
// ---------------------------------------------------------------------------

/**
 * Compute the Poseidon commitment for a single secret:
 *   `commitment = Poseidon(secret)`
 *
 * This matches the `poseidon_preimage` circuit's constraint:
 *   `Poseidon(secret) === commitment`
 *
 * @example
 * ```ts
 * const secret = 123456789n;
 * const commitment = poseidonCommit(secret);
 * // Pass commitment as the circuit's public input.
 * ```
 */
export function poseidonCommit(secret: bigint): bigint {
  if (typeof secret !== "bigint") {
    throw new SorobanZkError(
      "poseidonCommit: secret must be a bigint",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }
  return poseidon([secret]);
}

// ---------------------------------------------------------------------------
// poseidonCommitDouble
// ---------------------------------------------------------------------------

/**
 * Compute the double Poseidon commitment for the `identity_commitment`
 * circuit:
 *
 *   `inner  = Poseidon(secret)`
 *   `outer  = Poseidon(inner)`
 *
 * The circuit exposes `inner` and `outer` as public inputs so a verifier
 * can confirm the first-level commitment without learning `secret`.
 *
 * @returns `{ inner, outer }` — pass `outer` as the circuit's primary public
 *   input and `inner` as the secondary one.
 *
 * @example
 * ```ts
 * const { inner, outer } = poseidonCommitDouble(secret);
 * // Circuit inputs: { secret: secret.toString(), inner: inner.toString() }
 * // Circuit public outputs: [outer.toString(), inner.toString()]
 * ```
 */
export function poseidonCommitDouble(secret: bigint): { inner: bigint; outer: bigint } {
  if (typeof secret !== "bigint") {
    throw new SorobanZkError(
      "poseidonCommitDouble: secret must be a bigint",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }
  const inner = poseidon([secret]);
  const outer = poseidon([inner]);
  return { inner, outer };
}
