// sdk/src/metadata.ts
//
// ProofMetadata: a lightweight record attached to a proof that tracks
// circuit identity, expiry window, and submission timing. It is designed
// to be stored alongside a ProofBundle and consulted before submitting
// to avoid avoidable on-chain rejections (expired proof, wrong circuit).

import { SorobanZkError, SorobanZkErrorCode } from "./types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A self-describing metadata envelope that travels with a proof and lets
 * off-chain tooling answer "is this proof still submittable?" before
 * hitting the RPC node.
 */
export interface ProofMetadata {
  /** The circuit name this proof was generated for, e.g. `"poseidon_preimage"`. */
  circuit: string;
  /**
   * The numeric circuit ID this proof targets in `contracts/registry`.
   * `undefined` when the proof is only used with `contracts/verifier`.
   */
  circuitId?: number;
  /** ISO-8601 timestamp of when the proof was generated. */
  generatedAt: string;
  /**
   * The Soroban ledger sequence number after which this proof is considered
   * expired and will be rejected by `contracts/verifier`. `undefined` when
   * no expiry was set (proof never expires).
   */
  expiryLedger?: number;
  /**
   * Estimated wall-clock deadline derived from `expiryLedger` and a known
   * average ledger close time. Informational only — the contract always
   * uses the ledger sequence number for the actual check.
   */
  estimatedExpiryAt?: string;
  /** Free-form tags for application-level use (e.g. `["testnet", "v2"]`). */
  tags?: string[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Stellar's target average ledger close time in seconds. */
export const LEDGER_CLOSE_TIME_SECONDS = 5;

// ---------------------------------------------------------------------------
// createProofMetadata
// ---------------------------------------------------------------------------

/**
 * Options for {@link createProofMetadata}.
 */
export interface CreateProofMetadataOptions {
  /** Circuit name, e.g. `"poseidon_preimage"`. */
  circuit: string;
  /** Optional numeric circuit ID in `contracts/registry`. */
  circuitId?: number;
  /**
   * The expiry ledger number embedded in the proof's public inputs.
   * Pass `undefined` for a proof with no expiry.
   */
  expiryLedger?: number;
  /**
   * The current ledger sequence number at generation time. Required when
   * `expiryLedger` is set, so that {@link estimateExpiryDate} can compute
   * the wall-clock deadline. Optional otherwise.
   */
  currentLedger?: number;
  /** ISO-8601 override for `generatedAt`. Defaults to `new Date().toISOString()`. */
  generatedAt?: string;
  /** Free-form tags. */
  tags?: string[];
}

/**
 * Construct a {@link ProofMetadata} record for a proof about to be (or just)
 * generated.
 *
 * @example
 * ```ts
 * const meta = createProofMetadata({
 *   circuit: "poseidon_preimage",
 *   circuitId: 1,
 *   expiryLedger: currentLedger + 1000,
 *   currentLedger,
 * });
 * ```
 */
export function createProofMetadata(opts: CreateProofMetadataOptions): ProofMetadata {
  if (!opts.circuit || typeof opts.circuit !== "string" || opts.circuit.trim() === "") {
    throw new SorobanZkError(
      "createProofMetadata: circuit must be a non-empty string",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  if (opts.circuitId !== undefined) {
    if (!Number.isInteger(opts.circuitId) || opts.circuitId < 0) {
      throw new SorobanZkError(
        "createProofMetadata: circuitId must be a non-negative integer",
        SorobanZkErrorCode.INVALID_PROOF_FORMAT
      );
    }
  }

  if (opts.expiryLedger !== undefined) {
    if (!Number.isInteger(opts.expiryLedger) || opts.expiryLedger < 0 || opts.expiryLedger > 0xffffffff) {
      throw new SorobanZkError(
        "createProofMetadata: expiryLedger must be an unsigned 32-bit integer",
        SorobanZkErrorCode.INVALID_PROOF_FORMAT
      );
    }
  }

  const generatedAt = opts.generatedAt ?? new Date().toISOString();

  let estimatedExpiryAt: string | undefined;
  if (opts.expiryLedger !== undefined && opts.currentLedger !== undefined) {
    estimatedExpiryAt = estimateExpiryDate(
      opts.expiryLedger,
      opts.currentLedger,
      new Date(generatedAt)
    ).toISOString();
  }

  return {
    circuit: opts.circuit.trim(),
    circuitId: opts.circuitId,
    generatedAt,
    expiryLedger: opts.expiryLedger,
    estimatedExpiryAt,
    tags: opts.tags,
  };
}

// ---------------------------------------------------------------------------
// estimateExpiryDate
// ---------------------------------------------------------------------------

/**
 * Estimate the wall-clock expiry date for a proof given its expiry ledger,
 * the current ledger sequence number, and the current wall-clock time.
 *
 * Uses {@link LEDGER_CLOSE_TIME_SECONDS} (5 s) as the average close time.
 * The result is approximate — on-chain verification uses the ledger sequence
 * number, not the wall clock.
 *
 * @param expiryLedger  - Ledger number at which the proof expires.
 * @param currentLedger - Current ledger sequence number.
 * @param now           - Reference wall-clock time (defaults to `new Date()`).
 */
export function estimateExpiryDate(
  expiryLedger: number,
  currentLedger: number,
  now: Date = new Date()
): Date {
  const ledgersRemaining = expiryLedger - currentLedger;
  const secondsRemaining = ledgersRemaining * LEDGER_CLOSE_TIME_SECONDS;
  return new Date(now.getTime() + secondsRemaining * 1000);
}

// ---------------------------------------------------------------------------
// isProofExpired
// ---------------------------------------------------------------------------

/**
 * Return `true` if `meta.expiryLedger` is set and is strictly less than
 * `currentLedger` — i.e. the proof would be rejected by `contracts/verifier`
 * right now.
 *
 * Returns `false` (not expired) when `meta.expiryLedger` is `undefined`,
 * matching the contract's behaviour: a proof with no expiry field never
 * expires (within the verifier contract's purview).
 *
 * @example
 * ```ts
 * const ledger = await getCurrentLedger(rpcUrl);
 * if (isProofExpired(meta, ledger)) {
 *   console.error("Proof has expired — regenerate it.");
 * }
 * ```
 */
export function isProofExpired(meta: ProofMetadata, currentLedger: number): boolean {
  if (meta.expiryLedger === undefined) {
    return false;
  }
  return currentLedger > meta.expiryLedger;
}

// ---------------------------------------------------------------------------
// ledgersUntilExpiry
// ---------------------------------------------------------------------------

/**
 * Return the number of ledgers remaining before `meta.expiryLedger`.
 * Returns `Infinity` when no expiry is set, and 0 (clamped) when already
 * expired.
 *
 * @example
 * ```ts
 * const remaining = ledgersUntilExpiry(meta, currentLedger);
 * if (remaining < 100) {
 *   console.warn(`Proof expires in ~${remaining * 5} seconds.`);
 * }
 * ```
 */
export function ledgersUntilExpiry(meta: ProofMetadata, currentLedger: number): number {
  if (meta.expiryLedger === undefined) {
    return Infinity;
  }
  return Math.max(0, meta.expiryLedger - currentLedger);
}

// ---------------------------------------------------------------------------
// recommendExpiryLedger
// ---------------------------------------------------------------------------

/**
 * Recommend a safe expiry ledger for a new proof given the current ledger
 * and a desired time-to-live in seconds.
 *
 * Rounds up to the nearest ledger boundary to avoid edge cases where the
 * proof is submitted on exactly the expiry ledger.
 *
 * @param currentLedger   - Current ledger sequence number.
 * @param ttlSeconds      - Desired proof lifetime in seconds.
 * @param closeTimeSeconds - Average ledger close time (default: 5 s).
 *
 * @example
 * ```ts
 * // Proof valid for ~10 minutes
 * const expiryLedger = recommendExpiryLedger(currentLedger, 600);
 * ```
 */
export function recommendExpiryLedger(
  currentLedger: number,
  ttlSeconds: number,
  closeTimeSeconds: number = LEDGER_CLOSE_TIME_SECONDS
): number {
  if (!Number.isInteger(currentLedger) || currentLedger < 0) {
    throw new SorobanZkError(
      "recommendExpiryLedger: currentLedger must be a non-negative integer",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }
  if (ttlSeconds <= 0) {
    throw new SorobanZkError(
      "recommendExpiryLedger: ttlSeconds must be positive",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  const ledgersNeeded = Math.ceil(ttlSeconds / closeTimeSeconds);
  const expiry = currentLedger + ledgersNeeded;

  // Clamp to u32 max (Soroban ledger numbers are u32).
  return Math.min(expiry, 0xffffffff);
}
