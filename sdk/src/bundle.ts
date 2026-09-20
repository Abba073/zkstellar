// sdk/src/bundle.ts
//
// ProofBundle builder utilities. A ProofBundle is a self-describing JSON
// envelope that packages a snarkjs Groth16 proof together with the metadata
// needed to submit and verify it later — circuit name, network passphrase,
// and a generation timestamp. These utilities make constructing, validating,
// and checking the integrity of bundles explicit and safe, rather than
// leaving callers to hand-craft the object.

import { createHash } from "node:crypto";

import { formatProof } from "./proof.js";
import { ProofBundle, SnarkjsProof, SorobanZkError, SorobanZkErrorCode } from "./types.js";
import { validateProofInput } from "./validate.js";

// ---------------------------------------------------------------------------
// BundleIntegrityResult
// ---------------------------------------------------------------------------

/**
 * Result of {@link verifyBundleIntegrity}.
 *
 * `valid` is true only when every field is well-formed and the embedded
 * digest matches a fresh SHA-256 of the bundle content.
 */
export interface BundleIntegrityResult {
  valid: boolean;
  /** Human-readable description of the first integrity violation, if any. */
  reason?: string;
  /** ISO-8601 timestamp string from the bundle. */
  generatedAt: string;
  /** Circuit name from the bundle. */
  circuit: string;
  /** Network passphrase from the bundle. */
  networkPassphrase: string;
  /** Number of public signals in the bundle. */
  publicSignalCount: number;
}

// ---------------------------------------------------------------------------
// CreateBundleOptions
// ---------------------------------------------------------------------------

/**
 * Options for {@link createBundle}.
 */
export interface CreateBundleOptions {
  /** The Groth16 proof from snarkjs `groth16.fullProve`. */
  proof: SnarkjsProof;
  /** The public signals array returned alongside the proof. */
  publicSignals: string[];
  /** Circuit name, e.g. `"poseidon_preimage"`, `"range_proof"`. */
  circuit: string;
  /**
   * Stellar network passphrase, e.g.
   * `"Test SDF Network ; September 2015"`. This is checked when
   * the bundle is submitted via `verifyOnChain` or `verifyViaRegistry`.
   */
  networkPassphrase: string;
  /**
   * Override the bundle's `generatedAt` timestamp. Defaults to the
   * current UTC time in ISO-8601 format. Useful for deterministic
   * tests.
   */
  generatedAt?: string;
}

// ---------------------------------------------------------------------------
// createBundle
// ---------------------------------------------------------------------------

/**
 * Construct a {@link ProofBundle} from a snarkjs proof and the metadata
 * needed to submit and verify it later.
 *
 * The returned bundle is a plain JSON-serializable object — write it to
 * disk, pass it to {@link verifyOnChain} / {@link verifyViaRegistry}, or
 * inspect it with the CLI's `decode-bundle` command.
 *
 * @example
 * ```ts
 * const { proof, publicSignals } = await snarkjs.groth16.fullProve(
 *   { secret: secret.toString(), commitment: commitment.toString() },
 *   wasmPath,
 *   zkeyPath,
 * );
 *
 * const bundle = createBundle({
 *   proof,
 *   publicSignals,
 *   circuit: "poseidon_preimage",
 *   networkPassphrase: "Test SDF Network ; September 2015",
 * });
 *
 * fs.writeFileSync("proof.bundle.json", JSON.stringify(bundle, null, 2));
 * ```
 */
export function createBundle(opts: CreateBundleOptions): ProofBundle {
  validateProofInput(opts.proof, opts.publicSignals);

  if (!opts.circuit || typeof opts.circuit !== "string" || opts.circuit.trim() === "") {
    throw new SorobanZkError(
      "createBundle: circuit must be a non-empty string",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  if (
    !opts.networkPassphrase ||
    typeof opts.networkPassphrase !== "string" ||
    opts.networkPassphrase.trim() === ""
  ) {
    throw new SorobanZkError(
      "createBundle: networkPassphrase must be a non-empty string",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  const generatedAt = opts.generatedAt ?? new Date().toISOString();

  return {
    proof: opts.proof,
    publicSignals: opts.publicSignals,
    circuit: opts.circuit.trim(),
    generatedAt,
    networkPassphrase: opts.networkPassphrase,
  };
}

// ---------------------------------------------------------------------------
// bundleDigest — deterministic SHA-256 of a bundle's content fields
// ---------------------------------------------------------------------------

/**
 * Compute a deterministic SHA-256 digest of a {@link ProofBundle}'s
 * content fields (proof + publicSignals + circuit + networkPassphrase +
 * generatedAt). The digest is hex-encoded and can be stored alongside the
 * bundle to detect tampering.
 *
 * Note: `generatedAt` is included in the digest so that two bundles for the
 * same proof but generated at different times produce different digests.
 */
export function bundleDigest(bundle: ProofBundle): string {
  const content = JSON.stringify({
    proof: bundle.proof,
    publicSignals: bundle.publicSignals,
    circuit: bundle.circuit,
    generatedAt: bundle.generatedAt,
    // networkPassphrase is a well-known Stellar protocol constant string
    // (e.g. "Test SDF Network ; September 2015"), not a user password.
    // This SHA-256 is used for content-integrity detection, not password storage.
    networkPassphrase: bundle.networkPassphrase,
  });
  return createHash("sha256").update(content, "utf8").digest("hex"); // CodeQL [js/weak-cryptographic-algorithm] SHA-256 used for content integrity, not password hashing
}

// ---------------------------------------------------------------------------
// SignedBundle — a bundle with an attached digest
// ---------------------------------------------------------------------------

/**
 * A {@link ProofBundle} extended with a SHA-256 content digest that
 * {@link verifyBundleIntegrity} can check.
 *
 * Use {@link signBundle} to produce one and {@link verifyBundleIntegrity}
 * to check one.
 */
export interface SignedBundle extends ProofBundle {
  /**
   * SHA-256 hex digest of the bundle's content fields (proof,
   * publicSignals, circuit, generatedAt, networkPassphrase).
   * Computed by {@link signBundle} and verified by
   * {@link verifyBundleIntegrity}.
   */
  digest: string;
}

// ---------------------------------------------------------------------------
// signBundle
// ---------------------------------------------------------------------------

/**
 * Attach a SHA-256 content digest to a {@link ProofBundle}, producing a
 * {@link SignedBundle}. The digest covers all five content fields (proof,
 * publicSignals, circuit, generatedAt, networkPassphrase) and allows
 * {@link verifyBundleIntegrity} to detect any post-creation modification.
 *
 * @example
 * ```ts
 * const signed = signBundle(bundle);
 * fs.writeFileSync("proof.signed.json", JSON.stringify(signed, null, 2));
 * ```
 */
export function signBundle(bundle: ProofBundle): SignedBundle {
  return { ...bundle, digest: bundleDigest(bundle) };
}

// ---------------------------------------------------------------------------
// verifyBundleIntegrity
// ---------------------------------------------------------------------------

/**
 * Verify that a bundle (optionally containing a `digest` field from
 * {@link signBundle}) is internally consistent:
 *
 * 1. All required fields are present and non-empty.
 * 2. The proof encodes correctly via {@link formatProof} (G1/G2 byte
 *    lengths and BN254 field element range checks).
 * 3. If a `digest` field is present, it matches a freshly-computed
 *    SHA-256 of the bundle's content.
 *
 * This check is local and offline — it never touches the network.
 *
 * @example
 * ```ts
 * const result = verifyBundleIntegrity(signedBundle);
 * if (!result.valid) {
 *   console.error("Bundle integrity check failed:", result.reason);
 * }
 * ```
 */
export function verifyBundleIntegrity(
  bundle: ProofBundle | SignedBundle
): BundleIntegrityResult {
  const base: BundleIntegrityResult = {
    valid: false,
    generatedAt: bundle.generatedAt ?? "",
    circuit: bundle.circuit ?? "",
    networkPassphrase: bundle.networkPassphrase ?? "",
    publicSignalCount: Array.isArray(bundle.publicSignals) ? bundle.publicSignals.length : 0,
  };

  // 1. Required string fields
  for (const field of ["circuit", "generatedAt", "networkPassphrase"] as const) {
    if (!bundle[field] || typeof bundle[field] !== "string" || bundle[field].trim() === "") {
      return { ...base, reason: `${field} is missing or empty` };
    }
  }

  // 2. Proof and public signals must encode cleanly
  try {
    validateProofInput(bundle.proof, bundle.publicSignals);
    formatProof(bundle.proof, bundle.publicSignals);
  } catch (err) {
    return {
      ...base,
      reason: err instanceof Error ? err.message : String(err),
    };
  }

  // 3. Digest check (only if the bundle was produced by signBundle)
  const signed = bundle as SignedBundle;
  if (typeof signed.digest === "string") {
    const expected = bundleDigest(bundle);
    if (signed.digest !== expected) {
      return {
        ...base,
        reason: `digest mismatch: stored=${signed.digest.slice(0, 16)}… expected=${expected.slice(0, 16)}…`,
      };
    }
  }

  return { ...base, valid: true };
}
