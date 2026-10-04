// sdk/src/bundleIO.ts
//
// ProofBundle export / import utilities.
//
// Bundles are plain JSON objects in memory. These helpers let callers
// round-trip them through:
//   - Base64 strings  (for QR codes, URLs, clipboard)
//   - JSON strings    (for files / HTTP bodies)
//
// A structural validator (validateBundleShape) guards all import paths so
// that callers get a typed SorobanZkError instead of a runtime crash when
// they load a malformed or truncated bundle.

import { ProofBundle, SnarkjsProof, SorobanZkError, SorobanZkErrorCode } from "./types.js";
import { signBundle, SignedBundle, verifyBundleIntegrity } from "./bundle.js";

// ---------------------------------------------------------------------------
// validateBundleShape  (structural / schema check)
// ---------------------------------------------------------------------------

/**
 * Validate that a plain JS value has the shape of a {@link ProofBundle}.
 *
 * This is a *structural* check (required fields, correct types) — it is NOT
 * the same as {@link verifyBundleIntegrity}, which additionally re-encodes
 * the proof bytes and optionally checks the SHA-256 digest. Run both when
 * you need the full guarantee.
 *
 * @throws {@link SorobanZkError} with `INVALID_PROOF_FORMAT` on the first
 *   violation found.
 */
export function validateBundleShape(value: unknown): asserts value is ProofBundle {
  if (value === null || typeof value !== "object") {
    throw new SorobanZkError(
      "validateBundleShape: bundle must be a plain object",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  const obj = value as Record<string, unknown>;

  // --- circuit ---
  if (typeof obj["circuit"] !== "string" || obj["circuit"].trim() === "") {
    throw new SorobanZkError(
      "validateBundleShape: bundle.circuit must be a non-empty string",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  // --- generatedAt ---
  if (typeof obj["generatedAt"] !== "string" || obj["generatedAt"].trim() === "") {
    throw new SorobanZkError(
      "validateBundleShape: bundle.generatedAt must be a non-empty string",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  // --- networkPassphrase ---
  if (typeof obj["networkPassphrase"] !== "string" || obj["networkPassphrase"].trim() === "") {
    throw new SorobanZkError(
      "validateBundleShape: bundle.networkPassphrase must be a non-empty string",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  // --- publicSignals ---
  if (!Array.isArray(obj["publicSignals"])) {
    throw new SorobanZkError(
      "validateBundleShape: bundle.publicSignals must be an array",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }
  for (let i = 0; i < (obj["publicSignals"] as unknown[]).length; i++) {
    if (typeof (obj["publicSignals"] as unknown[])[i] !== "string") {
      throw new SorobanZkError(
        `validateBundleShape: bundle.publicSignals[${i}] must be a string`,
        SorobanZkErrorCode.INVALID_PROOF_FORMAT
      );
    }
  }

  // --- proof ---
  const proof = obj["proof"];
  if (proof === null || typeof proof !== "object") {
    throw new SorobanZkError(
      "validateBundleShape: bundle.proof must be an object",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }
  const p = proof as Record<string, unknown>;

  if ((p["protocol"] as string) !== "groth16") {
    throw new SorobanZkError(
      `validateBundleShape: bundle.proof.protocol must be "groth16" (got "${p["protocol"]}")`,
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  for (const field of ["pi_a", "pi_c"] as const) {
    if (!Array.isArray(p[field]) || (p[field] as unknown[]).length < 2) {
      throw new SorobanZkError(
        `validateBundleShape: bundle.proof.${field} must be an array with at least 2 elements`,
        SorobanZkErrorCode.INVALID_PROOF_FORMAT
      );
    }
  }

  if (!Array.isArray(p["pi_b"]) || (p["pi_b"] as unknown[]).length < 2) {
    throw new SorobanZkError(
      "validateBundleShape: bundle.proof.pi_b must be an array with at least 2 elements",
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }
}

// ---------------------------------------------------------------------------
// bundleToJson / bundleFromJson
// ---------------------------------------------------------------------------

/**
 * Serialize a {@link ProofBundle} (or {@link SignedBundle}) to a pretty JSON
 * string.
 *
 * @example
 * ```ts
 * import { writeFileSync } from "node:fs";
 * writeFileSync("proof.bundle.json", bundleToJson(signBundle(bundle)));
 * ```
 */
export function bundleToJson(bundle: ProofBundle, pretty = true): string {
  return JSON.stringify(bundle, null, pretty ? 2 : undefined);
}

/**
 * Parse a JSON string back into a {@link ProofBundle}, running a full
 * structural shape check before returning.
 *
 * @throws {@link SorobanZkError} on JSON parse failure or shape violation.
 *
 * @example
 * ```ts
 * import { readFileSync } from "node:fs";
 * const bundle = bundleFromJson(readFileSync("proof.bundle.json", "utf8"));
 * ```
 */
export function bundleFromJson(json: string): ProofBundle {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    throw new SorobanZkError(
      `bundleFromJson: invalid JSON — ${err instanceof Error ? err.message : String(err)}`,
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }
  validateBundleShape(parsed);
  return parsed;
}

// ---------------------------------------------------------------------------
// bundleToBase64 / bundleFromBase64
// ---------------------------------------------------------------------------

/**
 * Encode a {@link ProofBundle} to a URL-safe Base64 string (no padding).
 *
 * Useful for embedding in QR codes, URLs, or clipboard payloads.
 *
 * @example
 * ```ts
 * const b64 = bundleToBase64(bundle);
 * console.log(`zkstellar://verify?bundle=${b64}`);
 * ```
 */
export function bundleToBase64(bundle: ProofBundle): string {
  const json = bundleToJson(bundle, false);
  return Buffer.from(json, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Decode a Base64 (standard or URL-safe, with or without padding) string
 * back into a {@link ProofBundle}, running a full shape check.
 *
 * @throws {@link SorobanZkError} on decode failure or shape violation.
 *
 * @example
 * ```ts
 * const bundle = bundleFromBase64(urlParam);
 * ```
 */
export function bundleFromBase64(b64: string): ProofBundle {
  // Normalise URL-safe alphabet back to standard and re-add padding.
  const standard = b64.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard + "=".repeat((4 - (standard.length % 4)) % 4);

  let json: string;
  try {
    json = Buffer.from(padded, "base64").toString("utf8");
  } catch (err) {
    throw new SorobanZkError(
      `bundleFromBase64: base64 decode failed — ${err instanceof Error ? err.message : String(err)}`,
      SorobanZkErrorCode.INVALID_PROOF_FORMAT
    );
  }

  return bundleFromJson(json);
}

// ---------------------------------------------------------------------------
// importSignedBundle
// ---------------------------------------------------------------------------

/**
 * Result of {@link importSignedBundle}.
 */
export interface ImportBundleResult {
  /** The validated and integrity-checked bundle. */
  bundle: SignedBundle;
  /**
   * Whether the bundle carried a `digest` field that passed the SHA-256
   * integrity check. `false` means the bundle was imported successfully
   * but was not signed — it can still be used, but you get no tamper
   * evidence.
   */
  integrityVerified: boolean;
}

/**
 * Import a bundle from any supported encoding (JSON string, Base64 string,
 * or a plain JS object), run a full structural validation, and optionally
 * verify the SHA-256 digest if one is present.
 *
 * If the bundle has no `digest` field, it is auto-signed before return so
 * the caller always receives a {@link SignedBundle}.
 *
 * @example
 * ```ts
 * const { bundle, integrityVerified } = importSignedBundle(rawJson);
 * if (!integrityVerified) {
 *   console.warn("Bundle has no digest — tamper evidence unavailable.");
 * }
 * ```
 */
export function importSignedBundle(
  input: string | Record<string, unknown>
): ImportBundleResult {
  // Parse if string.
  let raw: unknown;
  if (typeof input === "string") {
    // Heuristic: if it starts with `{` it's JSON, otherwise try base64.
    const trimmed = input.trimStart();
    if (trimmed.startsWith("{")) {
      raw = (() => {
        try { return JSON.parse(trimmed); }
        catch (err) {
          throw new SorobanZkError(
            `importSignedBundle: invalid JSON — ${err instanceof Error ? err.message : String(err)}`,
            SorobanZkErrorCode.INVALID_PROOF_FORMAT
          );
        }
      })();
    } else {
      raw = bundleFromBase64(input);
    }
  } else {
    raw = input;
  }

  validateBundleShape(raw);
  const plain = raw as ProofBundle;

  const hasDigest = typeof (plain as SignedBundle).digest === "string";

  if (hasDigest) {
    const integrityResult = verifyBundleIntegrity(plain as SignedBundle);
    if (!integrityResult.valid) {
      throw new SorobanZkError(
        `importSignedBundle: integrity check failed — ${integrityResult.reason}`,
        SorobanZkErrorCode.INVALID_PROOF_FORMAT
      );
    }
    return { bundle: plain as SignedBundle, integrityVerified: true };
  }

  // No digest: auto-sign and return with integrityVerified = false.
  return { bundle: signBundle(plain), integrityVerified: false };
}
