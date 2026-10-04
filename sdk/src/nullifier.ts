// sdk/src/nullifier.ts
//
// Off-chain nullifier utilities that mirror contracts/registry's on-chain
// nullifier computation. Use these to predict whether a proof will be
// rejected as a replay before submitting it, or to build an off-chain
// nullifier index.
//
// On-chain formula (contracts/registry/src/lib.rs):
//   nullifier = sha256( circuit_id_be4 || inputs_hash )
// where
//   inputs_hash = sha256( concat(public_inputs_bytes) )

import { createHash } from "node:crypto";

import { SorobanZkError, SorobanZkErrorCode } from "./types.js";

// ---------------------------------------------------------------------------
// computeInputsHash
// ---------------------------------------------------------------------------

/**
 * Compute the `inputs_hash` for a set of 32-byte public input buffers —
 * the SHA-256 of the concatenation of all inputs in order.
 *
 * This is the same value the verifier and registry contracts publish in
 * their `verification_result` event's `inputs_hash` field, and that
 * `getVerificationHistory` returns as `entry.inputsHash` (hex-encoded).
 *
 * @param publicInputs - Array of 32-byte `Buffer` values (already encoded
 *   with {@link formatProof}).
 * @returns A 32-byte `Buffer` containing the SHA-256 digest.
 *
 * @example
 * ```ts
 * const calldata = formatProof(proof, publicSignals);
 * const inputsHash = computeInputsHash(calldata.publicInputs);
 * console.log(inputsHash.toString("hex"));
 * ```
 */
export function computeInputsHash(publicInputs: Buffer[]): Buffer {
  if (!Array.isArray(publicInputs) || publicInputs.length === 0) {
    throw new SorobanZkError(
      "computeInputsHash: publicInputs must be a non-empty array",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  for (let i = 0; i < publicInputs.length; i++) {
    if (!Buffer.isBuffer(publicInputs[i]) || publicInputs[i].length !== 32) {
      throw new SorobanZkError(
        `computeInputsHash: publicInputs[${i}] must be a 32-byte Buffer`,
        SorobanZkErrorCode.INVALID_PUBLIC_INPUT
      );
    }
  }

  const hash = createHash("sha256");
  for (const input of publicInputs) {
    hash.update(input);
  }
  return hash.digest();
}

// ---------------------------------------------------------------------------
// computeNullifier
// ---------------------------------------------------------------------------

/**
 * Compute the registry nullifier for a (circuit, proof) pair:
 *   `sha256( circuit_id_be4 || inputs_hash )`
 *
 * This mirrors `compute_nullifier` in `contracts/registry/src/lib.rs`
 * exactly. Scoping to `circuitId` prevents cross-circuit collisions when
 * two different circuits accept inputs that happen to hash identically.
 *
 * @param circuitId    - The circuit's numeric registry ID (u32).
 * @param publicInputs - The 32-byte encoded public input buffers from
 *   {@link formatProof}.
 * @returns A 32-byte `Buffer` — the nullifier key.
 *
 * @example
 * ```ts
 * const calldata = formatProof(proof, publicSignals);
 * const nullifier = computeNullifier(1, calldata.publicInputs);
 *
 * // Check before submitting:
 * const used = await isNullifierUsedOnChain({ rpcUrl, registryContractId, nullifier });
 * if (used) console.error("This proof has already been verified.");
 * ```
 */
export function computeNullifier(circuitId: number, publicInputs: Buffer[]): Buffer {
  if (!Number.isInteger(circuitId) || circuitId < 0 || circuitId > 0xffffffff) {
    throw new SorobanZkError(
      "computeNullifier: circuitId must be an unsigned 32-bit integer",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  const inputsHash = computeInputsHash(publicInputs);

  const circuitIdBytes = Buffer.allocUnsafe(4);
  circuitIdBytes.writeUInt32BE(circuitId, 0);

  const hash = createHash("sha256");
  hash.update(circuitIdBytes);
  hash.update(inputsHash);
  return hash.digest();
}

// ---------------------------------------------------------------------------
// nullifierHex / nullifierFromHex
// ---------------------------------------------------------------------------

/**
 * Hex-encode a nullifier buffer (lowercase, no `0x` prefix) — matches the
 * format `getVerificationHistory` returns for `inputsHash`.
 */
export function nullifierHex(nullifier: Buffer): string {
  if (!Buffer.isBuffer(nullifier) || nullifier.length !== 32) {
    throw new SorobanZkError(
      "nullifierHex: nullifier must be a 32-byte Buffer",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }
  return nullifier.toString("hex");
}

/**
 * Decode a hex string (with or without `0x` prefix) back to a 32-byte
 * nullifier `Buffer`. Useful when round-tripping through JSON or logs.
 *
 * @throws {@link SorobanZkError} with `INVALID_PUBLIC_INPUT` if the input
 *   is not a valid 64-char hex string.
 */
export function nullifierFromHex(hex: string): Buffer {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new SorobanZkError(
      `nullifierFromHex: expected a 64-character hex string, got "${clean.slice(0, 20)}${clean.length > 20 ? "…" : ""}"`,
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }
  return Buffer.from(clean, "hex");
}

// ---------------------------------------------------------------------------
// isNullifierUsedOnChain  (simulation-only RPC call)
// ---------------------------------------------------------------------------

import {
  Account,
  Contract,
  Keypair,
  TransactionBuilder,
  BASE_FEE,
  rpc,
  scValToNative,
  xdr,
} from "@stellar/stellar-sdk";

/**
 * Options for {@link isNullifierUsedOnChain}.
 */
export interface IsNullifierUsedOptions {
  /** Soroban RPC endpoint URL. */
  rpcUrl: string;
  /** Bech32m address of the deployed `contracts/registry` instance. */
  registryContractId: string;
  /**
   * The 32-byte nullifier to check — compute with {@link computeNullifier}.
   */
  nullifier: Buffer;
}

/**
 * Query `contracts/registry`'s `is_nullifier_used(nullifier)` view function
 * via a simulation-only call — no transaction is submitted, no fee is
 * charged, and no keypair is needed.
 *
 * Returns `true` if the nullifier has already been burned (proof was
 * successfully verified and can never be replayed), `false` otherwise.
 *
 * @example
 * ```ts
 * const calldata = formatProof(proof, publicSignals);
 * const nullifier = computeNullifier(1, calldata.publicInputs);
 *
 * const used = await isNullifierUsedOnChain({
 *   rpcUrl: "https://soroban-testnet.stellar.org",
 *   registryContractId: "CDTPNARKKZCZ36PL4BNKBXZTT2BLVR373S2K5NCFAOKCPPY62ESRHSXH",
 *   nullifier,
 * });
 * console.log("already used:", used);
 * ```
 */
export async function isNullifierUsedOnChain(
  opts: IsNullifierUsedOptions
): Promise<boolean> {
  if (!Buffer.isBuffer(opts.nullifier) || opts.nullifier.length !== 32) {
    throw new SorobanZkError(
      "isNullifierUsedOnChain: nullifier must be a 32-byte Buffer",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  const server = new rpc.Server(opts.rpcUrl, {
    allowHttp: opts.rpcUrl.startsWith("http://"),
  });
  const network = await server.getNetwork();

  const contract = new Contract(opts.registryContractId);
  const ephemeral = Keypair.random();
  let account: InstanceType<typeof import("@stellar/stellar-sdk").Account>;
  try {
    account = await server.getAccount(ephemeral.publicKey());
  } catch {
    account = new Account(ephemeral.publicKey(), "0");
  }

  const nullifierScVal = xdr.ScVal.scvBytes(opts.nullifier);

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: network.passphrase,
  })
    .addOperation(contract.call("is_nullifier_used", nullifierScVal))
    .setTimeout(30)
    .build();

  const simResult = await server.simulateTransaction(transaction);

  if (rpc.Api.isSimulationError(simResult)) {
    throw new SorobanZkError(
      `is_nullifier_used simulation failed: ${simResult.error}`,
      SorobanZkErrorCode.CONTRACT_INVOCATION_FAILED
    );
  }

  if (!("result" in simResult) || !simResult.result) {
    throw new SorobanZkError(
      "is_nullifier_used simulation returned no result",
      SorobanZkErrorCode.CONTRACT_INVOCATION_FAILED
    );
  }

  return Boolean(scValToNative(simResult.result.retval));
}
