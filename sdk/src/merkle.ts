// sdk/src/merkle.ts
//
// Pure-TypeScript Poseidon Merkle tree utilities for the `merkle_inclusion`
// circuit (circuits/merkle_inclusion/circuit.circom, depth 20). These helpers
// mirror the on-chain tree structure exactly: nodes are Poseidon(left, right)
// hashes, leaves are arbitrary field elements, and the tree is always padded
// to 2^depth leaves with a zero-leaf so the circuit's fixed-depth path always
// has the correct length.
//
// The canonical use-case is:
//   1. Build a tree from your set of leaves.
//   2. Commit to the root (publish it or pass it to the contract).
//   3. Later generate inclusion proofs with buildMerkleProof() and feed
//      them as circuit inputs to snarkjs groth16.fullProve().

import { poseidon } from "./poseidon.js";
import { SorobanZkError, SorobanZkErrorCode } from "./types.js";

/** The tree depth used by circuits/merkle_inclusion/circuit.circom. */
export const MERKLE_DEPTH = 20;

/** Maximum number of leaves a depth-20 tree can hold: 2^20 = 1,048,576. */
export const MERKLE_MAX_LEAVES = 1 << MERKLE_DEPTH;

/** The zero-leaf used for padding: bigint 0. */
export const MERKLE_ZERO_LEAF = 0n;

// ---------------------------------------------------------------------------
// MerkleTree
// ---------------------------------------------------------------------------

/**
 * An in-memory Poseidon Merkle tree with a fixed depth of
 * {@link MERKLE_DEPTH} (matching `circuits/merkle_inclusion`).
 *
 * Build one with {@link buildMerkleTree} and generate inclusion proofs with
 * {@link buildMerkleProof}. The tree is immutable after construction.
 */
export interface MerkleTree {
  /** The Merkle root — pass this as the circuit's `root` public input. */
  root: bigint;
  /**
   * All leaves (padded to `2^MERKLE_DEPTH`).
   * `leaves[i]` is the value you can prove membership for via
   * {@link buildMerkleProof}.
   */
  leaves: bigint[];
  /**
   * All internal nodes, stored as layers from leaves to root.
   * `layers[0]` is the leaf layer (same as `leaves`), `layers[MERKLE_DEPTH]`
   * is a length-1 array containing the root.
   */
  layers: bigint[][];
}

// ---------------------------------------------------------------------------
// MerkleProof
// ---------------------------------------------------------------------------

/**
 * An inclusion proof that a particular leaf is in a {@link MerkleTree}.
 *
 * Pass these fields directly to the `merkle_inclusion` circuit:
 * ```
 * { leaf, pathElements, pathIndices, root }
 * ```
 */
export interface MerkleProof {
  /** The leaf value being proven. */
  leaf: bigint;
  /**
   * Sibling hashes at each level of the path, from leaf to root.
   * Length = {@link MERKLE_DEPTH}.
   */
  pathElements: bigint[];
  /**
   * Direction bits: 0 means the leaf (or subtree) is the left child,
   * 1 means it is the right child. Length = {@link MERKLE_DEPTH}.
   */
  pathIndices: number[];
  /** The Merkle root — must match the public input `root`. */
  root: bigint;
  /** The 0-indexed position of the leaf in the padded leaf array. */
  leafIndex: number;
}

// ---------------------------------------------------------------------------
// buildMerkleTree
// ---------------------------------------------------------------------------

/**
 * Build a depth-{@link MERKLE_DEPTH} Poseidon Merkle tree from `leaves`.
 *
 * If `leaves.length` is less than `2^MERKLE_DEPTH`, the remaining positions
 * are filled with {@link MERKLE_ZERO_LEAF} (bigint 0) before hashing. Each
 * internal node is `Poseidon(leftChild, rightChild)`.
 *
 * @param leaves - Field elements to commit to. Must be non-empty and no
 *   more than `2^MERKLE_DEPTH` (= 1,048,576) entries.
 * @returns A fully-computed {@link MerkleTree}.
 *
 * @example
 * ```ts
 * const secrets = [1n, 2n, 3n, 4n];
 * const tree = buildMerkleTree(secrets);
 * console.log("root:", tree.root.toString());
 * ```
 */
export function buildMerkleTree(leaves: bigint[]): MerkleTree {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new SorobanZkError(
      "buildMerkleTree: leaves must be a non-empty array",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  if (leaves.length > MERKLE_MAX_LEAVES) {
    throw new SorobanZkError(
      `buildMerkleTree: too many leaves (${leaves.length} > ${MERKLE_MAX_LEAVES})`,
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  for (let i = 0; i < leaves.length; i++) {
    if (typeof leaves[i] !== "bigint") {
      throw new SorobanZkError(
        `buildMerkleTree: leaves[${i}] must be a bigint`,
        SorobanZkErrorCode.INVALID_PUBLIC_INPUT
      );
    }
  }

  // Pad leaf array to exactly 2^MERKLE_DEPTH entries.
  const padded: bigint[] = Array.from({ length: MERKLE_MAX_LEAVES }, (_, i) =>
    i < leaves.length ? leaves[i] : MERKLE_ZERO_LEAF
  );

  const layers: bigint[][] = [padded];

  let current: bigint[] = padded;
  for (let d = 0; d < MERKLE_DEPTH; d++) {
    const next: bigint[] = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(poseidon([current[i], current[i + 1]]));
    }
    layers.push(next);
    current = next;
  }

  return {
    root: current[0],
    leaves: padded,
    layers,
  };
}

// ---------------------------------------------------------------------------
// computeMerkleRoot
// ---------------------------------------------------------------------------

/**
 * Convenience wrapper: build a tree and return only its root.
 *
 * Use this when you only need to commit to a set of values and don't
 * need inclusion proofs. For generating proofs, use
 * {@link buildMerkleTree} + {@link buildMerkleProof}.
 *
 * @example
 * ```ts
 * const root = computeMerkleRoot([secret1, secret2, secret3]);
 * // Pass root as the circuit's `root` public input.
 * ```
 */
export function computeMerkleRoot(leaves: bigint[]): bigint {
  return buildMerkleTree(leaves).root;
}

// ---------------------------------------------------------------------------
// buildMerkleProof
// ---------------------------------------------------------------------------

/**
 * Generate an inclusion proof for `leaves[leafIndex]` in `tree`.
 *
 * The returned {@link MerkleProof} contains the exact fields the
 * `merkle_inclusion` circuit expects:
 * - `leaf` → private input
 * - `pathElements[0..MERKLE_DEPTH-1]` → private input
 * - `pathIndices[0..MERKLE_DEPTH-1]` → private input
 * - `root` → public input
 *
 * @param tree - A tree built with {@link buildMerkleTree}.
 * @param leafIndex - 0-indexed position of the leaf to prove.
 *
 * @example
 * ```ts
 * const tree = buildMerkleTree([commitment1, commitment2, commitment3]);
 * const proof = buildMerkleProof(tree, 1); // prove commitment2 is in tree
 *
 * // Feed to snarkjs:
 * const { proof: groth16Proof, publicSignals } = await snarkjs.groth16.fullProve(
 *   {
 *     leaf: proof.leaf.toString(),
 *     pathElements: proof.pathElements.map(e => e.toString()),
 *     pathIndices: proof.pathIndices,
 *     root: proof.root.toString(),
 *   },
 *   wasmPath,
 *   zkeyPath,
 * );
 * ```
 */
export function buildMerkleProof(tree: MerkleTree, leafIndex: number): MerkleProof {
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= MERKLE_MAX_LEAVES) {
    throw new SorobanZkError(
      `buildMerkleProof: leafIndex must be an integer in [0, ${MERKLE_MAX_LEAVES - 1}]`,
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];

  let index = leafIndex;
  for (let d = 0; d < MERKLE_DEPTH; d++) {
    const layer = tree.layers[d];
    const isRight = index % 2; // 1 if this node is the right child
    const siblingIndex = isRight ? index - 1 : index + 1;
    pathElements.push(layer[siblingIndex]);
    pathIndices.push(isRight);
    index = Math.floor(index / 2);
  }

  return {
    leaf: tree.leaves[leafIndex],
    pathElements,
    pathIndices,
    root: tree.root,
    leafIndex,
  };
}

// ---------------------------------------------------------------------------
// merkleProofToCircuitInputs
// ---------------------------------------------------------------------------

/**
 * Convert a {@link MerkleProof} to the plain-string circuit input object
 * that snarkjs's `groth16.fullProve` accepts — saves callers from manually
 * mapping bigints to strings.
 *
 * @example
 * ```ts
 * const inputs = merkleProofToCircuitInputs(proof);
 * const result = await snarkjs.groth16.fullProve(inputs, wasmPath, zkeyPath);
 * ```
 */
export function merkleProofToCircuitInputs(proof: MerkleProof): Record<string, unknown> {
  return {
    leaf: proof.leaf.toString(),
    pathElements: proof.pathElements.map((e) => e.toString()),
    pathIndices: proof.pathIndices,
    root: proof.root.toString(),
  };
}
