import { createHash } from "node:crypto";
import fs from "node:fs";

import { bundleDigest, createBundle, verifyBundleIntegrity } from "./bundle.js";
import { buildMerkleTree, computeMerkleRoot } from "./merkle.js";
import { poseidon } from "./poseidon.js";
import { formatProof, formatVerifyingKey } from "./proof.js";
import { SnarkjsProof, SorobanZkError, SorobanZkErrorCode, VerificationKey } from "./types.js";

// The live Testnet deployment documented in docs/architecture.md and
// docs/multi-circuit.md — used as format-vk's default so the generated
// command is ready to run as-is for the common case.
const REGISTRY_CONTRACT_ID = "CDTPNARKKZCZ36PL4BNKBXZTT2BLVR373S2K5NCFAOKCPPY62ESRHSXH";

interface InspectableBundle {
  proof: SnarkjsProof;
  publicSignals: string[];
  circuit: string;
  generatedAt: string;
  networkPassphrase: string;
  digest?: string;
}

const USAGE = [
  "zksoroban <command> [options]",
  "",
  "Commands:",
  "  prove          --secret <decimal>                     compute Poseidon commitment",
  "  verify         --proof <file> --public <file>         encode to Soroban calldata",
  "  inspect        --bundle <file>                        print ProofBundle metadata",
  "  estimate-fee   --proof <file> --public <file>         deterministic fee estimate",
  "  format-vk      --vk <file> --id <u32> [--registry-id <id>]  encode VK for register_circuit",
  "  decode-bundle  --bundle <file>                        decode and integrity-check a ProofBundle",
  "  check-nullifier --proof <file> --public <file> --circuit-id <u32>  compute the registry nullifier hash",
  "  merkle-root    --leaves <n1,n2,...>                   compute Poseidon Merkle root from a list of field elements"
].join("\n");

function getFlag(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1 || index === args.length - 1) {
    return undefined;
  }

  return args[index + 1];
}

function requireFlag(args: string[], name: string): string {
  const value = getFlag(args, name);
  if (value === undefined) {
    throw new SorobanZkError(`Missing required flag: ${name}`, SorobanZkErrorCode.INVALID_PROOF_FORMAT);
  }

  return value;
}

function readJson<T>(path: string): T {
  return JSON.parse(fs.readFileSync(path, "utf8")) as T;
}

function formatList(values: string[]): string[] {
  return values.map((value, index) => `  [${index}] ${value}`);
}

function commandProve(args: string[]): string[] {
  const secret = BigInt(requireFlag(args, "--secret"));
  const commitment = poseidon([secret]);

  return [
    "command: prove",
    "circuit: poseidon_preimage",
    `secret: ${secret.toString()}`,
    `commitment: ${commitment.toString()}`,
    "circuit input:",
    `  secret: ${secret.toString()}`,
    `  commitment: ${commitment.toString()}`
  ];
}

function commandVerify(args: string[]): string[] {
  const proof = readJson<SnarkjsProof>(requireFlag(args, "--proof"));
  const publicSignals = readJson<string[]>(requireFlag(args, "--public"));
  const calldata = formatProof(proof, publicSignals);

  return [
    "command: verify",
    "calldata encoding: ok",
    `proofA bytes: ${calldata.proofA.length}`,
    `proofB bytes: ${calldata.proofB.length}`,
    `proofC bytes: ${calldata.proofC.length}`,
    `public inputs: ${calldata.publicInputs.length}`
  ];
}

function commandInspect(args: string[]): string[] {
  const bundle = readJson<InspectableBundle>(requireFlag(args, "--bundle"));
  const calldata = formatProof(bundle.proof, bundle.publicSignals);

  return [
    "command: inspect",
    `circuit: ${bundle.circuit}`,
    `generatedAt: ${bundle.generatedAt}`,
    `networkPassphrase: ${bundle.networkPassphrase}`,
    `proof protocol: ${bundle.proof.protocol}`,
    "public signals:",
    ...formatList(bundle.publicSignals),
    `calldata bytes: ${calldata.proofA.length + calldata.proofB.length + calldata.proofC.length}`
  ];
}

function commandEstimateFee(args: string[]): string[] {
  const proof = readJson<SnarkjsProof>(requireFlag(args, "--proof"));
  const publicSignals = readJson<string[]>(requireFlag(args, "--public"));
  const calldata = formatProof(proof, publicSignals);

  const proofBytes = calldata.proofA.length + calldata.proofB.length + calldata.proofC.length;
  const publicBytes = calldata.publicInputs.reduce((total, item) => total + item.length, 0);
  const totalBytes = proofBytes + publicBytes;
  const estimatedFee = 100 + totalBytes * 7;

  return [
    "command: estimate-fee",
    `proof bytes: ${proofBytes}`,
    `public input bytes: ${publicBytes}`,
    `total bytes: ${totalBytes}`,
    `estimated fee (stroops): ${estimatedFee}`
  ];
}

function commandFormatVk(args: string[]): string[] {
  const id = requireFlag(args, "--id");
  const vk = readJson<VerificationKey>(requireFlag(args, "--vk"));
  const registryId = getFlag(args, "--registry-id") ?? REGISTRY_CONTRACT_ID;

  const { alpha, beta, gamma, delta, ic } = formatVerifyingKey(vk);
  const vkJson = JSON.stringify({
    alpha: alpha.toString("hex"),
    beta: beta.toString("hex"),
    gamma: gamma.toString("hex"),
    delta: delta.toString("hex"),
    ic: ic.map((point) => point.toString("hex"))
  });

  return [
    "command: format-vk",
    `circuit id: ${id}`,
    `registry: ${registryId}`,
    `alpha bytes: ${alpha.length}`,
    `beta bytes: ${beta.length}`,
    `gamma bytes: ${gamma.length}`,
    `delta bytes: ${delta.length}`,
    `ic points: ${ic.length}`,
    "",
    "stellar contract invoke \\",
    `  --id ${registryId} \\`,
    "  --network testnet \\",
    "  --source-account <registry-admin> \\",
    `  -- register_circuit --id ${id} --vk '${vkJson}'`
  ];
}

// ---------------------------------------------------------------------------
// decode-bundle — decode and integrity-check a ProofBundle file
// ---------------------------------------------------------------------------

function commandDecodeBundle(args: string[]): string[] {
  const bundlePath = requireFlag(args, "--bundle");
  const raw = readJson<InspectableBundle>(bundlePath);

  // Re-construct as a proper bundle to run integrity checks
  const bundle = createBundle({
    proof: raw.proof,
    publicSignals: raw.publicSignals,
    circuit: raw.circuit,
    networkPassphrase: raw.networkPassphrase,
    generatedAt: raw.generatedAt
  });

  const integrity = verifyBundleIntegrity(raw.digest ? { ...bundle, digest: raw.digest } : bundle);

  const lines: string[] = [
    "command: decode-bundle",
    `file: ${bundlePath}`,
    "",
    `circuit:           ${raw.circuit}`,
    `generatedAt:       ${raw.generatedAt}`,
    `networkPassphrase: ${raw.networkPassphrase}`,
    `proof protocol:    ${raw.proof.protocol}`,
    `public signals:    ${raw.publicSignals.length}`,
    ...formatList(raw.publicSignals),
    "",
    `calldata encoding: ${integrity.valid ? "ok" : "FAIL"}`,
  ];

  if (!integrity.valid && integrity.reason) {
    lines.push(`integrity error:   ${integrity.reason}`);
  }

  if (raw.digest) {
    lines.push(`stored digest:     ${raw.digest.slice(0, 16)}…`);
    lines.push(`digest valid:      ${integrity.valid ? "yes" : "no"}`);
  } else {
    // Compute and display digest even if not already stored
    const computed = bundleDigest(bundle);
    lines.push(`digest (computed): ${computed.slice(0, 16)}… (add "digest" field to sign bundle)`);
  }

  return lines;
}

// ---------------------------------------------------------------------------
// check-nullifier — compute the registry nullifier for a proof+circuit pair
// ---------------------------------------------------------------------------
//
// The registry's replay-protection nullifier is:
//   sha256( circuit_id_be_4bytes || sha256( concat(public_inputs_bytes) ) )
//
// This mirrors contracts/registry/src/lib.rs's `compute_nullifier` function
// exactly, so callers can check whether a proof has already been consumed
// before submitting it.

function commandCheckNullifier(args: string[]): string[] {
  const proof = readJson<SnarkjsProof>(requireFlag(args, "--proof"));
  const publicSignals = readJson<string[]>(requireFlag(args, "--public"));
  const circuitId = Number(requireFlag(args, "--circuit-id"));

  if (!Number.isInteger(circuitId) || circuitId < 0 || circuitId > 0xffffffff) {
    throw new SorobanZkError(
      "--circuit-id must be a u32 integer",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  const calldata = formatProof(proof, publicSignals);

  // Step 1: inputs_hash = sha256(concat(public_inputs))
  const inputsConcat = Buffer.concat(calldata.publicInputs);
  const inputsHash = createHash("sha256").update(inputsConcat).digest();

  // Step 2: nullifier = sha256(circuit_id_be || inputs_hash)
  const circuitIdBe = Buffer.alloc(4);
  circuitIdBe.writeUInt32BE(circuitId, 0);
  const nullifier = createHash("sha256")
    .update(Buffer.concat([circuitIdBe, inputsHash]))
    .digest("hex");

  return [
    "command: check-nullifier",
    `circuit id:   ${circuitId}`,
    `public inputs: ${publicSignals.length}`,
    ...formatList(publicSignals),
    "",
    `inputs_hash:  ${inputsHash.toString("hex")}`,
    `nullifier:    ${nullifier}`,
    "",
    "To check whether this proof has already been consumed on-chain, query:",
    `  stellar contract invoke --id <registry-contract-id> \\`,
    `    -- is_nullifier_used --nullifier '${nullifier}'`
  ];
}

// ---------------------------------------------------------------------------
// merkle-root — compute a Poseidon Merkle root from a comma-separated list
// ---------------------------------------------------------------------------

function commandMerkleRoot(args: string[]): string[] {
  const leavesRaw = requireFlag(args, "--leaves");
  const leafStrings = leavesRaw.split(",").map((s) => s.trim()).filter(Boolean);

  if (leafStrings.length === 0) {
    throw new SorobanZkError(
      "--leaves must be a non-empty comma-separated list of field elements",
      SorobanZkErrorCode.INVALID_PUBLIC_INPUT
    );
  }

  const leaves = leafStrings.map((s, i) => {
    try {
      return BigInt(s);
    } catch {
      throw new SorobanZkError(
        `leaves[${i}] "${s}" is not a valid integer`,
        SorobanZkErrorCode.INVALID_PUBLIC_INPUT
      );
    }
  });

  const tree = buildMerkleTree(leaves);
  const root = computeMerkleRoot(leaves);

  return [
    "command: merkle-root",
    `leaves:  ${leaves.length}`,
    ...formatList(leaves.map((l) => l.toString())),
    "",
    `depth:   ${20}`,
    `root:    ${root.toString()}`,
    "",
    "Pass this root as the `root` public input to the merkle_inclusion circuit."
  ];
}

// ---------------------------------------------------------------------------
// runCli
// ---------------------------------------------------------------------------

export function runCli(argv: string[]): string {
  const [command, ...args] = argv;

  switch (command) {
    case "prove":
      return commandProve(args).join("\n");
    case "verify":
      return commandVerify(args).join("\n");
    case "inspect":
      return commandInspect(args).join("\n");
    case "estimate-fee":
      return commandEstimateFee(args).join("\n");
    case "format-vk":
      return commandFormatVk(args).join("\n");
    case "decode-bundle":
      return commandDecodeBundle(args).join("\n");
    case "check-nullifier":
      return commandCheckNullifier(args).join("\n");
    case "merkle-root":
      return commandMerkleRoot(args).join("\n");
    default:
      return USAGE;
  }
}

if (require.main === module) {
  try {
    process.stdout.write(`${runCli(process.argv.slice(2))}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}
