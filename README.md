# zkstellar

[![ci](https://github.com/yusufadeagbo/zksoroban/actions/workflows/ci.yml/badge.svg)](https://github.com/yusufadeagbo/zksoroban/actions/workflows/ci.yml)
[![CodeQL](https://github.com/yusufadeagbo/zksoroban/actions/workflows/codeql.yml/badge.svg)](https://github.com/yusufadeagbo/zksoroban/actions/workflows/codeql.yml)

A developer SDK and reference verifier contract for zero-knowledge proofs on Stellar, built on Protocol 25's native BN254 and Poseidon host functions.

Testnet registry contract (targeted by `demo/`):
`CDTPNARKKZCZ36PL4BNKBXZTT2BLVR373S2K5NCFAOKCPPY62ESRHSXH`

## New to ZK proofs?

Follow the step-by-step tutorial: [docs/tutorial-first-proof.md](docs/tutorial-first-proof.md)

It covers prerequisites, Testnet account funding, exact commands, expected output, and a troubleshooting section.

## Quick Start

1. Install prerequisites: Node.js 22+, Rust, Stellar CLI, `make`, and `circom`.
2. Install the workspace dependencies from the repository root:
   `make install`
3. Build the verifier contract and SDK:
   `make build`
4. Run the full local check suite:
   `make test`
5. Run the end-to-end demo:
   `make demo`

The demo verifies against `contracts/registry` via a read-only simulation
call — no funded Testnet account or secret key needed. Accept the
interactive prompts' defaults to run against the deployed registry
directly.

Useful maintenance commands:

- `make lint`: run Rust formatting, clippy, and TypeScript checks.
- `make circuits`: compile and verify the reference Poseidon preimage circuit.
- `make clean`: remove generated Rust, SDK, demo, and circuit build artifacts.

Expected result:
`✓ Proof verified on-chain: true`

## What This Repo Contains

- `contracts/verifier/`: a Soroban verifier contract for a Groth16 proof over BN254, gated by caller auth, per-caller rate limiting, and proof expiry.
- `contracts/registry/`: a multi-circuit verifying-key registry, deployed to Testnet — supports nullifier-based replay protection and per-circuit deactivation via `remove_circuit`. See [docs/architecture.md](docs/architecture.md#verifying-key-registry).
- `sdk/`: a TypeScript SDK for Poseidon hashing, snarkjs proof formatting, on-chain verification, ProofBundle management, Merkle tree utilities, and on-chain event history queries.
- `circuits/`: the reference Poseidon preimage circuit (wired to both contracts above) plus four additional circuits — `merkle_inclusion`, `range_proof`, `threshold_2of3`, and `identity_commitment` — each with trusted-setup artifacts and example inputs.
- `demo/`: an end-to-end script that generates a fresh secret, proves knowledge of its Poseidon commitment, and verifies it on Stellar Testnet.
- `docs/`: architecture notes, ZK primer, proof format specification, security audit checklist, and Poseidon parameter notes.

## Architecture

```text
User secret
   |
   v
Poseidon(secret) -> commitment
   |
   v
circom + snarkjs
generate Groth16 proof
   |
   v
SDK formatProof()
encodes proofA / proofB / proofC / publicInputs
   |
   v
SDK verifyOnChain()
submits Soroban transaction
   |
   v
Verifier contract
reconstructs vk_x and runs BN254 pairing check
   |
   v
bool result on-chain
```

## Reference Flow

The reference circuit exposes one public input, `commitment`, and one private input, `secret`. The prover shows that `Poseidon(secret) == commitment` without revealing `secret`. The contract keeps state to a minimum — an admin address and per-caller rate-limit counters, nothing proof- or nullifier-related — and returns a boolean, which keeps the MVP easy to audit and inexpensive to call. See [docs/security.md](docs/security.md) for exactly what this contract does and does not guarantee.

## Repository Status

- Phase 0: foundation complete
- Phase 1: verifier contract deployed and resource-gated
- Phase 2: SDK complete with Testnet integration tests
- Phase 3: reference circuit, setup artifacts, and demo complete
- Phase 4: documentation and submission polish complete

Known gaps, tracked as open issues rather than left implicit:

- No replay protection on `contracts/verifier` — the single-circuit contract does not use nullifiers (#11). `contracts/registry` now enforces per-proof nullifiers (fixed in this release).
- `merkle_inclusion`, `range_proof`, and `threshold_2of3` circuits are registered with `contracts/registry` in a local test environment, but not yet on the live Testnet deployment — that needs the registry's admin key (#183).

## Testnet Proof

- `contracts/registry` contract address (deployed, targeted by `demo/`, `poseidon_preimage` registered under circuit ID `1`):
  `CDTPNARKKZCZ36PL4BNKBXZTT2BLVR373S2K5NCFAOKCPPY62ESRHSXH`
- Verified directly against the live deployment via `demo/`: a correct proof returns `true`, and a proof paired with the wrong public input returns `false`.
- `contracts/verifier` (the original single-circuit contract) is still live at
  `CBL6MAWJALQP25LYKUUOC34K464XPSF6BLKUW6MXZDEXEDXMQUSP7HNN`, but predates rate-limiting, caller auth, and expiry, and is no longer what `demo/` targets.

## New SDK Features

### ProofBundle utilities (`sdk/src/bundle.ts`)

`createBundle`, `signBundle`, and `verifyBundleIntegrity` make it safe and explicit to package a proof for later submission or storage:

```ts
import { createBundle, signBundle, verifyBundleIntegrity } from "@zksoroban/sdk";

const bundle = createBundle({
  proof,
  publicSignals,
  circuit: "poseidon_preimage",
  networkPassphrase: "Test SDF Network ; September 2015",
});

const signed = signBundle(bundle); // attaches SHA-256 digest
fs.writeFileSync("proof.bundle.json", JSON.stringify(signed, null, 2));

const result = verifyBundleIntegrity(signed); // checks encoding + digest
console.log(result.valid); // true
```

### Merkle tree utilities (`sdk/src/merkle.ts`)

`buildMerkleTree`, `computeMerkleRoot`, `buildMerkleProof`, and `merkleProofToCircuitInputs` build Poseidon Merkle trees matching the `merkle_inclusion` circuit (depth 20):

```ts
import { buildMerkleTree, buildMerkleProof, merkleProofToCircuitInputs } from "@zksoroban/sdk";

const tree = buildMerkleTree([commitment1, commitment2, commitment3]);
const proof = buildMerkleProof(tree, 1); // prove commitment2 is in the tree

// Feed directly to snarkjs:
const inputs = merkleProofToCircuitInputs(proof);
const { proof: groth16Proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasm, zkey);
```

### On-chain event history (`sdk/src/verify.ts`)

`getVerificationHistory` pages through `verification_result` events from any deployed verifier or registry contract:

```ts
import { getVerificationHistory } from "@zksoroban/sdk";

const history = await getVerificationHistory({
  rpcUrl: "https://soroban-testnet.stellar.org",
  contractId: "CBL6MAWJALQP25LYKUUOC34K464XPSF6BLKUW6MXZDEXEDXMQUSP7HNN",
  limit: 20,
  successFilter: true, // only successful verifications
});

for (const entry of history) {
  console.log(entry.ledger, entry.inputsHash, entry.success, entry.caller);
}
```

### New CLI commands

```bash
# Decode and integrity-check a bundle file
node sdk/dist/cjs/cli.js decode-bundle --bundle proof.bundle.json

# Compute the registry nullifier for a proof (to check replay protection)
node sdk/dist/cjs/cli.js check-nullifier \
  --proof circuits/poseidon_preimage/fixtures/proof.json \
  --public circuits/poseidon_preimage/fixtures/public.json \
  --circuit-id 1

# Compute a Poseidon Merkle root from a list of leaves
node sdk/dist/cjs/cli.js merkle-root --leaves 1,2,3,4,5
```

### New circuit: `identity_commitment` (circuit ID 5)

`circuits/identity_commitment/circuit.circom` proves knowledge of a `secret`
whose double Poseidon hash matches a public `commitment2`:
`Poseidon(Poseidon(secret)) == commitment2`. The intermediate hash `inner =
Poseidon(secret)` is also a public input, so a verifier can confirm the
first-level commitment without learning the secret. Useful for
anonymous-identity schemes where the on-chain anchor is a second-level hash.
See [`circuits/identity_commitment/README.md`](circuits/identity_commitment/README.md).

## Notes

- The setup artifacts in `circuits/poseidon_preimage/setup/` are testnet-only and non-production.
- `contracts/verifier` still hardcodes one circuit's verifying key; `contracts/registry` supports multiple, and is deployed, but only `poseidon_preimage` is registered under it so far.
- `contracts/registry` enforces replay protection via per-proof nullifiers. `contracts/verifier` (the original single-circuit contract) does not — see [docs/security.md](docs/security.md) for the full guarantees.

Building an application on top of `zkstellar`? Read
[docs/security-model.md](docs/security-model.md) first — it covers the
full stack's guarantees, trust assumptions, and threat model, including
what this stack explicitly does **not** protect against.

See [docs/zk-primer.md](https://github.com/yusufadeagbo/zksoroban/blob/main/docs/zk-primer.md) and [docs/proof-format.md](https://github.com/yusufadeagbo/zksoroban/blob/main/docs/proof-format.md) for the detailed background and byte-level interoperability spec.
