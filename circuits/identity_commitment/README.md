# identity_commitment circuit

Proves knowledge of a `secret` whose *double* Poseidon hash equals a public
`commitment2` — that is, `Poseidon(Poseidon(secret)) == commitment2`.

## Use case

Anonymous-identity schemes where:

1. A user registers by publishing their **inner commitment**
   `inner = Poseidon(secret)` — this anchors their identity without
   exposing the secret.
2. The on-chain anchor is the **second-level hash**
   `commitment2 = Poseidon(inner)` — so even the inner commitment stays
   private during proof verification.
3. The user later proves they know the original `secret` without revealing
   it, and without reusing the same nullifier as the inner-commitment scheme.

## Public inputs

| Signal | Description |
|---|---|
| `inner` | `Poseidon(secret)` — first-level commitment |
| `commitment2` | `Poseidon(Poseidon(secret))` — second-level on-chain anchor |

## Private inputs

| Signal | Description |
|---|---|
| `secret` | The raw secret value |

## Circuit ID

`5` — see [docs/multi-circuit.md](../../docs/multi-circuit.md) for the full
circuit ID assignment table.

## Computing inputs

Use the SDK's `poseidon` helper:

```ts
import { poseidon } from "@zksoroban/sdk";

const secret = 42n;
const inner = poseidon([secret]);
const commitment2 = poseidon([inner]);

console.log({ secret, inner: inner.toString(), commitment2: commitment2.toString() });
```

Or from the command line after building the SDK:

```bash
node -e "
const { poseidon } = require('./sdk/dist/index.cjs');
const s = 42n;
const i = poseidon([s]);
console.log('inner:', i.toString());
console.log('commitment2:', poseidon([i]).toString());
"
```

## Trusted setup

Follow the same `snarkjs powersoftau` / `groth16 setup` sequence documented
in [circuits/poseidon_preimage/README.md](../poseidon_preimage/README.md).
The resulting `.zkey` and `verification_key.json` go into `setup/`.

## Registering with the registry

Once the setup artifacts are committed, use the SDK's `format-vk` CLI
command to produce the ready-to-run `register_circuit` command:

```bash
node sdk/dist/cjs/cli.js format-vk \
  --vk circuits/identity_commitment/setup/verification_key.json \
  --id 5
```
