#![no_std]

use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype,
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine, BN254_G1_SERIALIZED_SIZE, BN254_G2_SERIALIZED_SIZE},
    vec, Address, Bytes, BytesN, Env, TryFromVal, Vec,
};

const PROOF_A_LEN: usize = BN254_G1_SERIALIZED_SIZE;
const PROOF_B_LEN: usize = BN254_G2_SERIALIZED_SIZE;

#[contracttype]
#[derive(Clone)]
pub struct VerifyingKey {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>,
}

#[contracttype]
enum DataKey {
    Admin,
    PendingAdmin,
    Circuit(u32),
    CircuitActive(u32),
    Nullifier(BytesN<32>),
}

/// Emitted on every `verify_proof` call, regardless of outcome.
#[contractevent(topics = ["zk", "verify"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    pub success: bool,
    /// sha256 of the concatenated public inputs, in call order.
    pub inputs_hash: BytesN<32>,
}

/// One entry in a `verify_batch` call — a circuit ID plus the same fields
/// `verify_proof(id, ...)` takes. Batching across different circuit IDs in
/// one call is the main value of batching on the registry, since it's the
/// multi-circuit contract.
#[contracttype]
#[derive(Clone)]
pub struct BatchItem {
    pub id: u32,
    pub proof_a: Bytes,
    pub proof_b: Bytes,
    pub proof_c: Bytes,
    pub public_inputs: Vec<BytesN<32>>,
}

#[contract]
pub struct RegistryContract;

#[contractimpl]
impl RegistryContract {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("registry is not initialized")
    }

    /// Propose `new_admin` as the next admin. Requires the *current* admin's
    /// auth. Does not take effect until `new_admin` calls `accept_admin`.
    pub fn propose_admin(env: Env, new_admin: Address) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("registry is not initialized");
        admin.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
    }

    /// The address currently proposed via `propose_admin`, if any.
    pub fn pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }

    /// Promote the pending admin to admin. Requires the *pending* admin's
    /// own auth — the current admin cannot force this through.
    pub fn accept_admin(env: Env) {
        let pending: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .expect("no pending admin");
        pending.require_auth();

        env.storage().instance().set(&DataKey::Admin, &pending);
        env.storage().instance().remove(&DataKey::PendingAdmin);
    }

    /// Replace this contract's executable with `new_wasm_hash`. Requires the
    /// current admin's auth. The wasm must already be uploaded (see
    /// `env.deployer().upload_contract_wasm`) before this call.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("registry is not initialized");
        admin.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    pub fn register_circuit(env: Env, id: u32, vk: VerifyingKey) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("registry is not initialized");
        admin.require_auth();

        env.storage().persistent().set(&DataKey::Circuit(id), &vk);
        env.storage()
            .persistent()
            .set(&DataKey::CircuitActive(id), &true);
    }

    pub fn has_circuit(env: Env, id: u32) -> bool {
        env.storage().persistent().has(&DataKey::Circuit(id))
    }

    /// Deactivate a registered circuit so it no longer accepts proofs.
    /// The verifying key is retained and can be re-enabled via
    /// `register_circuit`. Requires admin auth.
    pub fn remove_circuit(env: Env, id: u32) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("registry is not initialized");
        admin.require_auth();

        env.storage()
            .persistent()
            .set(&DataKey::CircuitActive(id), &false);
    }

    /// Whether a registered circuit is currently active (accepts proofs).
    /// Returns `false` for circuits that were never registered or have been
    /// removed via `remove_circuit`.
    pub fn is_circuit_active(env: Env, id: u32) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::CircuitActive(id))
            .unwrap_or(false)
    }

    /// Whether a proof nullifier has already been consumed. The nullifier
    /// is the sha256 of the concatenated public inputs, matching the
    /// `inputs_hash` field published in `VerificationResult` events.
    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier))
    }

    pub fn verify_proof(
        env: Env,
        id: u32,
        proof_a: Bytes,
        proof_b: Bytes,
        proof_c: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        let inputs_hash = compute_inputs_hash(&env, &public_inputs);

        // Reject proof if the circuit has been deactivated.
        let circuit_active: bool = env
            .storage()
            .persistent()
            .get(&DataKey::CircuitActive(id))
            .unwrap_or(false);
        if !circuit_active {
            VerificationResult {
                success: false,
                inputs_hash,
            }
            .publish(&env);
            return false;
        }

        // Replay protection: reject if this exact set of public inputs has
        // already been verified successfully for this circuit. The nullifier
        // is scoped to (circuit_id, inputs_hash) so the same inputs can be
        // used with different circuits without collision.
        let nullifier_key = compute_nullifier(&env, id, &inputs_hash);
        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier_key.clone()))
        {
            VerificationResult {
                success: false,
                inputs_hash,
            }
            .publish(&env);
            return false;
        }

        let success = run_verification(&env, id, &proof_a, &proof_b, &proof_c, &public_inputs);

        if success {
            // Burn the nullifier so this (circuit, inputs) pair cannot be
            // replayed. Persistent storage ensures it survives ledger archival.
            env.storage()
                .persistent()
                .set(&DataKey::Nullifier(nullifier_key), &true);
        }

        VerificationResult {
            success,
            inputs_hash,
        }
        .publish(&env);

        success
    }

    /// Verify a batch of (circuit_id, proof) pairs in a single call, in
    /// order. Each entry is independent — a bad, unknown-circuit, deactivated,
    /// or replayed entry just becomes `false` in the returned vec and doesn't
    /// affect the others. One `verification_result` event is published per
    /// entry.
    pub fn verify_batch(env: Env, batch: Vec<BatchItem>) -> Vec<bool> {
        let mut results = Vec::new(&env);
        for item in batch.iter() {
            let inputs_hash = compute_inputs_hash(&env, &item.public_inputs);

            // Check circuit is active.
            let circuit_active: bool = env
                .storage()
                .persistent()
                .get(&DataKey::CircuitActive(item.id))
                .unwrap_or(false);
            if !circuit_active {
                VerificationResult {
                    success: false,
                    inputs_hash,
                }
                .publish(&env);
                results.push_back(false);
                continue;
            }

            // Replay protection.
            let nullifier_key = compute_nullifier(&env, item.id, &inputs_hash);
            if env
                .storage()
                .persistent()
                .has(&DataKey::Nullifier(nullifier_key.clone()))
            {
                VerificationResult {
                    success: false,
                    inputs_hash,
                }
                .publish(&env);
                results.push_back(false);
                continue;
            }

            let success = run_verification(
                &env,
                item.id,
                &item.proof_a,
                &item.proof_b,
                &item.proof_c,
                &item.public_inputs,
            );

            if success {
                env.storage()
                    .persistent()
                    .set(&DataKey::Nullifier(nullifier_key), &true);
            }

            VerificationResult {
                success,
                inputs_hash,
            }
            .publish(&env);

            results.push_back(success);
        }

        results
    }
}

fn run_verification(
    env: &Env,
    id: u32,
    proof_a: &Bytes,
    proof_b: &Bytes,
    proof_c: &Bytes,
    public_inputs: &Vec<BytesN<32>>,
) -> bool {
    let vk: VerifyingKey = match env.storage().persistent().get(&DataKey::Circuit(id)) {
        Some(vk) => vk,
        None => return false,
    };

    if public_inputs.len() + 1 != vk.ic.len() {
        return false;
    }

    let proof_a = read_g1(env, proof_a, "proof_a");
    let proof_b = read_g2(env, proof_b, "proof_b");
    let proof_c = read_g1(env, proof_c, "proof_c");

    let vk_alpha = Bn254G1Affine::from_bytes(vk.alpha);
    let vk_beta = Bn254G2Affine::from_bytes(vk.beta);
    let vk_gamma = Bn254G2Affine::from_bytes(vk.gamma);
    let vk_delta = Bn254G2Affine::from_bytes(vk.delta);

    let mut vk_x = Bn254G1Affine::from_bytes(vk.ic.get(0).unwrap());
    for i in 0..public_inputs.len() {
        let input = Bn254Fr::from_bytes(public_inputs.get(i).unwrap());
        let ic = Bn254G1Affine::from_bytes(vk.ic.get(i + 1).unwrap());
        vk_x = vk_x + (ic * input);
    }

    env.crypto().bn254().pairing_check(
        vec![env, proof_a, -vk_alpha, -vk_x, -proof_c],
        vec![env, proof_b, vk_beta, vk_gamma, vk_delta],
    )
}

fn compute_inputs_hash(env: &Env, public_inputs: &Vec<BytesN<32>>) -> BytesN<32> {
    let mut bytes = Bytes::new(env);
    for input in public_inputs.iter() {
        bytes.append(&Bytes::from(&input));
    }
    env.crypto().sha256(&bytes).to_bytes()
}

/// Compute a per-circuit nullifier: sha256(circuit_id_be || inputs_hash).
/// Scoping to circuit_id prevents cross-circuit nullifier collisions when
/// two different circuits share the same public input value.
fn compute_nullifier(env: &Env, circuit_id: u32, inputs_hash: &BytesN<32>) -> BytesN<32> {
    let mut bytes = Bytes::new(env);
    bytes.append(&Bytes::from_array(env, &circuit_id.to_be_bytes()));
    bytes.append(&Bytes::from(inputs_hash));
    env.crypto().sha256(&bytes).to_bytes()
}

fn read_g1(env: &Env, bytes: &Bytes, label: &str) -> Bn254G1Affine {
    assert_eq!(bytes.len(), PROOF_A_LEN as u32, "{label} must be 64 bytes");
    let bytesn = BytesN::<PROOF_A_LEN>::try_from_val(env, bytes.as_val())
        .expect("proof bytes must be convertible to BytesN<64>");
    Bn254G1Affine::from_bytes(bytesn)
}

fn read_g2(env: &Env, bytes: &Bytes, label: &str) -> Bn254G2Affine {
    assert_eq!(bytes.len(), PROOF_B_LEN as u32, "{label} must be 128 bytes");
    let bytesn = BytesN::<PROOF_B_LEN>::try_from_val(env, bytes.as_val())
        .expect("proof bytes must be convertible to BytesN<128>");
    Bn254G2Affine::from_bytes(bytesn)
}

#[cfg(test)]
mod tests;
