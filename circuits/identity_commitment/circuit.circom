pragma circom 2.1.9;

// identity_commitment.circom
//
// Proves knowledge of a `secret` whose *double* Poseidon hash equals a
// public `commitment2` — i.e. Poseidon(Poseidon(secret)) == commitment2.
//
// This is useful for anonymous-identity schemes where a first-level
// commitment is revealed at registration time (Poseidon(secret) = inner)
// but the on-chain anchor is the second-level hash so the inner commitment
// stays private and the secret is never exposed.
//
// Inputs
//   private: secret         — the raw secret value
//   public:  inner          — Poseidon(secret); the intermediate commitment.
//                             Made public so a verifier can confirm the inner
//                             commitment without learning the secret.
//   public:  commitment2    — Poseidon(Poseidon(secret)); the final on-chain
//                             anchor.
//
// Circuit ID: 5 (see docs/multi-circuit.md for the full circuit ID table)

include "circomlib/circuits/poseidon.circom";

template IdentityCommitment() {
    // ---- signals -----------------------------------------------------------
    signal input secret;
    signal input inner;       // public: first-level hash Poseidon(secret)
    signal input commitment2; // public: second-level hash Poseidon(inner)

    // ---- first-level hash: inner = Poseidon(secret) ------------------------
    component h1 = Poseidon(1);
    h1.inputs[0] <== secret;
    inner === h1.out;

    // ---- second-level hash: commitment2 = Poseidon(inner) ------------------
    component h2 = Poseidon(1);
    h2.inputs[0] <== h1.out;
    commitment2 === h2.out;
}

component main {public [inner, commitment2]} = IdentityCommitment();
