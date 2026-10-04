import assert from "node:assert/strict";
import test from "node:test";

import { poseidon } from "../src/poseidon";
import {
  buildIdentityCommitment,
  identityCircuitInputs,
  identityRegistrationPayload,
  parseIdentityPublicSignals,
  verifyIdentityCommitment,
} from "../src/identity";
import { SorobanZkError, SorobanZkErrorCode } from "../src/types";

const SECRET = 0xdeadbeef_cafebaben;

// ---------------------------------------------------------------------------
// buildIdentityCommitment
// ---------------------------------------------------------------------------

test("buildIdentityCommitment inner equals Poseidon(secret)", () => {
  const { inner } = buildIdentityCommitment(SECRET);
  assert.equal(inner, poseidon([SECRET]));
});

test("buildIdentityCommitment outer equals Poseidon(inner)", () => {
  const { inner, outer } = buildIdentityCommitment(SECRET);
  assert.equal(outer, poseidon([inner]));
});

test("buildIdentityCommitment inner and outer are distinct", () => {
  const { inner, outer } = buildIdentityCommitment(SECRET);
  assert.notEqual(inner, outer);
});

test("buildIdentityCommitment is deterministic for the same secret", () => {
  const a = buildIdentityCommitment(SECRET);
  const b = buildIdentityCommitment(SECRET);
  assert.equal(a.inner, b.inner);
  assert.equal(a.outer, b.outer);
});

test("buildIdentityCommitment differs for different secrets", () => {
  const a = buildIdentityCommitment(1n);
  const b = buildIdentityCommitment(2n);
  assert.notEqual(a.inner, b.inner);
  assert.notEqual(a.outer, b.outer);
});

test("buildIdentityCommitment throws for non-bigint secret", () => {
  assert.throws(
    () => buildIdentityCommitment(12345 as unknown as bigint),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

// ---------------------------------------------------------------------------
// identityCircuitInputs
// ---------------------------------------------------------------------------

test("identityCircuitInputs returns an object with secret, inner, commitment2 as strings", () => {
  const inputs = identityCircuitInputs(SECRET);
  assert.equal(typeof inputs.secret, "string");
  assert.equal(typeof inputs.inner, "string");
  assert.equal(typeof inputs.commitment2, "string");
});

test("identityCircuitInputs secret field matches the original secret", () => {
  const inputs = identityCircuitInputs(SECRET);
  assert.equal(BigInt(inputs.secret), SECRET);
});

test("identityCircuitInputs inner equals poseidon([secret]) as string", () => {
  const inputs = identityCircuitInputs(SECRET);
  assert.equal(BigInt(inputs.inner), poseidon([SECRET]));
});

test("identityCircuitInputs commitment2 equals poseidon([inner]) as string", () => {
  const inputs = identityCircuitInputs(SECRET);
  const inner = poseidon([SECRET]);
  assert.equal(BigInt(inputs.commitment2), poseidon([inner]));
});

// ---------------------------------------------------------------------------
// verifyIdentityCommitment
// ---------------------------------------------------------------------------

test("verifyIdentityCommitment returns true for a correctly derived pair", () => {
  const { inner, outer } = buildIdentityCommitment(SECRET);
  assert.equal(verifyIdentityCommitment(inner, outer), true);
});

test("verifyIdentityCommitment returns false for a mismatched pair", () => {
  const { inner } = buildIdentityCommitment(SECRET);
  const { outer: wrongOuter } = buildIdentityCommitment(999n);
  assert.equal(verifyIdentityCommitment(inner, wrongOuter), false);
});

test("verifyIdentityCommitment returns false when inner and outer are swapped", () => {
  const { inner, outer } = buildIdentityCommitment(SECRET);
  assert.equal(verifyIdentityCommitment(outer, inner), false);
});

test("verifyIdentityCommitment throws for non-bigint arguments", () => {
  assert.throws(
    () => verifyIdentityCommitment("foo" as unknown as bigint, 1n),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

// ---------------------------------------------------------------------------
// identityRegistrationPayload
// ---------------------------------------------------------------------------

test("identityRegistrationPayload anchor matches outer commitment as string", () => {
  const { outer } = buildIdentityCommitment(SECRET);
  const payload = identityRegistrationPayload(SECRET);
  assert.equal(BigInt(payload.anchor), outer);
});

test("identityRegistrationPayload innerCommitment matches inner commitment as string", () => {
  const { inner } = buildIdentityCommitment(SECRET);
  const payload = identityRegistrationPayload(SECRET);
  assert.equal(BigInt(payload.innerCommitment), inner);
});

test("identityRegistrationPayload createdAt is a valid ISO-8601 string", () => {
  const payload = identityRegistrationPayload(SECRET);
  assert.ok(!isNaN(new Date(payload.createdAt).getTime()));
});

test("identityRegistrationPayload does not include the secret", () => {
  const payload = identityRegistrationPayload(SECRET) as Record<string, unknown>;
  assert.equal(payload["secret"], undefined);
});

// ---------------------------------------------------------------------------
// parseIdentityPublicSignals
// ---------------------------------------------------------------------------

test("parseIdentityPublicSignals parses inner and outer from a 2-element array", () => {
  const { inner, outer } = buildIdentityCommitment(SECRET);
  const signals = [inner.toString(), outer.toString()];
  const parsed = parseIdentityPublicSignals(signals);
  assert.equal(parsed.inner, inner);
  assert.equal(parsed.outer, outer);
});

test("parseIdentityPublicSignals round-trips identityCircuitInputs inner/commitment2", () => {
  const inputs = identityCircuitInputs(SECRET);
  // snarkjs output order: inner first, then commitment2
  const parsed = parseIdentityPublicSignals([inputs.inner, inputs.commitment2]);
  assert.equal(parsed.inner.toString(), inputs.inner);
  assert.equal(parsed.outer.toString(), inputs.commitment2);
});

test("parseIdentityPublicSignals throws for fewer than 2 signals", () => {
  assert.throws(
    () => parseIdentityPublicSignals(["123"]),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

test("parseIdentityPublicSignals throws for non-array input", () => {
  assert.throws(
    () => parseIdentityPublicSignals(null as unknown as string[]),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});
