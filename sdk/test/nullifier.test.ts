import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { formatProof } from "../src/proof";
import {
  computeInputsHash,
  computeNullifier,
  nullifierFromHex,
  nullifierHex,
} from "../src/nullifier";
import { SorobanZkError, SorobanZkErrorCode } from "../src/types";
import { VALID_PUBLIC_SIGNALS, VALID_SNARKJS_PROOF } from "./fixtures";

// Derive a canonical set of encoded public inputs from the shared fixture.
function makePublicInputs(): Buffer[] {
  return formatProof(VALID_SNARKJS_PROOF, VALID_PUBLIC_SIGNALS).publicInputs;
}

// ---------------------------------------------------------------------------
// computeInputsHash
// ---------------------------------------------------------------------------

test("computeInputsHash returns a 32-byte Buffer", () => {
  const hash = computeInputsHash(makePublicInputs());
  assert.ok(Buffer.isBuffer(hash));
  assert.equal(hash.length, 32);
});

test("computeInputsHash is deterministic", () => {
  const a = computeInputsHash(makePublicInputs());
  const b = computeInputsHash(makePublicInputs());
  assert.equal(a.toString("hex"), b.toString("hex"));
});

test("computeInputsHash matches manual sha256 of concatenated inputs", () => {
  const inputs = makePublicInputs();
  const expected = createHash("sha256");
  for (const buf of inputs) expected.update(buf);
  assert.equal(
    computeInputsHash(inputs).toString("hex"),
    expected.digest("hex")
  );
});

test("computeInputsHash changes when an input changes", () => {
  const a = makePublicInputs();
  const b = makePublicInputs();
  b[0][0] ^= 0xff; // flip first byte of first input
  assert.notEqual(
    computeInputsHash(a).toString("hex"),
    computeInputsHash(b).toString("hex")
  );
});

test("computeInputsHash throws for empty array", () => {
  assert.throws(
    () => computeInputsHash([]),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

test("computeInputsHash throws for non-32-byte buffer", () => {
  assert.throws(
    () => computeInputsHash([Buffer.alloc(31)]),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

// ---------------------------------------------------------------------------
// computeNullifier
// ---------------------------------------------------------------------------

test("computeNullifier returns a 32-byte Buffer", () => {
  const n = computeNullifier(1, makePublicInputs());
  assert.ok(Buffer.isBuffer(n));
  assert.equal(n.length, 32);
});

test("computeNullifier is deterministic for same circuitId and inputs", () => {
  const a = computeNullifier(1, makePublicInputs());
  const b = computeNullifier(1, makePublicInputs());
  assert.equal(a.toString("hex"), b.toString("hex"));
});

test("computeNullifier differs across circuit IDs for the same inputs", () => {
  const inputs = makePublicInputs();
  const n1 = computeNullifier(1, inputs);
  const n2 = computeNullifier(2, inputs);
  assert.notEqual(n1.toString("hex"), n2.toString("hex"));
});

test("computeNullifier differs for same circuitId with different inputs", () => {
  const a = makePublicInputs();
  const b = makePublicInputs();
  b[0][0] ^= 0xff;
  assert.notEqual(
    computeNullifier(1, a).toString("hex"),
    computeNullifier(1, b).toString("hex")
  );
});

test("computeNullifier matches hand-rolled formula: sha256(circuitId_be4 || inputsHash)", () => {
  const circuitId = 1;
  const inputs = makePublicInputs();
  const inputsHash = computeInputsHash(inputs);

  const circuitBytes = Buffer.allocUnsafe(4);
  circuitBytes.writeUInt32BE(circuitId, 0);

  const expected = createHash("sha256")
    .update(circuitBytes)
    .update(inputsHash)
    .digest("hex");

  assert.equal(computeNullifier(circuitId, inputs).toString("hex"), expected);
});

test("computeNullifier throws for circuitId > u32 max", () => {
  assert.throws(
    () => computeNullifier(0x1_0000_0000, makePublicInputs()),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

test("computeNullifier throws for negative circuitId", () => {
  assert.throws(
    () => computeNullifier(-1, makePublicInputs()),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

// ---------------------------------------------------------------------------
// nullifierHex / nullifierFromHex
// ---------------------------------------------------------------------------

test("nullifierHex returns a 64-char lowercase hex string", () => {
  const n = computeNullifier(1, makePublicInputs());
  const hex = nullifierHex(n);
  assert.equal(hex.length, 64);
  assert.match(hex, /^[0-9a-f]+$/);
});

test("nullifierFromHex round-trips nullifierHex output", () => {
  const n = computeNullifier(1, makePublicInputs());
  const roundTripped = nullifierFromHex(nullifierHex(n));
  assert.equal(roundTripped.toString("hex"), n.toString("hex"));
});

test("nullifierFromHex accepts 0x-prefixed hex", () => {
  const n = computeNullifier(1, makePublicInputs());
  const hex = "0x" + nullifierHex(n);
  const decoded = nullifierFromHex(hex);
  assert.equal(decoded.toString("hex"), n.toString("hex"));
});

test("nullifierFromHex throws for a too-short string", () => {
  assert.throws(
    () => nullifierFromHex("deadbeef"),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

test("nullifierFromHex throws for a non-hex string", () => {
  assert.throws(
    () => nullifierFromHex("z".repeat(64)),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

test("nullifierHex throws for a non-32-byte buffer", () => {
  assert.throws(
    () => nullifierHex(Buffer.alloc(16)),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});
