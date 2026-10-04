import assert from "node:assert/strict";
import test from "node:test";

import { poseidon } from "../src/poseidon";
import {
  domainSeparatedHash,
  poseidonBatch,
  poseidonCommit,
  poseidonCommitDouble,
} from "../src/poseidonUtils";
import { SorobanZkError, SorobanZkErrorCode } from "../src/types";

// ---------------------------------------------------------------------------
// poseidonBatch
// ---------------------------------------------------------------------------

test("poseidonBatch with ≤16 inputs produces the same result as poseidon()", () => {
  const inputs = [1n, 2n, 3n];
  assert.equal(poseidonBatch(inputs), poseidon(inputs));
});

test("poseidonBatch with a single input equals poseidon([input])", () => {
  assert.equal(poseidonBatch([42n]), poseidon([42n]));
});

test("poseidonBatch with exactly 16 inputs delegates to a single poseidon call", () => {
  const inputs = Array.from({ length: 16 }, (_, i) => BigInt(i + 1));
  assert.equal(poseidonBatch(inputs), poseidon(inputs));
});

test("poseidonBatch with 17 inputs does not throw and returns a bigint", () => {
  const inputs = Array.from({ length: 17 }, (_, i) => BigInt(i + 1));
  const result = poseidonBatch(inputs);
  assert.equal(typeof result, "bigint");
});

test("poseidonBatch is deterministic", () => {
  const inputs = [1n, 2n, 3n, 4n, 5n];
  assert.equal(poseidonBatch(inputs), poseidonBatch(inputs));
});

test("poseidonBatch result changes when any input changes", () => {
  const a = poseidonBatch([1n, 2n, 3n]);
  const b = poseidonBatch([1n, 2n, 4n]);
  assert.notEqual(a, b);
});

test("poseidonBatch throws for empty array", () => {
  assert.throws(
    () => poseidonBatch([]),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

test("poseidonBatch throws when an element is not a bigint", () => {
  assert.throws(
    () => poseidonBatch([1n, "2" as unknown as bigint]),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

// ---------------------------------------------------------------------------
// domainSeparatedHash
// ---------------------------------------------------------------------------

test("domainSeparatedHash returns a bigint", () => {
  assert.equal(typeof domainSeparatedHash(1n, [42n]), "bigint");
});

test("different domain tags produce different hashes for the same input", () => {
  const h1 = domainSeparatedHash(1n, [99n]);
  const h2 = domainSeparatedHash(2n, [99n]);
  assert.notEqual(h1, h2);
});

test("domainSeparatedHash is deterministic", () => {
  assert.equal(
    domainSeparatedHash(7n, [1n, 2n, 3n]),
    domainSeparatedHash(7n, [1n, 2n, 3n])
  );
});

test("domainSeparatedHash equals poseidon([tag, ...inputs])", () => {
  const tag = 5n;
  const inputs = [10n, 20n];
  assert.equal(
    domainSeparatedHash(tag, inputs),
    poseidon([tag, ...inputs])
  );
});

test("domainSeparatedHash throws for non-bigint domainTag", () => {
  assert.throws(
    () => domainSeparatedHash("tag" as unknown as bigint, [1n]),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

test("domainSeparatedHash throws when total arity exceeds 16", () => {
  // 1 tag + 16 inputs = 17 total — exceeds MAX_ARITY
  const inputs = Array.from({ length: 16 }, (_, i) => BigInt(i));
  assert.throws(
    () => domainSeparatedHash(1n, inputs),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

test("domainSeparatedHash throws for empty inputs array", () => {
  assert.throws(
    () => domainSeparatedHash(1n, []),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

// ---------------------------------------------------------------------------
// poseidonCommit
// ---------------------------------------------------------------------------

test("poseidonCommit equals poseidon([secret])", () => {
  const secret = 12345n;
  assert.equal(poseidonCommit(secret), poseidon([secret]));
});

test("poseidonCommit is deterministic", () => {
  assert.equal(poseidonCommit(1n), poseidonCommit(1n));
});

test("poseidonCommit throws for non-bigint secret", () => {
  assert.throws(
    () => poseidonCommit("secret" as unknown as bigint),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});

// ---------------------------------------------------------------------------
// poseidonCommitDouble
// ---------------------------------------------------------------------------

test("poseidonCommitDouble inner equals poseidon([secret])", () => {
  const secret = 99n;
  const { inner } = poseidonCommitDouble(secret);
  assert.equal(inner, poseidon([secret]));
});

test("poseidonCommitDouble outer equals poseidon([inner])", () => {
  const secret = 99n;
  const { inner, outer } = poseidonCommitDouble(secret);
  assert.equal(outer, poseidon([inner]));
});

test("poseidonCommitDouble inner and outer are different", () => {
  const { inner, outer } = poseidonCommitDouble(123n);
  assert.notEqual(inner, outer);
});

test("poseidonCommitDouble is deterministic", () => {
  const a = poseidonCommitDouble(777n);
  const b = poseidonCommitDouble(777n);
  assert.equal(a.inner, b.inner);
  assert.equal(a.outer, b.outer);
});

test("poseidonCommitDouble throws for non-bigint secret", () => {
  assert.throws(
    () => poseidonCommitDouble(42 as unknown as bigint),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PUBLIC_INPUT
  );
});
