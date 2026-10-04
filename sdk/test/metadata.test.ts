import assert from "node:assert/strict";
import test from "node:test";

import {
  createProofMetadata,
  estimateExpiryDate,
  isProofExpired,
  LEDGER_CLOSE_TIME_SECONDS,
  ledgersUntilExpiry,
  recommendExpiryLedger,
} from "../src/metadata";
import { SorobanZkError, SorobanZkErrorCode } from "../src/types";

// ---------------------------------------------------------------------------
// createProofMetadata
// ---------------------------------------------------------------------------

test("createProofMetadata returns correct fields for a minimal input", () => {
  const meta = createProofMetadata({ circuit: "poseidon_preimage" });

  assert.equal(meta.circuit, "poseidon_preimage");
  assert.equal(meta.circuitId, undefined);
  assert.equal(meta.expiryLedger, undefined);
  assert.equal(meta.estimatedExpiryAt, undefined);
  assert.equal(typeof meta.generatedAt, "string");
});

test("createProofMetadata trims circuit name whitespace", () => {
  const meta = createProofMetadata({ circuit: "  range_proof  " });
  assert.equal(meta.circuit, "range_proof");
});

test("createProofMetadata stores circuitId and expiryLedger", () => {
  const meta = createProofMetadata({
    circuit: "range_proof",
    circuitId: 2,
    expiryLedger: 5000,
    currentLedger: 4000,
  });

  assert.equal(meta.circuitId, 2);
  assert.equal(meta.expiryLedger, 5000);
  assert.equal(typeof meta.estimatedExpiryAt, "string");
});

test("createProofMetadata uses provided generatedAt override", () => {
  const ts = "2026-01-01T00:00:00.000Z";
  const meta = createProofMetadata({ circuit: "poseidon_preimage", generatedAt: ts });
  assert.equal(meta.generatedAt, ts);
});

test("createProofMetadata stores tags", () => {
  const meta = createProofMetadata({
    circuit: "merkle_inclusion",
    tags: ["testnet", "v2"],
  });
  assert.deepEqual(meta.tags, ["testnet", "v2"]);
});

test("createProofMetadata throws for empty circuit string", () => {
  assert.throws(
    () => createProofMetadata({ circuit: "   " }),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});

test("createProofMetadata throws for negative circuitId", () => {
  assert.throws(
    () => createProofMetadata({ circuit: "poseidon_preimage", circuitId: -1 }),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});

test("createProofMetadata throws for expiryLedger exceeding u32 max", () => {
  assert.throws(
    () =>
      createProofMetadata({
        circuit: "poseidon_preimage",
        expiryLedger: 0x1_0000_0000,
      }),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});

// ---------------------------------------------------------------------------
// estimateExpiryDate
// ---------------------------------------------------------------------------

test("estimateExpiryDate returns future date when expiryLedger > currentLedger", () => {
  const now = new Date("2026-01-01T00:00:00.000Z");
  const result = estimateExpiryDate(1100, 1000, now);
  // 100 ledgers × 5 s = 500 s in the future
  assert.equal(result.getTime(), now.getTime() + 100 * LEDGER_CLOSE_TIME_SECONDS * 1000);
});

test("estimateExpiryDate returns past date when expiryLedger < currentLedger", () => {
  const now = new Date("2026-01-01T00:00:00.000Z");
  const result = estimateExpiryDate(900, 1000, now);
  assert.ok(result < now);
});

test("estimateExpiryDate returns now when expiryLedger equals currentLedger", () => {
  const now = new Date("2026-01-01T00:00:00.000Z");
  const result = estimateExpiryDate(1000, 1000, now);
  assert.equal(result.getTime(), now.getTime());
});

// ---------------------------------------------------------------------------
// isProofExpired
// ---------------------------------------------------------------------------

test("isProofExpired returns false when no expiryLedger is set", () => {
  const meta = createProofMetadata({ circuit: "poseidon_preimage" });
  assert.equal(isProofExpired(meta, 9_999_999), false);
});

test("isProofExpired returns false when currentLedger <= expiryLedger", () => {
  const meta = createProofMetadata({
    circuit: "poseidon_preimage",
    expiryLedger: 1000,
  });
  assert.equal(isProofExpired(meta, 1000), false);
  assert.equal(isProofExpired(meta, 999), false);
});

test("isProofExpired returns true when currentLedger > expiryLedger", () => {
  const meta = createProofMetadata({
    circuit: "poseidon_preimage",
    expiryLedger: 1000,
  });
  assert.equal(isProofExpired(meta, 1001), true);
});

// ---------------------------------------------------------------------------
// ledgersUntilExpiry
// ---------------------------------------------------------------------------

test("ledgersUntilExpiry returns Infinity when no expiryLedger", () => {
  const meta = createProofMetadata({ circuit: "poseidon_preimage" });
  assert.equal(ledgersUntilExpiry(meta, 0), Infinity);
});

test("ledgersUntilExpiry returns correct count before expiry", () => {
  const meta = createProofMetadata({
    circuit: "poseidon_preimage",
    expiryLedger: 1000,
  });
  assert.equal(ledgersUntilExpiry(meta, 800), 200);
});

test("ledgersUntilExpiry returns 0 when already expired", () => {
  const meta = createProofMetadata({
    circuit: "poseidon_preimage",
    expiryLedger: 1000,
  });
  assert.equal(ledgersUntilExpiry(meta, 1500), 0);
});

// ---------------------------------------------------------------------------
// recommendExpiryLedger
// ---------------------------------------------------------------------------

test("recommendExpiryLedger adds correct number of ledgers for ttl", () => {
  // 600 s / 5 s per ledger = 120 ledgers
  assert.equal(recommendExpiryLedger(1000, 600), 1120);
});

test("recommendExpiryLedger rounds up fractional ledger counts", () => {
  // 11 s / 5 s = 2.2 → ceil = 3 ledgers
  assert.equal(recommendExpiryLedger(1000, 11), 1003);
});

test("recommendExpiryLedger clamps to u32 max", () => {
  assert.equal(recommendExpiryLedger(0xffff_fffe, 600), 0xffff_ffff);
});

test("recommendExpiryLedger throws for negative currentLedger", () => {
  assert.throws(
    () => recommendExpiryLedger(-1, 600),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});

test("recommendExpiryLedger throws for zero ttlSeconds", () => {
  assert.throws(
    () => recommendExpiryLedger(1000, 0),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});

test("recommendExpiryLedger accepts a custom closeTimeSeconds", () => {
  // 600 s / 10 s per ledger = 60 ledgers
  assert.equal(recommendExpiryLedger(1000, 600, 10), 1060);
});
