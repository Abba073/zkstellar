import assert from "node:assert/strict";
import test from "node:test";

import { createBundle, signBundle } from "../src/bundle";
import {
  bundleFromBase64,
  bundleFromJson,
  bundleToBase64,
  bundleToJson,
  importSignedBundle,
  validateBundleShape,
} from "../src/bundleIO";
import { SorobanZkError, SorobanZkErrorCode } from "../src/types";
import { VALID_PUBLIC_SIGNALS, VALID_SNARKJS_PROOF } from "./fixtures";

const TESTNET = "Test SDF Network ; September 2015";

function makeBundle() {
  return createBundle({
    proof: VALID_SNARKJS_PROOF,
    publicSignals: VALID_PUBLIC_SIGNALS,
    circuit: "poseidon_preimage",
    networkPassphrase: TESTNET,
    generatedAt: "2026-01-01T00:00:00.000Z",
  });
}

// ---------------------------------------------------------------------------
// validateBundleShape
// ---------------------------------------------------------------------------

test("validateBundleShape passes for a well-formed bundle", () => {
  assert.doesNotThrow(() => validateBundleShape(makeBundle()));
});

test("validateBundleShape throws for null", () => {
  assert.throws(
    () => validateBundleShape(null),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});

test("validateBundleShape throws when circuit is missing", () => {
  const bad = { ...makeBundle(), circuit: "" };
  assert.throws(
    () => validateBundleShape(bad),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.message.toLowerCase().includes("circuit")
  );
});

test("validateBundleShape throws when generatedAt is missing", () => {
  const bad = { ...makeBundle(), generatedAt: "" };
  assert.throws(
    () => validateBundleShape(bad),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.message.toLowerCase().includes("generatedat")
  );
});

test("validateBundleShape throws when networkPassphrase is missing", () => {
  const bad = { ...makeBundle(), networkPassphrase: "" };
  assert.throws(
    () => validateBundleShape(bad),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.message.toLowerCase().includes("networkpassphrase")
  );
});

test("validateBundleShape throws when publicSignals is not an array", () => {
  const bad = { ...makeBundle(), publicSignals: "not-an-array" };
  assert.throws(
    () => validateBundleShape(bad),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.message.toLowerCase().includes("publicsignals")
  );
});

test("validateBundleShape throws when proof.protocol is not groth16", () => {
  const bad = {
    ...makeBundle(),
    proof: { ...VALID_SNARKJS_PROOF, protocol: "plonk" },
  };
  assert.throws(
    () => validateBundleShape(bad),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.message.includes("groth16")
  );
});

// ---------------------------------------------------------------------------
// bundleToJson / bundleFromJson
// ---------------------------------------------------------------------------

test("bundleToJson produces valid JSON that round-trips via bundleFromJson", () => {
  const bundle = makeBundle();
  const json = bundleToJson(bundle);
  const parsed = bundleFromJson(json);
  assert.equal(parsed.circuit, bundle.circuit);
  assert.equal(parsed.networkPassphrase, bundle.networkPassphrase);
  assert.deepEqual(parsed.publicSignals, bundle.publicSignals);
});

test("bundleToJson with pretty=false produces compact JSON", () => {
  const json = bundleToJson(makeBundle(), false);
  assert.ok(!json.includes("\n"));
});

test("bundleFromJson throws on invalid JSON", () => {
  assert.throws(
    () => bundleFromJson("not json {{{"),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});

test("bundleFromJson throws on JSON that fails shape validation", () => {
  assert.throws(
    () => bundleFromJson(JSON.stringify({ hello: "world" })),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});

// ---------------------------------------------------------------------------
// bundleToBase64 / bundleFromBase64
// ---------------------------------------------------------------------------

test("bundleToBase64 produces a URL-safe base64 string with no padding", () => {
  const b64 = bundleToBase64(makeBundle());
  assert.ok(typeof b64 === "string");
  assert.ok(!b64.includes("+"));
  assert.ok(!b64.includes("/"));
  assert.ok(!b64.includes("="));
});

test("bundleFromBase64 round-trips bundleToBase64 output", () => {
  const bundle = makeBundle();
  const b64 = bundleToBase64(bundle);
  const parsed = bundleFromBase64(b64);
  assert.equal(parsed.circuit, bundle.circuit);
  assert.deepEqual(parsed.publicSignals, bundle.publicSignals);
});

test("bundleFromBase64 accepts standard base64 padding", () => {
  const b64 = Buffer.from(bundleToJson(makeBundle(), false)).toString("base64");
  const parsed = bundleFromBase64(b64);
  assert.equal(parsed.circuit, "poseidon_preimage");
});

test("bundleFromBase64 throws for invalid base64", () => {
  assert.throws(
    () => bundleFromBase64("not-valid-base64-!!!"),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});

// ---------------------------------------------------------------------------
// importSignedBundle
// ---------------------------------------------------------------------------

test("importSignedBundle accepts a signed bundle object and verifies integrity", () => {
  const signed = signBundle(makeBundle());
  const { bundle, integrityVerified } = importSignedBundle(signed);
  assert.equal(integrityVerified, true);
  assert.equal(bundle.circuit, "poseidon_preimage");
});

test("importSignedBundle auto-signs an unsigned bundle object and returns integrityVerified=false", () => {
  const { bundle, integrityVerified } = importSignedBundle(makeBundle());
  assert.equal(integrityVerified, false);
  assert.equal(typeof bundle.digest, "string");
});

test("importSignedBundle accepts a JSON string starting with {", () => {
  const { bundle, integrityVerified } = importSignedBundle(
    bundleToJson(makeBundle())
  );
  assert.equal(integrityVerified, false);
  assert.equal(bundle.circuit, "poseidon_preimage");
});

test("importSignedBundle accepts a base64 string", () => {
  const b64 = bundleToBase64(makeBundle());
  const { bundle } = importSignedBundle(b64);
  assert.equal(bundle.circuit, "poseidon_preimage");
});

test("importSignedBundle throws when the digest is tampered", () => {
  const signed = signBundle(makeBundle());
  const tampered = { ...signed, digest: "00".repeat(32) };
  assert.throws(
    () => importSignedBundle(tampered),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT &&
      e.message.includes("integrity")
  );
});

test("importSignedBundle throws for a JSON string with a bad shape", () => {
  assert.throws(
    () => importSignedBundle(JSON.stringify({ not: "a bundle" })),
    (e: unknown) =>
      e instanceof SorobanZkError &&
      e.code === SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
});
