// Vanilla-node (no jest/vitest) regression test for canonicalJson.
//
// Verifies that canonicalJson escapes non-ASCII code points as \uXXXX
// to match Python's json.dumps(..., ensure_ascii=True). Audit F-A-2.
//
// Run via `npm test` in sdk-ts/ (exits non-zero on any failure).
import assert from "node:assert/strict";
import { canonicalJson, computePayloadHash } from "../dist/utils.js";

const cases = [
  {
    name: "ascii only",
    payload: { a: 1, b: "hello" },
    canonical: '{"a":1,"b":"hello"}',
    hash: "d84ab9f85753473707229d00b92623f0f9a1b8b9bf69763fc5cfc692b56c236b",
  },
  {
    name: "latin1 (José)",
    payload: { name: "José" },
    canonical: '{"name":"Jos\\u00e9"}',
    hash: "782f7fb6e7349477ad0878467428033420f78fc728c94d07ebb1d49d7cbae82e",
  },
  {
    name: "astral (café 🎉)",
    payload: { msg: "café 🎉" },
    canonical: '{"msg":"caf\\u00e9 \\ud83c\\udf89"}',
    hash: "10c53dc2027ebf7f5f31e8d5191382d676bbf62f847bae56a09414891cd2dd6a",
  },
  {
    name: "controls + DEL boundary",
    payload: { k: "\u0000\u007f\u0080\u00ff" },
    canonical: '{"k":"\\u0000\\u007f\\u0080\\u00ff"}',
    hash: "8506cd934650b2d8920884f9cdb74037de8b53e9ebdc7da337927921230bef23",
  },
  {
    name: "sorted keys nested",
    payload: { z: 1, a: { c: 3, b: 2 } },
    canonical: '{"a":{"b":2,"c":3},"z":1}',
  },
];

let failed = 0;
for (const c of cases) {
  try {
    const got = canonicalJson(c.payload);
    assert.equal(got, c.canonical, `${c.name}: canonical mismatch`);
    if (c.hash) {
      assert.equal(
        computePayloadHash(c.payload),
        c.hash,
        `${c.name}: hash mismatch`,
      );
    }
    // DEL (U+007F) and non-ASCII BMP must NOT appear raw in the output.
    for (let i = 0; i < got.length; i++) {
      const cp = got.charCodeAt(i);
      assert.ok(
        cp < 0x7f,
        `${c.name}: raw code point U+${cp.toString(16)} leaked at index ${i}`,
      );
    }
    console.log(`  ok  ${c.name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL  ${c.name}: ${err.message}`);
  }
}

if (failed > 0) {
  console.error(`\n${failed} test(s) failed`);
  process.exit(1);
}
console.log(`\nall ${cases.length} tests passed`);
