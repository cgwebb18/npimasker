/* UTF-16 and UTF-32, with and without a BOM.
 *
 * Field report from the Python side of this repo: PowerShell's `Out-File` and
 * `>` redirection write UTF-16LE, so exports too large to have come through
 * Excel arrive that way. Reading those bytes as UTF-8 does not fail -- NUL is
 * valid UTF-8 -- so the old ladder (BOM, then UTF-8 with fatal:true, then
 * cp1252) accepted them silently.
 *
 * The damage is not cosmetic. `\r\n` is 0D 00 0A 00, so an 8-bit read ends a
 * row at the \r and another at the \n: a 20-row file parses to 41 rows, half of
 * them invented and all identical. The collapser then groups those, deletes
 * them, and reports a successful dedup.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { loadCsv, loadGrid } from "./harness.mjs";

const C = loadCsv();
const G = loadGrid();

function utf16(str, { be = false, bom = false } = {}){
  const n = str.length;
  const out = new Uint8Array(n * 2 + (bom ? 2 : 0));
  let p = 0;
  if (bom){ out[p++] = be ? 0xFE : 0xFF; out[p++] = be ? 0xFF : 0xFE; }
  for (let i = 0; i < n; i++){
    const c = str.charCodeAt(i);
    if (be){ out[p++] = c >> 8; out[p++] = c & 0xff; }
    else   { out[p++] = c & 0xff; out[p++] = c >> 8; }
  }
  return out;
}
function utf32(str, { be = false } = {}){
  const out = new Uint8Array(4 + str.length * 4);
  let p = 0;
  if (be){ out[p++] = 0; out[p++] = 0; out[p++] = 0xFE; out[p++] = 0xFF; }
  else   { out[p++] = 0xFF; out[p++] = 0xFE; out[p++] = 0; out[p++] = 0; }
  for (const ch of str){
    const c = ch.codePointAt(0);
    if (be){ out[p++] = 0; out[p++] = 0; out[p++] = c >> 8; out[p++] = c & 0xff; }
    else   { out[p++] = c & 0xff; out[p++] = c >> 8; out[p++] = 0; out[p++] = 0; }
  }
  return out;
}
const CSV = "ID,Name\r\n1,Ann\r\n2,Bob\r\n";

test("BOM-less UTF-16LE is recognised, not accepted as UTF-8", () => {
  const r = C.decodeText(utf16(CSV));
  assert.equal(r.encoding, "utf-16le");
  assert.equal(r.text, CSV);
});

test("BOM-less UTF-16BE is recognised", () => {
  const r = C.decodeText(utf16(CSV, { be: true }));
  assert.equal(r.encoding, "utf-16be");
  assert.equal(r.text, CSV);
});

test("a BOM-less UTF-16 file yields the right number of rows", () => {
  // The old behaviour turned 2 data rows into 6, half of them invented and
  // identical -- which the collapser then happily deleted.
  const t = G.gridToTable(C.parseCSV(C.decodeText(utf16(CSV)).text));
  assert.deepEqual(t.headers, ["ID", "Name"]);
  assert.equal(t.rows.length, 2);
  assert.deepEqual(t.rows[0], ["1", "Ann"]);
  assert.deepEqual(t.rows[1], ["2", "Bob"]);
});

test("UTF-32LE is tested before UTF-16LE, whose BOM is its prefix", () => {
  // FF FE 00 00 starts with FF FE, so order of the checks is the whole fix.
  const r = C.decodeText(utf32(CSV));
  assert.equal(r.encoding, "utf-32le");
  assert.equal(r.text, CSV);
});

test("UTF-32BE is recognised", () => {
  const r = C.decodeText(utf32(CSV, { be: true }));
  assert.equal(r.encoding, "utf-32be");
  assert.equal(r.text, CSV);
});

test("a BOM still wins outright for UTF-16", () => {
  const r = C.decodeText(utf16(CSV, { bom: true }));
  assert.equal(r.encoding, "utf-16le");
  assert.equal(r.text, CSV);
});

test("binary that is no encoding at all is refused, not decoded as cp1252", () => {
  // An .xlsx renamed .csv used to come back as 400 characters of junk.
  const junk = new Uint8Array([0x50, 0x4B, 3, 4, 0, 0, 8, 8, 0, 0, 0x9A, 0, 0x11, 0, 0]);
  assert.throws(() => C.decodeText(junk), /encoding/i,
    "refusing is the only safe answer when the evidence is not decisive");
});

test("one stray NUL in a short UTF-8 file does not trigger a UTF-16 guess", () => {
  // The Python original misfires here: a 9-byte file with one NUL satisfies
  // its density rule. Require a minimum length before density means anything.
  const bytes = new Uint8Array([0x61, 0x2C, 0x62, 0x0A, 0x31, 0x00, 0x32, 0x0A, 0x33]);
  const r = C.decodeText(bytes);
  assert.notEqual(r.encoding, "utf-16le");
  assert.notEqual(r.encoding, "utf-16be");
});

test("ordinary UTF-8 and cp1252 files are unaffected", () => {
  assert.equal(C.decodeText(new TextEncoder().encode(CSV)).encoding, "utf-8");
  const cp = new Uint8Array([0x42, 0x6A, 0xF6, 0x72, 0x6E]);   // "Björn" in cp1252
  const r = C.decodeText(cp);
  assert.equal(r.encoding, "windows-1252");
  assert.equal(r.text, "Björn");
});
