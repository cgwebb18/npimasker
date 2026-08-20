/* CSV text decoding.
 *
 * The page used to read every CSV as UTF-8. Excel on Windows writes
 * Windows-1252 for plain "CSV (Comma delimited)" -- only the separate
 * "CSV UTF-8" option is UTF-8. Decoding cp1252 bytes as UTF-8 replaces every
 * bad byte with U+FFFD, and that is not cosmetic: two different names collapse
 * into the same string and the tool deletes one of them, with nothing in the
 * output looking unusual and the near-miss counter reading zero.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { loadCsv } from "./harness.mjs";

const C = loadCsv();
const u8 = (...b) => new Uint8Array(b);
const cp1252 = s => {
  // encode the few high characters we test by codepoint; cp1252 is latin-1
  // for the range we use here
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.codePointAt(i) & 0xff;
  return out;
};
const utf8 = s => new TextEncoder().encode(s);

test("plain ASCII decodes as UTF-8", () => {
  const r = C.decodeText(utf8("ref_id,name\n1,Ann\n"));
  assert.equal(r.encoding, "utf-8");
  assert.match(r.text, /^ref_id,name/);
});

test("a UTF-8 BOM is recognised and removed", () => {
  const bytes = new Uint8Array([0xEF, 0xBB, 0xBF, ...utf8("a,b\n")]);
  const r = C.decodeText(bytes);
  assert.equal(r.encoding, "utf-8");
  assert.equal(r.text[0], "a", "the BOM must not survive into the header name");
});

test("valid multi-byte UTF-8 is decoded as UTF-8", () => {
  const r = C.decodeText(utf8("name\nBjörn Andrésen\n"));
  assert.equal(r.encoding, "utf-8");
  assert.match(r.text, /Björn Andrésen/);
});

test("Windows-1252 bytes are detected and decoded correctly", () => {
  const r = C.decodeText(cp1252("name\nBjörn Andrésen\n"));
  assert.equal(r.encoding, "windows-1252");
  assert.match(r.text, /Björn Andrésen/, "the accents must survive intact");
  assert.ok(!r.text.includes("�"), "no replacement characters anywhere");
});

test("the two names that used to collapse stay distinct", () => {
  // This is the actual field failure: as UTF-8 both became "Bj�rn Andr�sen"
  const a = C.decodeText(cp1252("Björn Andrésen")).text;
  const b = C.decodeText(cp1252("Bjürn Andrèsen")).text;
  assert.notEqual(a, b, "two different people must not decode to the same string");
  assert.equal(a, "Björn Andrésen");
  assert.equal(b, "Bjürn Andrèsen");
});

test("a UTF-16 LE BOM is handled", () => {
  const body = "a,b\n1,2\n";
  const bytes = new Uint8Array(2 + body.length * 2);
  bytes[0] = 0xFF; bytes[1] = 0xFE;
  for (let i = 0; i < body.length; i++){
    bytes[2 + i * 2] = body.charCodeAt(i) & 0xff;
    bytes[3 + i * 2] = body.charCodeAt(i) >> 8;
  }
  const r = C.decodeText(bytes);
  assert.equal(r.encoding, "utf-16le");
  assert.match(r.text, /^a,b/);
});

test("a UTF-16 BE BOM is handled", () => {
  const body = "a,b\n";
  const bytes = new Uint8Array(2 + body.length * 2);
  bytes[0] = 0xFE; bytes[1] = 0xFF;
  for (let i = 0; i < body.length; i++){
    bytes[2 + i * 2] = body.charCodeAt(i) >> 8;
    bytes[3 + i * 2] = body.charCodeAt(i) & 0xff;
  }
  const r = C.decodeText(bytes);
  assert.equal(r.encoding, "utf-16be");
  assert.match(r.text, /^a,b/);
});

test("decoding never introduces a replacement character silently", () => {
  // every byte 0x80-0xFF is a valid cp1252 character except a handful;
  // whatever we choose, the result must not contain U+FFFD
  const bytes = new Uint8Array(128);
  for (let i = 0; i < 128; i++) bytes[i] = 128 + i;
  const r = C.decodeText(bytes);
  assert.ok(!r.text.includes("�"),
    "if this fails the tool is corrupting data it could have read");
});

test("the chosen encoding is reported so the UI can say which it used", () => {
  assert.equal(C.decodeText(utf8("a")).encoding, "utf-8");
  assert.equal(C.decodeText(cp1252("é")).encoding, "windows-1252");
});

test("an empty file decodes to empty text without throwing", () => {
  const r = C.decodeText(new Uint8Array(0));
  assert.equal(r.text, "");
});
