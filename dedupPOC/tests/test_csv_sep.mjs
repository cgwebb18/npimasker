/* Excel's "sep=" preamble.
 *
 * Excel on Windows writes a leading `sep=,` (or `sep=;`) line when the list
 * separator of the machine that saved the file differs from the one implied by
 * the extension. Treating that line as the header row is catastrophic and
 * silent: the file is read as two columns wide, the real header becomes data
 * row 1, and every column past the second is dropped from the output.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { loadCsv, loadGrid } from "./harness.mjs";

const C = loadCsv();
const G = loadGrid();

const table = text => G.gridToTable(C.parseCSV(text));

test("a sep= line sets the delimiter and is not treated as data", () => {
  const t = table("sep=,\r\nId,Account,Owner\r\n1,Acme,Ann\r\n2,Globex,Bob\r\n");
  assert.deepEqual(t.headers, ["Id", "Account", "Owner"]);
  assert.equal(t.width, 3, "was 2 before: sep= and an empty second field");
  assert.equal(t.rows.length, 2, "the real header must not become a data row");
  assert.deepEqual(t.rows[0], ["1", "Acme", "Ann"]);
});

test("sep=; declares a semicolon even where commas also appear", () => {
  const t = table('sep=;\r\nId;Notes;Owner\r\n1;"a, b, c";Ann\r\n');
  assert.deepEqual(t.headers, ["Id", "Notes", "Owner"]);
  assert.deepEqual(t.rows[0], ["1", "a, b, c", "Ann"]);
});

test("sep= with a tab is honoured", () => {
  const t = table("sep=\t\r\nId\tAccount\r\n1\tAcme\r\n");
  assert.deepEqual(t.headers, ["Id", "Account"]);
  assert.deepEqual(t.rows[0], ["1", "Acme"]);
});

test("a UTF-8 BOM in front of sep= is handled", () => {
  const t = table("﻿sep=,\r\nId,Account\r\n1,Acme\r\n");
  assert.deepEqual(t.headers, ["Id", "Account"]);
});

test("the declared separator beats what sniffing would have guessed", () => {
  // Semicolon-delimited, but the header names contain more commas than
  // semicolons, so sniffing alone would pick the comma and shred the row.
  const text = "sep=;\r\nA,B,C;D,E,F;G\r\n1;2;3\r\n";
  const t = table(text);
  assert.deepEqual(t.headers, ["A,B,C", "D,E,F", "G"]);
  assert.deepEqual(t.rows[0], ["1", "2", "3"]);
});

test("a bare sep= with no character is ignored rather than breaking the file", () => {
  const t = table("sep=\r\nId,Account\r\n1,Acme\r\n");
  assert.deepEqual(t.headers, ["Id", "Account"],
    "fall back to sniffing; do not consume the header row");
});

test("a column genuinely named sep= is not mistaken for the preamble", () => {
  // The preamble is exactly `sep=` plus one character on its own line. A header
  // row that merely starts with it has other fields after a delimiter.
  const t = table("sep=,other\r\n1,2\r\n");
  assert.equal(t.headers.length, 2);
  assert.equal(t.headers[0], "sep=");
  assert.equal(t.headers[1], "other");
});

test("files without a preamble are unaffected", () => {
  const t = table("Id,Account,Owner\r\n1,Acme,Ann\r\n");
  assert.deepEqual(t.headers, ["Id", "Account", "Owner"]);
  assert.equal(t.rows.length, 1);
});

test("a lone LF after sep= works as well as CRLF", () => {
  const t = table("sep=,\nId,Account\n1,Acme\n");
  assert.deepEqual(t.headers, ["Id", "Account"]);
});
