/* Saving and reloading a dataset's settings.
 *
 * A saved preset holds both halves of the setup: the match columns that decide
 * what counts as a duplicate, and the ordered criteria that decide which row
 * survives. It is stored by COLUMN NAME, never by position, because the whole
 * point is to reuse it on next month's export -- where a column may well have
 * moved.
 *
 * Binding a saved preset to a file's headers is the one new silent-failure
 * mode this feature introduces: a preset that quietly attaches to the wrong
 * column produces a plausible, wrong answer. So binding reports what it could
 * not find, and never guesses.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { loadPresets } from "./harness.mjs";

const P = loadPresets();

const HEADERS = ["Client ID", "Entry Date", "Case Note", "NoteWriter", "Amount"];

const SETTINGS = {
  match: new Set([0, 1]),
  prefix: new Map([[2, "REF: "]]),
  rules: [
    { type:"minmax", parse:"date", dir:"min", field:1, fmt:"ISO", on:true },
    { type:"minmax", parse:"number", dir:"min", field:4, strip:"prefix", pfx:"INV-", on:true },
    { type:"count", dir:"max", fields:[2, 3], counts:"above-zero", on:true },
  ],
};

/* ---------- writing ---------- */

test("a saved preset records columns by name, not by position", () => {
  const p = P.toPreset("Casenotes", HEADERS, SETTINGS);
  assert.deepEqual(p.match, ["Client ID", "Entry Date"]);
  assert.deepEqual(p.prefix, { "Case Note": "REF: " });
  assert.equal(p.rules[0].field, "Entry Date");
  assert.deepEqual(p.rules[2].fields, ["Case Note", "NoteWriter"]);
});

test("the label and a format version are carried", () => {
  const p = P.toPreset("Casenotes", HEADERS, SETTINGS);
  assert.equal(p.label, "Casenotes");
  assert.equal(typeof p.version, "number", "so a later format change can be detected");
});

test("everything that changes the outcome is saved", () => {
  const p = P.toPreset("x", HEADERS, SETTINGS);
  const r = p.rules[1];
  assert.equal(r.parse, "number");
  assert.equal(r.dir, "min");
  assert.equal(r.strip, "prefix");
  assert.equal(r.pfx, "INV-");
  assert.equal(p.rules[2].counts, "above-zero");
});

test("a switched-off criterion is saved as off, not dropped", () => {
  const s = { match:new Set([0]), prefix:new Map(),
              rules:[{ type:"hasvalue", field:3, on:false }] };
  const p = P.toPreset("x", HEADERS, s);
  assert.equal(p.rules[0].on, false, "it must come back the way it was left");
});

test("a saved preset survives a round trip through JSON", () => {
  const p = P.toPreset("Casenotes", HEADERS, SETTINGS);
  const back = JSON.parse(JSON.stringify(p));
  const bound = P.fromPreset(back, HEADERS);
  assert.deepEqual([...bound.match], [0, 1]);
  assert.deepEqual([...bound.prefix], [[2, "REF: "]]);
  assert.equal(bound.rules[0].field, 1);
  assert.deepEqual(bound.rules[2].fields, [2, 3]);
  assert.equal(bound.missing.length, 0);
});

/* ---------- binding to a different file ---------- */

test("columns are found again after they move", () => {
  const moved = ["Amount", "NoteWriter", "Client ID", "Case Note", "Entry Date"];
  const p = P.toPreset("x", HEADERS, SETTINGS);
  const b = P.fromPreset(p, moved);
  assert.deepEqual([...b.match].sort((x, y) => x - y), [2, 4], "Client ID and Entry Date");
  assert.equal(b.rules[0].field, 4, "the date criterion followed Entry Date");
  assert.equal(b.missing.length, 0);
});

test("header names match despite case and punctuation drift", () => {
  const drifted = ["client id", "ENTRY_DATE", "Case  Note", "NoteWriter", "Amount"];
  const b = P.fromPreset(P.toPreset("x", HEADERS, SETTINGS), drifted);
  assert.equal(b.missing.length, 0, "normalised comparison, as the presets rely on");
  assert.equal(b.rules[0].field, 1);
});

test("a column that is genuinely absent is reported, never guessed", () => {
  const short = ["Client ID", "Case Note", "NoteWriter", "Amount"];   // no Entry Date
  const b = P.fromPreset(P.toPreset("x", HEADERS, SETTINGS), short);
  assert.ok(b.missing.length > 0);
  assert.ok(b.missing.some(m => /Entry Date/.test(m.name)));
  assert.ok(!b.rules.some(r => r.field === undefined && r.type !== "count"),
    "no criterion is left pointing at nothing");
});

test("a criterion whose column is missing comes back switched off", () => {
  const short = ["Client ID", "Case Note", "NoteWriter", "Amount"];
  const b = P.fromPreset(P.toPreset("x", HEADERS, SETTINGS), short);
  const dateRule = b.rules.find(r => r.parse === "date");
  assert.equal(dateRule.on, false,
    "better inert and visible than silently bound to the wrong column");
});

test("a counting rule keeps the columns it did find", () => {
  const partial = ["Client ID", "Entry Date", "Case Note", "Amount"];  // no NoteWriter
  const b = P.fromPreset(P.toPreset("x", HEADERS, SETTINGS), partial);
  const count = b.rules.find(r => r.type === "count");
  assert.deepEqual(count.fields, [2], "Case Note survived; NoteWriter is reported missing");
  assert.ok(b.missing.some(m => /NoteWriter/.test(m.name)));
});

test("a match column that is missing is reported, and not silently dropped", () => {
  const short = ["Client ID", "Case Note", "NoteWriter", "Amount"];
  const b = P.fromPreset(P.toPreset("x", HEADERS, SETTINGS), short);
  assert.ok(b.missing.some(m => m.where === "match"),
    "losing a match column changes what counts as a duplicate; that must be loud");
});

/* ---------- rejecting rubbish ---------- */

test("a file that is not a preset is refused with a reason", () => {
  assert.throws(() => P.parsePreset('{"hello":"world"}'), /preset/i);
  assert.throws(() => P.parsePreset("not json at all"), /read/i);
});

test("a preset from a newer format version is refused rather than half-read", () => {
  assert.throws(() => P.parsePreset(JSON.stringify({ version: 999, label:"x", match:[], rules:[] })),
    /newer/i);
});

test("a valid preset parses", () => {
  const p = P.toPreset("x", HEADERS, SETTINGS);
  const back = P.parsePreset(JSON.stringify(p));
  assert.equal(back.label, "x");
  assert.equal(back.rules.length, 3);
});

test("the label falls back to something usable when absent", () => {
  const p = P.parsePreset(JSON.stringify({ version:1, match:["Client ID"], rules:[] }));
  assert.ok(p.label && p.label.length, "a nameless preset is still listable");
});
