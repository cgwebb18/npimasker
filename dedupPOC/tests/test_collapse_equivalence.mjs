/* Differential test: the working tree's collapseRows against the last committed
   one, over randomised tables.
 *
 * This exists so the grouping can be rewritten for speed and memory without
 * anyone having to take "it behaves the same" on trust. It is a healthcare
 * dedup tool; which rows survive is not something to eyeball.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { loadRulesFromSource } from "./harness.mjs";

const HERE = new URL(".", import.meta.url).pathname;
const HEAD = execFileSync("git", ["show", "HEAD:dedupPOC/collapse-duplicates.html"],
  { cwd: HERE + "../..", encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
const WORK = readFileSync(HERE + "../collapse-duplicates.html", "utf8");

const REF = loadRulesFromSource(HEAD);
const NEW = loadRulesFromSource(WORK);

/* A deliberately hostile alphabet: the things that have broken this tool
   before, plus the things that break naive hashing. */
const VALUES = [
  "", " ", "  ", "\t", "a", "A", "a ", " a", "ab", "ba", "0", "00", "0.0",
  "-1", "1e3", "1.23E+15", "REF: x", "REF:x", "x", "Ann", "ann", "ÄNN", "änn",
  "2026-03-04", "04/03/2026", "20260304", "46085", "INV-0001", "INV-1",
  "Kqbu", "K6apa",            // a genuine 32-bit FNV-1a collision pair
  String.fromCharCode(0) + "z", "z" + String.fromCharCode(0),
];

function mulberry(seed){
  return function(){
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function makeCase(rnd){
  const cols = 2 + Math.floor(rnd() * 5);
  const rows = 1 + Math.floor(rnd() * 24);
  const table = [];
  for (let i = 0; i < rows; i++){
    const r = [];
    for (let c = 0; c < cols; c++) r.push(VALUES[Math.floor(rnd() * VALUES.length)]);
    table.push(r);
  }
  const keys = [];
  for (let c = 0; c < cols; c++) if (rnd() < 0.55) keys.push(c);
  if (!keys.length) keys.push(0);

  const pfx = new Map();
  if (rnd() < 0.3) pfx.set(keys[0], "REF:");
  const opts = { ci: rnd() < 0.5, trim: rnd() < 0.5 };

  const kinds = ["hasvalue", "date", "number", "text", "count"];
  const rules = [];
  const levels = Math.floor(rnd() * 3);
  for (let l = 0; l < levels; l++){
    const kind = kinds[Math.floor(rnd() * kinds.length)];
    const field = Math.floor(rnd() * cols);
    const dir = rnd() < 0.5 ? "min" : "max";
    if (kind === "count"){
      const fields = [];
      for (let c = 0; c < cols; c++) if (rnd() < 0.5) fields.push(c);
      rules.push({ type:"count", dir, fields, counts: rnd() < 0.5 ? "above-zero" : "filled" });
    } else if (kind === "hasvalue"){
      rules.push({ type:"hasvalue", field });
    } else {
      const c = { type:"minmax", parse:kind, dir, field,
                  strip: rnd() < 0.4 ? "digits" : (rnd() < 0.5 ? "prefix" : "none"), pfx:"INV-" };
      if (kind === "date") c.fmt = ["ISO","DMY","MDY","YMD8","SERIAL"][Math.floor(rnd() * 5)];
      if (kind === "number" && rnd() < 0.3) c.zero = true;
      rules.push(c);
    }
  }
  return { table, keys, pfx, opts, rules, wsBlank: rnd() < 0.5 };
}

function run(mod, c){
  const cellAt = (i, j) => c.table[i][j];
  return mod.collapseRows({
    n: c.table.length,
    cellAt,
    keys: c.keys,
    norm: mod.makeNorm(c.pfx, c.opts),
    anyPfx: c.pfx.size > 0,
    rules: mod.buildRules(c.rules, cellAt, c.table.length, c.wsBlank),
    wsBlank: c.wsBlank,
    tie: c.keys[0],
    sampleLimit: 30,
  });
}

/* Compare everything a caller can observe. */
function compare(a, b, label){
  assert.deepEqual(a.keptIdx, b.keptIdx, label + ": survivors");
  assert.deepEqual(a.goneIdx, b.goneIdx, label + ": removed");
  assert.deepEqual(a.decidedAt, b.decidedAt, label + ": which level decided");
  assert.deepEqual(a.stats, b.stats, label + ": every counter");
  assert.equal(a.samples.length, b.samples.length, label + ": sample count");
  for (let i = 0; i < a.samples.length; i++){
    const x = a.samples[i], y = b.samples[i];
    assert.equal(x.k, y.k, label + ": group key " + i);
    assert.deepEqual(x.idxs, y.idxs, label + ": group members " + i);
    assert.equal(x.winner, y.winner, label + ": winner " + i);
    assert.equal(x.reason, y.reason, label + ": reason " + i);
    assert.equal(x.decidedBy, y.decidedBy, label + ": attribution " + i);
    assert.deepEqual(x.trail, y.trail, label + ": trail " + i);
    assert.deepEqual(x.shown, y.shown, label + ": per-criterion values " + i);
  }
}

test("the working tree matches the committed implementation over 2000 random cases", () => {
  const rnd = mulberry(20260820);
  for (let n = 0; n < 2000; n++){
    const c = makeCase(rnd);
    compare(run(REF, c), run(NEW, c), "case " + n);
  }
});

test("rows whose keys collide under a 32-bit hash stay in separate groups", () => {
  // "Kqbu" and "K6apa" share an FNV-1a 32-bit hash. Any hashed grouping must
  // confirm the hit against the real values, or these two merge.
  const table = [["Kqbu", "a"], ["K6apa", "b"], ["Kqbu", "c"]];
  const c = { table, keys:[0], pfx:new Map(), opts:{}, rules:[], wsBlank:true };
  const out = run(NEW, c);
  assert.equal(out.stats.groups, 2, "two distinct keys, not one");
  assert.equal(out.stats.dupGroups, 1);
  compare(run(REF, c), out, "hash collision");
});

test("a NUL inside a value groups the same way it always has", () => {
  const Z = String.fromCharCode(0);
  const table = [["a" + Z + "b", ""], ["a", "b"], ["a" + Z + "b", ""]];
  const c = { table, keys:[0, 1], pfx:new Map(), opts:{}, rules:[], wsBlank:true };
  compare(run(REF, c), run(NEW, c), "NUL in value");
});
