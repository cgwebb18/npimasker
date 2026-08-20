/* End-to-end characterisation against sample_shape.csv.
 *
 * The published README states exactly what this file must produce. Those
 * numbers were written before any of this refactor existed, which makes them
 * an independent golden record: if the rules engine changes what the tool
 * decides, this test fails.
 *
 *   18 rows out   11 rows removed   9 colliding groups
 *   3 tiebreak overrides   3 groups joined by prefix   4 near-miss keys
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadRules, loadCsv } from "./harness.mjs";

const R = loadRules();
const C = loadCsv();

const SAMPLE = new URL("../sample_shape.csv", import.meta.url);

// Column layout of sample_shape.csv
const REF_ID = 0, SITE = 1, SVC_DATE = 2, CATEGORY = 3, SUB_CAT = 4, STATUS = 5;
const KEYS = [REF_ID, SITE, SVC_DATE, CATEGORY, SUB_CAT];

/* Mirrors what load() does to a parsed grid (:348-356). */
function ingest(text){
  let grid = C.parseCSV(text);
  grid = grid.filter(row => row.some(c => String(c ?? "").length));
  const headers = grid[0].map(h => String(h ?? ""));
  const w = headers.length;
  const rows = grid.slice(1).map(row => {
    const out = new Array(w);
    for (let i = 0; i < w; i++) out[i] = String(row[i] ?? "");
    return out;
  });
  return { headers, rows };
}

/* The README's stated configuration, with the page's default checkbox states:
   prefix trim on, prefix case-sensitive, whitespace-is-blank on. */
function runSample(){
  const { headers, rows } = ingest(readFileSync(SAMPLE, "utf8"));
  const pfx = new Map([[CATEGORY, "REF NOTE:"]]);
  const norm = R.makeNorm(pfx, { trim: true, ci: false });
  const cellAt = (i, c) => rows[i][c];
  const wsBlank = true;

  const out = R.collapseRows({
    n: rows.length,
    cellAt,
    keys: KEYS,
    norm,
    anyPfx: true,
    rules: [R.makeHasValueRule(cellAt, STATUS, wsBlank)],
    wsBlank,
    tie: STATUS,
    sampleLimit: 30,
  });
  return { headers, rows, out };
}

test("the sample parses to the shape the README describes", () => {
  const { headers, rows } = ingest(readFileSync(SAMPLE, "utf8"));
  assert.equal(headers.length, 8);
  assert.equal(headers[REF_ID], "ref_id");
  assert.equal(headers[STATUS], "status_note");
  assert.equal(rows.length, 29, "README: 29 rows of made-up data");
});

test("rows in minus rows removed equals rows out", () => {
  const { out } = runSample();
  assert.equal(out.stats.rowsIn - out.stats.removed, out.stats.rowsOut,
    "the arithmetic check the tool prints in its own summary");
});

test("README golden numbers: 18 out, 11 removed, 9 colliding groups", () => {
  const { out } = runSample();
  assert.equal(out.stats.rowsOut, 18, "rows out");
  assert.equal(out.stats.removed, 11, "rows removed");
  assert.equal(out.stats.dupGroups, 9, "colliding groups");
});

test("README golden flags: 3 overrides, 3 joined by prefix, 4 near-miss", () => {
  const { out } = runSample();
  assert.equal(out.stats.conflicts, 3, "tiebreak overrode order");
  assert.equal(out.stats.pfxMerged, 3, "groups joined by prefix");
  assert.equal(out.stats.nearMiss, 4, "near-miss keys");
});

test("every surviving row index appears exactly once", () => {
  const { out } = runSample();
  const seen = new Set(out.keptIdx);
  assert.equal(seen.size, out.keptIdx.length, "no duplicates among survivors");
  assert.equal(out.keptIdx.length + out.goneIdx.length, out.stats.rowsIn,
    "every row is either kept or removed, never both or neither");
});

test("the collision inspector gets a sample for every group, up to its limit", () => {
  const { out } = runSample();
  assert.equal(out.samples.length, Math.min(9, 30));
  for (const s of out.samples){
    assert.ok(s.idxs.includes(s.winner), "the kept row must be in its own group");
    assert.ok(s.idxs.length > 1, "singletons are not collisions");
  }
});
