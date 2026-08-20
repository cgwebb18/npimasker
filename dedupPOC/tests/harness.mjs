/* Loads the survivor-rules engine out of the shipped page.
 *
 * The tool has to stay a single self-contained .html file, so there is nothing
 * to import. Instead we slice the marked pure-logic block out of the real file
 * and evaluate it. Tests therefore run against exactly the code that ships —
 * a copy would be free to drift.
 */
import { readFileSync } from "node:fs";

const PAGE = new URL("../collapse-duplicates.html", import.meta.url);

/** Slice one marked region out of the shipped page. */
function region(tag){
  const html = readFileSync(PAGE, "utf8");
  const begin = `/* ==== ${tag}:begin ==== */`;
  const end = `/* ==== ${tag}:end ==== */`;
  const a = html.indexOf(begin);
  const b = html.indexOf(end);
  if (a === -1 || b === -1){
    throw new Error(
      `Could not find the ${begin} / ${end} markers in collapse-duplicates.html.\n` +
      "That code must live inside those markers so the tests can reach it."
    );
  }
  return html.slice(a + begin.length, b);
}

/** Evaluate a region and hand back whichever of `names` it defines. */
function exportsOf(src, names){
  const fields = names
    .map(n => `${n}: typeof ${n} === "function" ? ${n} : undefined`)
    .join(",");
  return new Function('"use strict";' + src + "\nreturn {" + fields + "};")();
}

export function loadCsv(){
  return exportsOf(region("csv"), ["parseCSV", "sniffDelim", "toCSV", "csvCell", "decodeText"]);
}

export function loadRules(){
  const src = region("rules");
  const exported = [
    "collapseRows",
    "buildRules",
    "describeChain",
    "makeNorm",
    "pickWinner",
    "makeHasValueRule",
    "makeCountRule",
    "makeTextRule",
    "makeNumberRule",
    "makeDateRule",
    "detectDateFormat",
    "parseDateWith",
    "parseNumberWith",
  ];
  // Export only what the page actually defines, so rule types can land one at a
  // time without every earlier test file going red.
  return exportsOf(src, exported);
}

/** Build a cellAt(row, col) accessor over a plain array-of-arrays fixture. */
export function cellsOf(rows){
  return (i, c) => {
    const r = rows[i];
    const v = r === undefined ? undefined : r[c];
    return v === undefined || v === null ? "" : String(v);
  };
}

export function loadGrid(){
  return exportsOf(region("grid"), ["gridToTable", "headerLabel", "colLetter"]);
}

export function loadPresets(){
  return exportsOf(region("presets"), ["toPreset", "fromPreset", "parsePreset", "normName"]);
}
