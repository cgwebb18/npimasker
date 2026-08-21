# Tests for the row collapser

```
cd dedupPOC
node --test "tests/*.mjs"
```

No dependencies and no build. Node 18 or newer.

## How these reach the code

The tool has to stay a single self-contained `.html` file, so there is nothing to import. The tests slice marked regions straight out of `collapse-duplicates.html` and evaluate them:

```
/* ==== csv:begin ==== */    …CSV parsing…     /* ==== csv:end ==== */
/* ==== rules:begin ==== */  …survivor rules…  /* ==== rules:end ==== */
```

Everything inside those markers must stay pure — no DOM, no globals from outside the block, no I/O. That is what makes it testable, and it means the tested code and the shipped code cannot drift apart. **If you move code out of those markers, the tests stop covering it.**

`domshim.mjs` is a DOM small enough to run the page's UI code in Node. It is not a browser and is not trying to be. It exists so the rule builder actually executes in a test — a syntax check cannot catch a typo in an event handler.

| File | Covers |
|---|---|
| `test_engine.mjs` | The narrowing engine and its invariants |
| `test_rule_date.mjs` | Date parsing and format detection |
| `test_rule_number.mjs` | Prefix stripping and number parsing |
| `test_rule_completeness.mjs` | Counting filled columns |
| `test_collapse_sample.mjs` | `sample_shape.csv` against the numbers the README publishes |
| `test_rules_sample.mjs` | `sample_rules.csv`, asserting which level decided which group |
| `test_ui_builder.mjs` | The rule builder running against the DOM shim |

## Two things worth keeping

`test_collapse_sample.mjs` asserts the figures printed in the README, which were written before any of this existed. It is an independent record of what the tool decided before the rules engine, so it catches a behaviour change disguised as a refactor.

`test_rules_sample.mjs` asserts **attribution**, not just row counts — which level decided which group. Counts alone would pass even with the levels running in the wrong order.
