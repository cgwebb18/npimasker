/* A DOM small enough to run the page's UI code in Node.
 *
 * Not a browser and not trying to be. It exists so the rule-builder actually
 * executes in a test: attaching listeners, rendering rows, reading selects.
 * A syntax check cannot catch a typo in an event handler; this can.
 */
import { readFileSync } from "node:fs";

const PAGE = new URL("../collapse-duplicates.html", import.meta.url);

class El {
  constructor(tag){
    this.tagName = String(tag || "div").toUpperCase();
    this.children = [];
    this.listeners = {};
    this.className = "";
    this.style = {};
    this._html = "";
    this.textContent = "";
    this.value = "";
    this.checked = false;
    this.hidden = false;
    this.disabled = false;
    this.classList = {
      _s: new Set(),
      add: c => this.classList._s.add(c),
      remove: c => this.classList._s.delete(c),
      contains: c => this.classList._s.has(c),
    };
  }
  get innerHTML(){ return this._html; }
  set innerHTML(v){ this._html = String(v); this.children = []; }
  appendChild(c){ this.children.push(c); return c; }
  addEventListener(ev, fn){ (this.listeners[ev] ||= []).push(fn); }
  fire(ev, arg){ for (const fn of this.listeners[ev] || []) fn(arg || { preventDefault(){} }); }
  scrollIntoView(){}
  remove(){}
  querySelectorAll(){ return []; }
  /* depth-first search of created children, for assertions */
  find(pred){
    if (pred(this)) return this;
    for (const c of this.children){ const r = c.find(pred); if (r) return r; }
    return null;
  }
  findAll(pred, acc = []){
    if (pred(this)) acc.push(this);
    for (const c of this.children) c.findAll(pred, acc);
    return acc;
  }
}

export function bootPage(){
  const html = readFileSync(PAGE, "utf8");
  const i = html.indexOf('<script>\n"use strict";');
  const j = html.indexOf("</script>", i);
  const js = html.slice(i + "<script>".length, j);

  const byId = new Map();
  const el = id => {
    if (!byId.has(id)){
      const e = new El("div");
      e.id = id;
      byId.set(id, e);
    }
    return byId.get(id);
  };
  // Elements the page expects to exist, with their real defaults.
  el("wsBlank").checked = true;
  el("pfxTrim").checked = true;
  el("pfxCase").checked = false;

  const document = {
    querySelector(sel){ return el(sel.replace(/^#/, "")); },
    createElement(tag){ return new El(tag); },
    createTextNode(t){ const n = new El("#text"); n.textContent = String(t); return n; },
    body: new El("body"),
  };

  const epilogue = `
    ;return {
      el: (id) => __byId(id),
      setData(h, r){ HEADERS = h; ROWS = r; },
      buildPickers, renderRules, syncPick, runCollapse, render, defaultCfg,
      keySet,
      get RULECFG(){ return RULECFG; }, set RULECFG(v){ RULECFG = v; },
      get RESULT(){ return RESULT; },
    };`;

  const fn = new Function("document", "window", "XLSX", "__byId", js + epilogue);
  const api = fn(document, { }, { utils:{}, write(){}, read(){} }, el);
  api.byId = byId;
  return api;
}
