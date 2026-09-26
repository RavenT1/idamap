/* idamap web UI. Everything that comes from a binary (names, strings, output)
 * is attacker-controlled: it only ever reaches the DOM through textContent. */
"use strict";

// ------------------------------------------------------------------ helpers
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// replaceChildren that, like h(), flattens arrays and drops null/false
function fill(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter((c) => c != null && c !== false).map((c) => (c instanceof Node ? c : String(c))));
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}
const post = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const store = {
  get(k, d) { try { const v = localStorage.getItem("idamap." + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("idamap." + k, JSON.stringify(v)); } catch { /* private mode */ } },
};

function throttle(fn, ms) {
  let t = null, pending = false;
  return (...a) => {
    if (t) { pending = true; return; }
    fn(...a);
    t = setTimeout(() => { t = null; if (pending) { pending = false; fn(...a); } }, ms);
  };
}

const pad = (n) => String(n).padStart(2, "0");
function clock(ts) { const d = new Date(ts * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
function dateTime(ts) { const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; }
function ago(ts) {
  if (!ts) return "—";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return `${Math.max(0, Math.floor(s))}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function dur(ms) { if (ms == null) return ""; return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)}s`; }
const addrNum = (hex) => Number(BigInt(hex));

// ------------------------------------------------------------------ domain
const F = { SEEN: 1, DISASM: 2, DECOMP: 4, XREF: 8, CFG: 16, DATA: 32, RENAMED: 64, COMMENTED: 128, TYPED: 256, PATCHED: 512, FRAME: 1024, LUMINA: 2048, EXPLAINED: 4096 };
const ANNOTATED = F.RENAMED | F.COMMENTED | F.TYPED | F.PATCHED | F.LUMINA | F.EXPLAINED;
const STAGES = ["unseen", "seen", "explored", "disassembled", "decompiled", "annotated"];
const STAGE_LABEL = { unseen: "not looked at", seen: "seen in results", explored: "xrefs explored", disassembled: "disassembled", decompiled: "decompiled", annotated: "annotated" };
function stageOf(f) {
  if (f & ANNOTATED) return "annotated";
  if (f & F.DECOMP) return "decompiled";
  if (f & (F.DISASM | F.CFG | F.FRAME | F.DATA)) return "disassembled";
  if (f & F.XREF) return "explored";
  if (f & F.SEEN) return "seen";
  return "unseen";
}
const stageRank = (s) => STAGES.indexOf(s);
const PILLS = [["D", F.DECOMP, "decompiled"], ["A", F.DISASM, "disassembly"], ["B", F.CFG, "basic blocks"], ["X", F.XREF, "xrefs / callers / callees"],
  ["F", F.FRAME, "stack frame / types viewed"], ["M", F.DATA, "memory read"], ["R", F.RENAMED, "renamed"], ["C", F.COMMENTED, "commented"],
  ["T", F.TYPED, "types applied"], ["P", F.PATCHED, "patched"], ["E", F.EXPLAINED, "explained by the LLM (idamap_annotate)"]];
const HUMAN = ["todo", "in_progress", "reviewed", "interesting", "suspicious", "ignore"];
const HUMAN_LABEL = { todo: "To do", in_progress: "In progress", reviewed: "Reviewed", interesting: "Interesting", suspicious: "Suspicious", ignore: "Ignore" };
const stColor = (s) => css(`--st-${s}`);
const catColor = (c) => css(`--cat-${c}`) || css("--cat-other");
const huColor = (s) => css(`--hu-${s}`);

// ------------------------------------------------------------------ state
const state = {
  info: null,
  dbs: [],
  db: null,               // current db id
  summary: null,
  funcs: new Map(),       // start -> {start,name,size,flags,touches,last,first,human,orig,note}
  order: [],              // starts sorted by address
  calls: new Map(),       // id -> call (current db, most recent window)
  prompts: {},
  running: new Map(),     // id -> call (any db)
  tab: store.get("tab", "overview"),
  funcsNow: 0,
  drawerFn: null,
  lastActive: null,       // most recent function the LLM targeted
};

// ------------------------------------------------------------------ boot
async function boot() {
  applyTheme(store.get("theme", null));
  state.info = await api("/api/info");
  await loadConfig();
  await loadDbs();
  const m = location.hash.match(/db=(\d+)/);
  const want = m ? +m[1] : store.get("db", null);
  const pick = state.dbs.find((d) => d.id === want) || state.dbs[0];
  wireUi();
  showTab(state.tab);
  if (pick) await selectDb(pick.id);
  else renderEmpty();
  connectLive();
  setInterval(() => { updateNowBar(); if (state.tab === "overview") refreshRelTimes(); }, 1000);
}

async function loadDbs() {
  state.dbs = await api("/api/dbs");
  const sel = $("#dbSelect");
  const cur = state.db;
  fill(sel, ...state.dbs.map((d) => h("option", { value: d.id }, `${d.name}`)));
  if (cur != null) sel.value = cur;
  sel.hidden = !state.dbs.length;
}

async function selectDb(id) {
  state.db = id;
  store.set("db", id);
  history.replaceState(null, "", `#db=${id}`);
  $("#dbSelect").value = id;
  state.funcs.clear();
  state.calls.clear();
  state.prompts = {};
  graphState.loadedFor = null;
  const [sum, fn, cl] = await Promise.all([
    api(`/api/db/${id}/summary`), api(`/api/db/${id}/functions`), api(`/api/calls?db=${id}&limit=400`),
  ]);
  state.summary = sum;
  ingestFunctions(fn, true);
  for (const c of cl.calls) state.calls.set(c.id, c);
  Object.assign(state.prompts, cl.prompts);
  tl.oldest = cl.calls.length ? Math.min(...cl.calls.map((c) => c.id)) : null;
  tl.exhausted = cl.calls.length < 400;
  $("#exReport").href = `/api/db/${id}/report.md`;
  $("#exSync").href = `/api/db/${id}/ida_sync.py`;
  renderHeader();
  renderTab(true);
}

function ingestFunctions(res, reset) {
  if (reset) state.funcs.clear();
  let structural = reset;
  for (const r of res.functions) {
    const [start, name, size, flags, touches, last, first, human, orig, note, dem, summary, annStatus, suggested] = r;
    const rec = { start, name, size, flags, touches, last, first, human, orig, note, dem, summary, annStatus, suggested };
    const cur = state.funcs.get(start);
    if (cur) Object.assign(cur, rec);  // update in place: cached map groups hold these objects
    else { structural = true; state.funcs.set(start, { ...rec, n: addrNum(start) }); }
  }
  if (structural) state.order = [...state.funcs.values()].sort((a, b) => (a.n < b.n ? -1 : a.n > b.n ? 1 : 0)).map((f) => f.start);
  state.funcsNow = res.now;
  return structural;
}

// ------------------------------------------------------------------ live
function connectLive() {
  const es = new EventSource(`/api/live?since=${Date.now() / 1000}`);
  const dot = $("#liveDot");
  es.onopen = () => dot.className = "live on";
  es.onerror = () => dot.className = "live off";
  es.addEventListener("calls", (e) => onCalls(JSON.parse(e.data)));
  es.addEventListener("functions", () => refreshFunctions());
  es.addEventListener("dbs", async () => {
    await loadDbs();
    if (state.db == null && state.dbs.length) return selectDb(state.dbs[0].id);
    renderHeader();
  });
}

function onCalls(calls) {
  let mine = false, switchTo = null;
  for (const c of calls) {
    if (c.status === "running") state.running.set(c.id, c); else state.running.delete(c.id);
    if (c.func && c.status !== "error") state.lastActive = { db: c.db_id, func: c.func };
    if (c.db_id == null) continue;  // open_idb still deciding which database it is
    if (state.db == null) { switchTo = c.db_id; continue; }
    if (c.db_id === state.db) {
      mine = true;
      state.calls.set(c.id, c);
      if (c.prompt_id && !state.prompts[c.prompt_id]) needPrompts = true;
    } else if ($("#followDb").checked && c.status === "running") {
      switchTo = c.db_id;
    }
  }
  if (switchTo != null && state.dbs.some((d) => d.id === switchTo)) { selectDb(switchTo); return; }
  if (switchTo != null) { loadDbs().then(() => selectDb(switchTo)); return; }
  updateNowBar();
  if (!mine) return;
  if (needPrompts) loadPrompts();
  timelineLive(calls.filter((c) => c.db_id === state.db));
  refreshSummary();
  if (state.tab === "graph") graphPulse();
  if (state.tab === "map") drawMapSoon();
}

let needPrompts = false;
const loadPrompts = throttle(async () => {
  needPrompts = false;
  const cl = await api(`/api/calls?db=${state.db}&limit=50`);
  Object.assign(state.prompts, cl.prompts);
  renderTimeline();
}, 1500);

const refreshSummary = throttle(async () => {
  if (state.db == null) return;
  state.summary = await api(`/api/db/${state.db}/summary`);
  renderHeader();
  if (state.tab === "overview") renderOverview();
}, 1500);

const refreshFunctions = throttle(async () => {
  if (state.db == null) return;
  const res = await api(`/api/db/${state.db}/functions?since=${state.funcsNow - 3}`);
  ingestFunctions(res, false);
  renderHeader();
  if (state.tab === "map") { layoutMap(); drawMap(); }
  if (state.tab === "functions") renderFunctions();
  if (state.tab === "graph") loadGraph(false);
  if (state.drawerFn && state.tab !== "none") refreshDrawer();
}, 1200);

// ------------------------------------------------------------------ header / now bar
function renderHeader() {
  const d = state.dbs.find((x) => x.id === state.db);
  const meta = $("#dbMeta");
  meta.textContent = d ? [d.processor, d.file_type, d.bits ? `${d.bits}-bit` : null].filter(Boolean).join(" · ") : "";
  meta.title = d ? d.key : "";
  const bar = $("#miniBar");
  const counts = countStages();
  const total = Math.max(totalFuncs(), 1);
  fill(bar, ...STAGES.slice(1).reverse().map((s) => h("i", { style: { width: `${(100 * counts[s]) / total}%`, background: stColor(s) }, title: `${s}: ${counts[s]}` })));
}

function totalFuncs() {
  const d = state.dbs.find((x) => x.id === state.db);
  return Math.max(d?.func_total || 0, state.funcs.size);
}
function countStages() {
  const c = Object.fromEntries(STAGES.map((s) => [s, 0]));
  for (const f of state.funcs.values()) c[stageOf(f.flags)]++;
  c.unseen += Math.max(0, totalFuncs() - state.funcs.size);
  return c;
}

// Mangled Swift / C++ / MSVC names are unreadable: show the demangled form instead.
const MANGLED = /^_*(\$[sS]|T0|Z[NLS]?\d|\?)/;
function displayName(name, dem) { return dem && MANGLED.test(name || "") ? dem : name; }
function fnDisplay(f) { return displayName(f.name, f.dem); }
function fnName(start) { const f = state.funcs.get(start); return f ? fnDisplay(f) : start; }
// IDA auto-names carry no meaning: show the LLM's suggested name next to them (marked as a guess)
const AUTONAME = /^(sub|j_sub|nullsub|loc|unknown_libname)_[0-9A-Fa-f]+/;
function suggestionTag(f) {
  if (!f?.suggested || !AUTONAME.test(f.name || "") || f.suggested === f.name) return null;
  return h("span", { class: "sugg", title: f.annStatus === "confirmed" ? "name suggested by the LLM, explanation confirmed" : "name suggested by the LLM (unconfirmed)" },
    f.suggested, f.annStatus === "confirmed" ? "" : "?");
}

function updateNowBar() {
  const bar = $("#nowBar"), txt = $("#nowText");
  const running = [...state.running.values()].sort((a, b) => b.started_at - a.started_at);
  if (!running.length) {
    bar.classList.add("idle");
    const last = [...state.calls.values()].sort((a, b) => b.id - a.id)[0];
    fill(txt, last
      ? h("span", { class: "muted" }, "Idle · last call ", h("b", { class: "mono" }, last.tool), " ", ago(last.ended_at || last.started_at))
      : h("span", { class: "muted" }, "Waiting for ida-mcp activity…"));
    return;
  }
  bar.classList.remove("idle");
  const c = running[0];
  const db = state.dbs.find((d) => d.id === c.db_id);
  const elapsed = Date.now() / 1000 - c.started_at;
  fill(txt, 
    h("span", { class: "tool badge", style: { background: catColor(c.category) } }, c.tool),
    c.func ? fnLink(c.func, c.func_name || fnName(c.func)) : h("span", { class: "mono" }, c.target || ""),
    db && db.id !== state.db ? h("span", { class: "muted small" }, `in ${db.name}`) : null,
    harnessTag(c.harness),
    h("span", { class: "muted mono small" }, dur(Math.round(elapsed * 1000))),
    running.length > 1 ? h("span", { class: "muted small" }, `+${running.length - 1} more`) : null,
    c.intent ? h("span", { class: "intent" }, "— " + c.intent.split("\n")[0]) : null,
  );
}

function fnLink(start, name) {
  const f = state.funcs.get(start);
  const label = f ? fnDisplay(f) : (name || start);
  return h("span", { class: "fn", title: f && label !== f.name ? `${f.name}\n${start}` : start,
    onclick: (e) => { e.stopPropagation(); openFunction(start); } },
    h("span", { class: "dot", style: { background: stColor(stageOf(f?.flags || 0)) } }),
    h("span", { class: "fname" }, label), suggestionTag(f));
}

// ------------------------------------------------------------------ tabs
function showTab(tab) {
  state.tab = tab;
  store.set("tab", tab);
  $$("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $$(".tab").forEach((s) => s.classList.toggle("active", s.id === `tab-${tab}`));
}
function renderTab(force) {
  if (state.db == null) return renderEmpty();
  ({ overview: renderOverview, map: () => { layoutMap(); drawMap(); }, graph: () => loadGraph(force),
     functions: renderFunctions, timeline: renderTimeline })[state.tab]();
}

function renderEmpty() {
  fill($("#tab-overview"), h("div", { class: "empty" },
    h("h2", null, "No ida-mcp activity recorded yet"),
    h("p", null, "Route your MCP client's ida-mcp through the idamap proxy (any harness), or use Claude Code hooks:"),
    h("pre", null, "idamap mcp-config        # config snippets: Cursor, Codex, Claude Desktop, VS Code, Gemini, …\n" +
      "                         #   command: idamap proxy -- ida-mcp\n" +
      "idamap install           # Claude Code: hooks (adds prompts + LLM intent)"),
    h("p", null, "Every ida-mcp tool call will appear here live.")));
  showTab("overview");
}

// ------------------------------------------------------------------ overview
function kpi(label, value, sub, frac, color) {
  return h("div", { class: "kpi" },
    h("div", { class: "l" }, label),
    h("div", { class: "v" }, value, sub != null ? h("small", null, sub) : null),
    frac != null ? h("div", { class: "bar" }, h("i", { style: { width: `${Math.min(100, frac * 100)}%`, background: color || css("--accent") } })) : null);
}

function renderOverview() {
  const s = state.summary;
  if (!s) return;
  const d = s.db || {};
  const counts = countStages();
  const total = totalFuncs();
  const inspected = counts.explored + counts.disassembled + counts.decompiled + counts.annotated;
  const pct = (n) => (total ? `${((100 * n) / total).toFixed(1)}%` : "");
  const errors = s.by_tool.reduce((a, t) => a + (t.errors || 0), 0);
  const reviewed = (s.human.reviewed || 0);
  const root = $("#tab-overview");
  const kids = [];

  if (!d.map_imported_at) {
    kids.push(h("div", { class: "callout" },
      h("b", null, "Full function map not imported yet. "),
      `Coverage is measured against the ${total} function(s) seen so far. To map the whole binary (all functions + call edges), ask the LLM to run:`,
      h("div", { style: { marginTop: "8px", display: "flex", gap: "8px", alignItems: "center" } },
        h("code", null, `run_script(file="${state.info.export_script}")`),
        h("button", { class: "btn", onclick: (e) => copy(`run_script(file="${state.info.export_script}")`, e.target) }, "Copy")),
      h("div", { class: "muted small", style: { marginTop: "6px" } }, "Only one short summary line goes back into the model context. From the IDA GUI: File › Script file…, then ", h("code", null, "idamap import <json>"), ".")));
  }

  kids.push(h("div", { class: "kpis" },
    kpi("Functions", total.toLocaleString(), d.map_imported_at ? "mapped" : "known", null),
    kpi("Inspected", inspected.toLocaleString(), pct(inspected), total ? inspected / total : 0, stColor("disassembled")),
    kpi("Decompiled", (counts.decompiled + counts.annotated).toLocaleString(), pct(counts.decompiled + counts.annotated), total ? (counts.decompiled + counts.annotated) / total : 0, stColor("decompiled")),
    kpi("Annotated", counts.annotated.toLocaleString(), `${s.renames.length ? "renames, comments, types" : "renamed / commented"}`, total ? counts.annotated / total : 0, stColor("annotated")),
    kpi("Human reviewed", reviewed.toLocaleString(), inspected ? `of ${inspected} inspected` : "", inspected ? reviewed / inspected : 0, huColor("reviewed")),
    kpi("Tool calls", (d.calls || 0).toLocaleString(), errors ? `${errors} errors` : `${s.sessions} session(s)`, null)));

  kids.push(h("div", { class: "card" },
    h("h3", null, "Coverage"),
    h("div", { class: "stackbar" }, STAGES.slice(1).reverse().map((st) =>
      h("i", { style: { width: `${(100 * counts[st]) / Math.max(total, 1)}%`, background: stColor(st) }, title: `${STAGE_LABEL[st]}: ${counts[st]}` }))),
    h("div", { class: "legend", style: { marginTop: "8px" } }, STAGES.slice().reverse().map((st) =>
      h("span", null, h("i", { class: "sw", style: { background: stColor(st) } }), `${STAGE_LABEL[st]} `, h("b", { class: "mono" }, counts[st].toLocaleString()))))));

  const focus = h("ul", { class: "list" }, s.focus.length ? s.focus.map((f, i) => {
    const fr = state.funcs.get(f.start);
    return h("li", null,
      h("span", { class: "mono faint small", style: { width: "22px" } }, i === 0 ? "▶" : String(i + 1)),
      h("span", { class: "grow" }, fnLink(f.start, fr?.name || f.name)),
      h("span", { class: "muted small" }, stageOf(fr?.flags ?? f.flags)),
      h("span", { class: "faint small rel", "data-ts": fr?.last || "" }, ago(fr?.last)));
  }) : h("li", { class: "muted" }, "Nothing inspected yet."));

  const prompts = h("ul", { class: "list" }, s.prompts.length ? s.prompts.slice(0, 12).map((p) =>
    h("li", { class: "prompt-li", onclick: () => { showTab("timeline"); renderTimeline(); setTimeout(() => $(`[data-prompt="${CSS.escape(p.id || "")}"]`)?.scrollIntoView({ block: "start" }), 50); } },
      h("span", { class: "grow" }, p.text || h("i", { class: "muted" }, "(prompt text unavailable)")),
      h("span", { class: "mono muted small" }, `${p.calls} calls`),
      h("span", { class: "faint small" }, ago(p.ts)))) : h("li", { class: "muted" }, "No prompts recorded."));

  const maxTool = Math.max(1, ...s.by_tool.map((t) => t.n));
  const tools = h("div", { class: "bars" }, s.by_tool.slice(0, 14).map((t) =>
    h("div", { class: "row", title: `${t.n} calls · avg ${dur(Math.round(t.avg_ms || 0))}${t.errors ? ` · ${t.errors} errors` : ""}` },
      h("span", { class: "mono small", style: { overflow: "hidden", textOverflow: "ellipsis" } }, t.tool),
      h("div", { class: "track" }, h("i", { style: { width: `${(100 * t.n) / maxTool}%`, background: catColor(t.category) } })),
      h("span", { class: "n" }, t.n))));

  const renames = h("ul", { class: "list" }, s.renames.length ? s.renames.slice(0, 10).map((r) =>
    h("li", null,
      h("span", { class: "grow mono small" }, h("span", { class: "faint" }, r.old_name || "?"), "  →  ",
        r.addr && state.funcs.has(r.addr) ? fnLink(r.addr, r.new_name) : h("b", null, r.new_name)),
      h("span", { class: "faint small" }, ago(r.ts)))) : h("li", { class: "muted" }, "No renames yet."));

  const comments = h("ul", { class: "list" }, s.comments.length ? s.comments.slice(0, 10).map((c) =>
    h("li", null, c.func ? fnLink(c.func) : h("span", { class: "mono small" }, c.addr),
      h("span", { class: "grow muted" }, c.text), h("span", { class: "faint small" }, ago(c.ts)))) : h("li", { class: "muted" }, "No comments yet."));

  kids.push(h("div", { class: "cols" },
    h("div", null,
      h("div", { class: "card" }, h("h3", null, "Focus trail — most recently inspected"), focus),
      h("div", { class: "card" }, h("h3", null, "Tasks (prompts)"), prompts),
      h("div", { class: "card" }, h("h3", null, "Sessions & clients"), sessionsList(s.session_list || []))),
    h("div", null,
      h("div", { class: "card" }, h("h3", null, "Activity (calls / minute)"), sparkline(s.activity)),
      h("div", { class: "card" }, h("h3", null, "Tool usage"), tools),
      h("div", { class: "card" }, h("h3", null, "Recent renames"), renames),
      h("div", { class: "card" }, h("h3", null, "Recent comments"), comments),
      h("div", { class: "card" }, h("h3", null, "Recent LLM explanations"), explanationsList(s)))));
  fill(root, ...kids);
}

function explanationsList(s) {
  const list = s.explanations || [];
  if (!list.length) return h("div", { class: "muted" }, "None yet. " + EXPLAIN_HOWTO);
  const c = s.explanation_counts || {};
  return [h("div", { class: "muted small", style: { marginBottom: "6px" } },
    `${c.hypothesis || 0} unconfirmed · ${c.confirmed || 0} confirmed · ${c.rejected || 0} rejected`),
  h("ul", { class: "list" }, list.slice(0, 10).map((e) => h("li", null,
    fnLink(e.func, state.funcs.get(e.func)?.name || e.name),
    h("span", { class: "grow muted small" }, e.summary),
    h("span", { class: `badge st-${e.status}` }, e.status === "hypothesis" ? "?" : e.status === "confirmed" ? "✓" : "✗"))))];
}

function sessionsList(list) {
  if (!list.length) return h("div", { class: "muted" }, "No sessions yet.");
  return h("ul", { class: "list" }, list.map((x) => h("li", {
    class: "prompt-li", onclick: () => { showTab("timeline"); renderTimeline(); setTimeout(() => $(`[data-session="${CSS.escape(x.id)}"], [data-prompt]`)?.scrollIntoView({ block: "start" }), 50); },
  },
    harnessTag(x.harness || "unknown"),
    h("span", { class: "grow muted small mono" }, x.id.slice(0, 20)),
    h("span", { class: "faint small" }, x.source === "hook" ? "hooks" : x.source || ""),
    h("span", { class: "mono muted small" }, `${x.calls} calls${x.errors ? `, ${x.errors} err` : ""}`),
    h("span", { class: "faint small" }, ago(x.last)))));
}

function refreshRelTimes() { $$(".rel").forEach((e) => { if (e.dataset.ts) e.textContent = ago(+e.dataset.ts); }); }

function sparkline(act) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", "spark");
  if (!act.length) { svg.setAttribute("height", "20"); return h("div", { class: "muted" }, "No activity yet."); }
  // last 3 hours, one bar per minute
  const end = Math.floor(Date.now() / 60000) * 60, start = Math.min(Math.max(act[0][0], end - 180 * 60), end - 30 * 60);
  const n = Math.max(1, (end - start) / 60 + 1);
  const map = new Map(act.map(([t, c]) => [t, c]));
  const max = Math.max(1, ...act.filter(([t]) => t >= start).map(([, c]) => c));
  svg.setAttribute("viewBox", `0 0 ${n} 60`);
  svg.setAttribute("preserveAspectRatio", "none");
  for (let i = 0; i < n; i++) {
    const c = map.get(start + i * 60) || 0;
    if (!c) continue;
    const r = document.createElementNS(ns, "rect");
    const hgt = Math.max(2, (58 * c) / max);
    r.setAttribute("x", i + 0.1); r.setAttribute("width", 0.8); r.setAttribute("y", 60 - hgt); r.setAttribute("height", hgt);
    r.setAttribute("fill", css("--accent"));
    const t = document.createElementNS(ns, "title"); t.textContent = `${clock(start + i * 60)} — ${c} calls`; r.append(t);
    svg.append(r);
  }
  return h("div", null, svg, h("div", { class: "faint small", style: { display: "flex", justifyContent: "space-between" } },
    h("span", null, clock(start).slice(0, 5)), h("span", null, "now")));
}

function copy(text, btn) {
  navigator.clipboard?.writeText(text).then(() => { if (btn) { const o = btn.textContent; btn.textContent = "Copied"; setTimeout(() => btn.textContent = o, 1200); } });
}

// ------------------------------------------------------------------ coverage map
const mapState = { mode: store.get("mapMode", "stage"), hidden: new Set(), search: "", layout: null, tile: 10 };

// getComputedStyle is slow: resolve theme colours once per draw, not once per tile (100k+ tiles)
let colorCache = null;
function cachedColors() {
  if (!colorCache) {
    colorCache = { st: Object.fromEntries(STAGES.map((s) => [s, stColor(s)])), hu: Object.fromEntries(HUMAN.map((s) => [s, huColor(s)])),
      text: css("--text"), accent: css("--accent"), muted: css("--muted") };
    queueMicrotask(() => { colorCache = null; });  // theme may change between draws
  }
  return colorCache;
}

function mapColor(f) {
  const C = cachedColors();
  const stColor = (s) => C.st[s];
  const huColor = (s) => C.hu[s];
  const st = stageOf(f.flags);
  switch (mapState.mode) {
    case "heat": {
      if (!f.touches) return st === "seen" ? stColor("seen") : stColor("unseen");
      const t = Math.min(1, Math.log2(1 + f.touches) / 5);
      return `hsl(${200 - 190 * t}, 80%, ${38 + 14 * t}%)`;
    }
    case "recency": {
      if (!f.last) return stColor("unseen");
      const age = (Date.now() / 1000 - f.last) / 3600;
      const t = Math.max(0, 1 - Math.log2(1 + age) / 7);
      return `hsla(150, 70%, 48%, ${0.18 + 0.82 * t})`;
    }
    case "human": return f.human ? huColor(f.human) : stColor("unseen");
    default: return stColor(st);
  }
}
function mapVisible(f) {
  if (mapState.mode === "stage" && mapState.hidden.has(stageOf(f.flags))) return false;
  return true;
}
// name / address / original name / demangled name / explanation
function fnMatches(f, q) {
  return f.name?.toLowerCase().includes(q) || f.start.includes(q) || f.orig?.toLowerCase().includes(q) ||
    f.dem?.toLowerCase().includes(q) || f.summary?.toLowerCase().includes(q);
}

function mapMatches(f) {
  const q = mapState.search;
  return q && fnMatches(f, q);
}

function renderMapLegend() {
  const lg = $("#mapLegend");
  if (mapState.mode === "stage") {
    const counts = countStages();
    fill(lg, ...STAGES.slice().reverse().map((s) => h("span", {
      class: mapState.hidden.has(s) ? "off" : "", title: "click to toggle",
      onclick: () => { mapState.hidden.has(s) ? mapState.hidden.delete(s) : mapState.hidden.add(s); renderMapLegend(); drawMap(); },
    }, h("i", { class: "sw", style: { background: stColor(s) } }), `${STAGE_LABEL[s]} (${counts[s]})`)));
  } else if (mapState.mode === "human") {
    fill(lg, ...HUMAN.map((s) => h("span", null, h("i", { class: "sw", style: { background: huColor(s) } }), HUMAN_LABEL[s])));
  } else if (mapState.mode === "heat") {
    fill(lg, h("span", null, "few calls"), ...[0, .25, .5, .75, 1].map((t) => h("i", { class: "sw", style: { background: `hsl(${200 - 190 * t}, 80%, ${38 + 14 * t}%)` } })), h("span", null, "many calls"));
  } else {
    fill(lg, h("span", null, "older"), ...[0.2, 0.4, 0.6, 0.8, 1].map((a) => h("i", { class: "sw", style: { background: `hsla(150,70%,48%,${a})` } })), h("span", null, "just now"));
  }
}

// Grouping 100k functions into segments is not free: redo it only when the function set or segments change.
function segmentsForMap() {
  const sl = state.summary?.segments || [];
  const segKey = sl.map((x) => x.start + "-" + x.end).join(",");  // summary is refetched often; compare content
  if (mapState.blocksFor?.order === state.order && mapState.blocksFor?.segKey === segKey) return mapState.blocksFor.value;
  const value = computeSegmentsForMap();
  mapState.blocksFor = { order: state.order, segKey, value };
  return value;
}

function computeSegmentsForMap() {
  const segs = (state.summary?.segments || []).map((s) => ({ ...s, s: addrNum(s.start), e: addrNum(s.end) }));
  const fns = state.order.map((k) => state.funcs.get(k));
  if (!segs.length) {
    if (!fns.length) return [];
    const last = fns[fns.length - 1];
    return [{ name: "functions", s: fns[0].n, e: last.n + (last.size || 16), fns }];
  }
  const out = segs.map((s) => ({ ...s, fns: [] }));
  const other = { name: "(outside known segments)", s: 0, e: 0, fns: [] };
  let j = 0;
  for (const f of fns) {
    while (j < out.length && out[j].e <= f.n) j++;
    if (j < out.length && out[j].s <= f.n) out[j].fns.push(f); else other.fns.push(f);
  }
  const res = out.filter((s) => s.fns.length || s.type === "CODE");
  if (other.fns.length) res.push(other);
  return res;
}

function layoutMap() {
  const grid = $("#grid");
  const width = grid.parentElement.clientWidth - 28;
  const blocks = segmentsForMap();
  const n = Math.max(1, blocks.reduce((a, b) => a + b.fns.length, 0));
  // pick a tile size so the whole binary fits in ~2.5 screens
  const target = Math.max(window.innerHeight * 2.5, 400) * width;
  const tile = Math.max(3, Math.min(18, Math.floor(Math.sqrt(target / n))));
  const gap = tile >= 7 ? 1 : 0;
  const step = tile + gap, cols = Math.max(1, Math.floor(width / step));
  let y = 0;
  const lay = [];
  for (const b of blocks) {
    const rows = Math.ceil(b.fns.length / cols);
    lay.push({ ...b, y0: y + 18, rows });
    y += 18 + rows * step + 12;
  }
  mapState.layout = { blocks: lay, tile, gap, step, cols, width, height: Math.max(y, 40) };
  const dpr = window.devicePixelRatio || 1;
  grid.width = width * dpr; grid.height = mapState.layout.height * dpr;
  grid.style.width = width + "px"; grid.style.height = mapState.layout.height + "px";
  renderMapLegend();
}

// CSS colour string -> [r, g, b, a] (0-255), memoised; used to write tiles straight into ImageData
const rgbaCache = new Map();
function rgba(color) {
  let v = rgbaCache.get(color);
  if (!v) {
    const c = rgba.ctx || (rgba.ctx = Object.assign(document.createElement("canvas"), { width: 1, height: 1 }).getContext("2d", { willReadFrequently: true }));
    c.clearRect(0, 0, 1, 1);
    c.fillStyle = color;
    c.fillRect(0, 0, 1, 1);
    v = c.getImageData(0, 0, 1, 1).data;
    if (rgbaCache.size > 4096) rgbaCache.clear();
    rgbaCache.set(color, v);
  }
  return v;
}

function drawMap() {
  if (state.tab !== "map" || !mapState.layout) return;
  drawBand();
  const L = mapState.layout, grid = $("#grid"), ctx = grid.getContext("2d");
  const C = cachedColors();
  const dpr = window.devicePixelRatio || 1;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, L.width, L.height);
  // 1) tiles. Large binaries (small tiles, no gaps): one pixel per function in a tiny image, scaled up
  //    by the GPU. 100k+ individual fillRect calls or a full-resolution pixel buffer are too slow.
  if (L.gap === 0) {
    const off = drawMap.off || (drawMap.off = document.createElement("canvas"));
    ctx.imageSmoothingEnabled = false;
    for (const b of L.blocks) {
      if (!b.fns.length) continue;
      off.width = L.cols; off.height = b.rows;
      const octx = off.getContext("2d");
      const img = octx.createImageData(L.cols, b.rows), px = img.data;
      b.fns.forEach((f, i) => {
        const [r, g, bl, a] = rgba(mapColor(f));
        const o = i * 4;
        px[o] = r; px[o + 1] = g; px[o + 2] = bl; px[o + 3] = mapVisible(f) ? a : Math.round(a * 0.12);
      });
      octx.putImageData(img, 0, 0);
      ctx.drawImage(off, 0, b.y0, L.cols * L.step, b.rows * L.step);
    }
  } else {
    for (const b of L.blocks) {
      b.fns.forEach((f, i) => {
        ctx.globalAlpha = mapVisible(f) ? 1 : 0.12;
        ctx.fillStyle = mapColor(f);
        ctx.fillRect((i % L.cols) * L.step, b.y0 + Math.floor(i / L.cols) * L.step, L.tile, L.tile);
      });
    }
    ctx.globalAlpha = 1;
  }
  // 2) labels and the few highlighted tiles on top
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const active = state.lastActive?.db === state.db ? state.lastActive.func : null;
  const running = new Set([...state.running.values()].filter((c) => c.db_id === state.db && c.func).map((c) => c.func));
  ctx.font = "11px " + css("--mono");
  for (const b of L.blocks) {
    ctx.fillStyle = C.muted;
    ctx.fillText(`${b.name}  ${b.fns.length ? b.fns.length + " functions" : ""}${b.start ? "  " + b.start : ""}`, 0, b.y0 - 6);
    b.fns.forEach((f, i) => {
      const hit = mapState.search && mapMatches(f), live = f.start === active || running.has(f.start);
      const mark = f.human && mapState.mode !== "human" && L.tile >= 8;
      if (!hit && !live && !mark) return;
      const x = (i % L.cols) * L.step, y = b.y0 + Math.floor(i / L.cols) * L.step;
      if (hit) { ctx.strokeStyle = C.text; ctx.lineWidth = 1.5; ctx.strokeRect(x - 1, y - 1, L.tile + 2, L.tile + 2); }
      if (live) { ctx.strokeStyle = C.accent; ctx.lineWidth = 2; ctx.strokeRect(x - 2, y - 2, L.tile + 4, L.tile + 4); }
      if (mark) { ctx.fillStyle = C.hu[f.human]; ctx.fillRect(x + L.tile - 3, y, 3, 3); }
    });
  }
}

const drawMapSoon = throttle(() => drawMap(), 500);

function mapHit(ev) {
  const L = mapState.layout;
  if (!L) return null;
  const r = $("#grid").getBoundingClientRect();
  const x = ev.clientX - r.left, y = ev.clientY - r.top;
  for (const b of L.blocks) {
    if (y < b.y0 || y >= b.y0 + b.rows * L.step) continue;
    const col = Math.floor(x / L.step), row = Math.floor((y - b.y0) / L.step);
    if (col >= L.cols) return null;
    return b.fns[row * L.cols + col] || null;
  }
  return null;
}

function drawBand() {
  const c = $("#band"), w = c.parentElement.clientWidth - 28, hgt = 34, dpr = window.devicePixelRatio || 1;
  c.width = w * dpr; c.height = hgt * dpr; c.style.height = hgt + "px";
  const ctx = c.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = css("--panel2"); ctx.fillRect(0, 0, w, hgt);
  const blocks = segmentsForMap().filter((b) => b.fns.length && b.e > b.s);
  const bandSegs = $("#bandSegs");
  fill(bandSegs);
  if (!blocks.length) return;
  // each segment gets width ∝ size, but at least 40px so tiny segments stay visible
  const total = blocks.reduce((a, b) => a + (b.e - b.s), 0);
  const minW = Math.min(40, w / blocks.length / 2);
  const free = w - minW * blocks.length;
  let x = 0;
  const px = [];
  const segX = [];
  for (const b of blocks) {
    const bw = minW + (free * (b.e - b.s)) / total;
    segX.push({ b, x, w: bw });
    bandSegs.append(h("span", { style: { left: `${x}px`, width: `${bw}px` }, title: `${b.name} ${b.start || ""}` }, b.name));
    // per-pixel best stage (highest rank wins)
    const best = new Int8Array(Math.ceil(bw) + 1).fill(-1);
    const bestF = new Array(best.length);
    for (const f of b.fns) {
      if (!mapVisible(f)) continue;
      const a0 = Math.floor(((f.n - b.s) / (b.e - b.s)) * bw);
      const a1 = Math.max(a0, Math.floor(((f.n + (f.size || 1) - b.s) / (b.e - b.s)) * bw));
      const rk = mapState.mode === "stage" ? stageRank(stageOf(f.flags)) : (f.touches ? 5 : f.flags ? 1 : 0);
      for (let p = Math.max(0, a0); p <= Math.min(best.length - 1, a1); p++) if (rk > best[p]) { best[p] = rk; bestF[p] = f; }
    }
    for (let p = 0; p < best.length; p++) {
      if (best[p] < 0) continue;
      ctx.fillStyle = mapColor(bestF[p]);
      ctx.fillRect(x + p, 3, 1, hgt - 6);
      px[Math.floor(x + p)] = bestF[p];
    }
    x += bw;
  }
  mapState.bandPx = px;
  const active = state.lastActive?.db === state.db ? state.funcs.get(state.lastActive.func) : null;
  if (active) {
    const sx = segX.find((s) => active.n >= s.b.s && active.n < s.b.e);
    if (sx) {
      const ax = sx.x + ((active.n - sx.b.s) / (sx.b.e - sx.b.s)) * sx.w;
      ctx.fillStyle = css("--accent"); ctx.fillRect(ax - 1, 0, 3, hgt);
    }
  }
}

function showTip(ev, f) {
  const tip = $("#mapTip");
  if (!f) { tip.hidden = true; return; }
  fill(tip, 
    h("b", null, fnDisplay(f)), suggestionTag(f), h("div", { class: "muted mono small" }, `${f.start}${f.size ? ` · ${f.size} bytes` : ""}`),
    fnDisplay(f) !== f.name ? h("div", { class: "faint small mono raw" }, f.name) : f.dem && f.dem !== f.name ? h("div", { class: "muted small mono" }, f.dem) : null,
    f.orig ? h("div", { class: "faint small" }, `was ${f.orig}`) : null,
    f.summary ? h("div", { class: "tip-summary" }, f.summary, f.annStatus === "confirmed" ? " ✓" : "") : null,
    h("div", null, h("span", { class: "sw", style: { background: stColor(stageOf(f.flags)), marginRight: "5px" } }), STAGE_LABEL[stageOf(f.flags)],
      f.touches ? ` · ${f.touches} calls` : "", f.last ? ` · ${ago(f.last)}` : ""),
    f.human ? h("div", { style: { color: huColor(f.human) } }, "● " + HUMAN_LABEL[f.human]) : null,
    f.note ? h("div", { class: "muted small" }, "has note") : null);
  tip.hidden = false;
  const x = Math.min(ev.clientX + 14, window.innerWidth - 300), y = Math.min(ev.clientY + 14, window.innerHeight - 120);
  tip.style.left = x + "px"; tip.style.top = y + "px";
}

// ------------------------------------------------------------------ graph
const graphState = { cy: null, mode: "touched", layout: "cose", loadedFor: null, data: null };

async function loadGraph(force) {
  const key = `${state.db}:${graphState.mode}`;
  const data = await api(`/api/db/${state.db}/graph?mode=${graphState.mode}`);
  const same = !force && graphState.loadedFor === key && graphState.data &&
    data.nodes.length === graphState.data.nodes.length && data.edges.length === graphState.data.edges.length;
  graphState.data = data;
  graphState.loadedFor = key;
  if (same && graphState.cy) { restyleGraph(); return; }
  buildGraph(data);
}

function nodeData(n) {
  const f = state.funcs.get(n.id);
  const flags = f ? f.flags : n.flags;
  const label = f ? (f.suggested && AUTONAME.test(f.name) ? `${f.suggested}?` : fnDisplay(f)) : n.name;
  return { id: n.id, label: label.length > 44 ? label.slice(0, 42) + "…" : label, stage: stageOf(flags), color: stColor(stageOf(flags)),
    w: 16 + Math.min(34, 7 * Math.log2(1 + (f?.touches ?? n.touches))), frontier: n.frontier ? 1 : 0,
    human: f?.human || n.human || "", hcolor: (f?.human || n.human) ? huColor(f?.human || n.human) : "transparent" };
}

function buildGraph(data) {
  const el = $("#cy");
  if (typeof cytoscape === "undefined") { el.textContent = "cytoscape failed to load"; return; }
  const elements = [
    ...data.nodes.map((n) => ({ data: nodeData(n) })),
    ...data.edges.map(([a, b]) => ({ data: { id: `${a}>${b}`, source: a, target: b } })),
  ];
  const trail = $("#graphTrail").checked ? data.trail : [];
  const ids = new Set(data.nodes.map((n) => n.id));
  const tr = trail.filter((t) => ids.has(t));
  for (let i = 1; i < tr.length; i++) elements.push({ data: { id: `trail${i}`, source: tr[i - 1], target: tr[i], trail: 1, label: String(i) } });
  if (graphState.cy) graphState.cy.destroy();
  const text = css("--text"), line = css("--line2"), accent = css("--accent");
  const cy = graphState.cy = cytoscape({
    container: el, elements, wheelSensitivity: 0.25, minZoom: 0.05, maxZoom: 4,
    style: [
      { selector: "node", style: {
        "background-color": "data(color)", width: "data(w)", height: "data(w)", label: "data(label)",
        color: text, "font-family": css("--mono"), "font-size": 10, "text-valign": "bottom", "text-margin-y": 4,
        "text-outline-color": css("--bg"), "text-outline-width": 2, "border-width": 2, "border-color": "data(hcolor)",
        "min-zoomed-font-size": 7 } },
      { selector: "node[frontier = 1]", style: { "background-opacity": 0.35, "border-width": 1, "border-style": "dashed", "border-color": css("--muted"), color: css("--muted"), label: "", width: 12, height: 12 } },
      { selector: "node.hover", style: { label: "data(label)", "z-index": 99 } },
      { selector: "edge", style: { width: 1.2, "line-color": line, "target-arrow-color": line, "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 } },
      { selector: "edge[trail = 1]", style: { width: 2, "line-color": accent, "target-arrow-color": accent, "line-style": "dashed", label: "data(label)", "font-size": 9, color: accent, "text-background-color": css("--bg"), "text-background-opacity": 1 } },
      { selector: "node.active", style: { "border-color": accent, "border-width": 4, "overlay-color": accent, "overlay-opacity": 0.12, "overlay-padding": 8 } },
      { selector: "node:selected", style: { "border-color": text, "border-width": 3 } },
      { selector: ".dim", style: { opacity: 0.15 } },
    ],
    layout: layoutOpts(),
  });
  cy.on("tap", "node", (e) => openFunction(e.target.id()));
  cy.on("mouseover", "node", (e) => { const nb = e.target.closedNeighborhood(); cy.elements().not(nb).addClass("dim"); nb.nodes().addClass("hover"); });
  cy.on("mouseout", "node", () => cy.elements().removeClass("dim hover"));
  $("#graphInfo").textContent = `${data.nodes.length} functions · ${data.edges.length} call edges` +
    (data.nodes.length && !data.edges.length ? " — no call edges known yet (import the full map or query callers/callees)" : "");
  graphPulse();
}

function layoutOpts() {
  const L = graphState.layout;
  if (L === "breadthfirst") return { name: "breadthfirst", directed: true, spacingFactor: 1.1, animate: false };
  if (L === "concentric") return { name: "concentric", concentric: (n) => stageRank(n.data("stage")), levelWidth: () => 1, animate: false, minNodeSpacing: 20 };
  return { name: "cose", animate: false, nodeRepulsion: () => 16000, idealEdgeLength: () => 90, nodeOverlap: 20, numIter: 1500, randomize: true, padding: 40 };
}

function restyleGraph() {
  const cy = graphState.cy;
  if (!cy) return;
  cy.batch(() => cy.nodes().forEach((n) => {
    const src = graphState.data.nodes.find((x) => x.id === n.id());
    if (src) n.data(nodeData(src));
  }));
  graphPulse();
}

function graphPulse() {
  const cy = graphState.cy;
  if (!cy) return;
  cy.nodes(".active").removeClass("active");
  const ids = [...state.running.values()].filter((c) => c.db_id === state.db && c.func).map((c) => c.func);
  if (state.lastActive?.db === state.db) ids.push(state.lastActive.func);
  let focus = null;
  for (const id of ids) { const n = cy.getElementById(id); if (n.nonempty()) { n.addClass("active"); focus = focus || n; } }
  if (!focus && ids.length && graphState.loadedFor) loadGraph(false);  // new function: refetch graph
  if (focus && $("#graphFollow").checked) cy.animate({ center: { eles: focus }, duration: 300 });
}

// ------------------------------------------------------------------ functions table
const fnState = { sort: store.get("fnSort", "last"), asc: false, stages: new Set(STAGES.slice(1)), human: "", q: "", limit: 500 };

function renderFunctions() {
  const counts = countStages();
  fill($("#fnStages"), ...STAGES.map((s) => h("span", {
    class: "chip" + (fnState.stages.has(s) ? " on" : ""),
    onclick: () => { fnState.stages.has(s) ? fnState.stages.delete(s) : fnState.stages.add(s); fnState.limit = 500; renderFunctions(); },
  }, h("i", { class: "sw", style: { background: stColor(s) } }), `${s} ${counts[s]}`)));
  const q = fnState.q;
  let rows = [...state.funcs.values()].filter((f) => fnState.stages.has(stageOf(f.flags)) &&
    (!fnState.human || (fnState.human === "none" ? !f.human : f.human === fnState.human)) &&
    (!q || fnMatches(f, q)));
  const key = { name: (f) => (fnDisplay(f) || "").toLowerCase(), addr: (f) => f.n, size: (f) => f.size || 0, stage: (f) => stageRank(stageOf(f.flags)) * 1e6 + (f.touches || 0),
    touches: (f) => f.touches || 0, last: (f) => f.last || 0, human: (f) => f.human || "" }[fnState.sort];
  rows.sort((a, b) => { const x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : 0) * (fnState.asc ? 1 : -1); });
  $("#fnCount").textContent = `${rows.length.toLocaleString()} of ${state.funcs.size.toLocaleString()} known functions`;
  $$("#fnTable th").forEach((th) => { th.classList.toggle("sorted", th.dataset.sort === fnState.sort); th.classList.toggle("asc", fnState.asc); });
  const body = $("#fnTable tbody");
  fill(body, ...rows.slice(0, fnState.limit).map((f) => {
    const st = stageOf(f.flags);
    return h("tr", { onclick: () => openFunction(f.start) },
      h("td", null, h("span", { class: "fn" }, h("span", { class: "dot", style: { background: stColor(st) } }), h("span", { class: "fname" }, fnDisplay(f)), suggestionTag(f)),
        f.orig ? h("span", { class: "was" }, `was ${f.orig}`) : null, f.note ? h("span", { class: "faint", title: "has note" }, " ✎") : null,
        fnDisplay(f) !== f.name ? h("div", { class: "dem" }, f.name) : f.dem && f.dem !== f.name ? h("div", { class: "dem" }, f.dem) : null,
        f.summary ? h("div", { class: "fn-summary", title: f.summary }, f.annStatus === "confirmed" ? "✓ " : "", f.summary) : null),
      h("td", { class: "mono muted" }, f.start),
      h("td", { class: "num muted" }, f.size ?? "?"),
      h("td", null, h("span", { class: "badge", style: { background: stColor(st) } }, st)),
      h("td", null, pills(f.flags)),
      h("td", { class: "num" }, f.touches || ""),
      h("td", { class: "muted small" }, ago(f.last)),
      h("td", null, f.human ? h("span", { class: "badge", style: { background: huColor(f.human) } }, HUMAN_LABEL[f.human]) : null));
  }));
  $("#fnMore").hidden = rows.length <= fnState.limit;
}

function pills(flags) {
  return h("span", { class: "pills" }, PILLS.map(([l, bit, title]) => {
    const on = flags & bit;
    const st = bit & ANNOTATED ? "annotated" : bit === F.DECOMP ? "decompiled" : bit === F.XREF ? "explored" : "disassembled";
    return h("span", { class: "pill" + (on ? " on" : ""), title, style: on ? { background: stColor(st) } : null }, l);
  }));
}

// ------------------------------------------------------------------ timeline
const tl = { cats: new Set(), errors: false, q: "", oldestFirst: false, open: new Set(), oldest: null, exhausted: false };

function callVisible(c) {
  if (tl.errors && c.status !== "error") return false;
  if (tl.cats.size && !tl.cats.has(c.category)) return false;
  if (tl.q) {
    const hay = `${c.tool} ${c.target || ""} ${c.func_name || ""} ${c.intent || ""} ${c.error || ""}`.toLowerCase();
    if (!hay.includes(tl.q)) return false;
  }
  return true;
}

function renderTimeline() {
  if (state.tab !== "timeline") return;
  const cats = Object.keys(state.info.categories).concat("other");
  const used = new Set([...state.calls.values()].map((c) => c.category));
  fill($("#tlCats"), ...cats.filter((c) => used.has(c)).map((c) => h("span", {
    class: "chip" + (tl.cats.has(c) ? " on" : ""),
    onclick: () => { tl.cats.has(c) ? tl.cats.delete(c) : tl.cats.add(c); renderTimeline(); },
  }, h("i", { class: "sw", style: { background: catColor(c) } }), c)));

  const calls = [...state.calls.values()].filter(callVisible).sort((a, b) => (tl.oldestFirst ? a.id - b.id : b.id - a.id));
  const root = $("#timeline");
  const out = [];
  let group = undefined, intent = undefined, prev = null;
  for (const c of calls) {
    // Group by user prompt (Claude Code hooks). Harnesses seen only through the
    // proxy have no prompts: group their calls into work bursts per session.
    let key;
    if (c.prompt_id) key = "p:" + c.prompt_id;
    else if (prev && !prev.prompt_id && prev.session_id === c.session_id && Math.abs(c.started_at - prev.started_at) < BURST_GAP) key = group;
    else key = `s:${c.session_id}:${c.id}`;
    prev = c;
    if (key !== group) {
      group = key; intent = undefined;
      out.push(c.prompt_id ? promptHeader(c) : sessionHeader(c));
    }
    if (c.intent && c.intent !== intent) { intent = c.intent; out.push(h("div", { class: "tl-intent" }, c.intent)); }
    out.push(callEl(c));
  }
  if (!out.length) out.push(h("div", { class: "empty" }, state.calls.size ? "No calls match the filters." : "No calls yet."));
  fill(root, ...out);
  $("#tlMore").hidden = tl.exhausted;
}

const BURST_GAP = 300;  // seconds of silence that start a new work block

function harnessTag(name) {
  return name ? h("span", { class: "hn", title: "MCP client" }, name) : null;
}

function promptHeader(c) {
  const p = state.prompts[c.prompt_id];
  return h("div", { class: "tl-prompt", "data-prompt": c.prompt_id },
    h("div", { class: "who" }, "you"),
    h("div", { class: "body" },
      h("div", { class: "faint small" }, p ? dateTime(p.ts) : dateTime(c.started_at), p?.session_id ? ` · session ${p.session_id.slice(0, 8)}` : "", " ", harnessTag(c.harness)),
      h("div", { class: "txt", onclick: (e) => e.currentTarget.classList.toggle("open") },
        p?.text || h("i", { class: "muted" }, "(prompt text unavailable — transcript not readable)"))));
}

function sessionHeader(c) {
  return h("div", { class: "tl-prompt", "data-session": c.session_id },
    h("div", { class: "who", title: c.harness || "" }, (c.harness || "mcp").slice(0, 2)),
    h("div", { class: "body" },
      h("div", { class: "faint small" }, dateTime(c.started_at), ` · session ${c.session_id.replace(/^(stdio|http)-/, "").slice(0, 8)}`, " ", harnessTag(c.harness)),
      h("div", { class: "muted" }, `Work block via ${c.harness || "an MCP client"} — prompts are not visible through the MCP protocol, so calls are grouped by session and time.`)));
}

function callEl(c) {
  const el = h("div", { class: `tl-call ${c.status}`, "data-call": c.id },
    h("div", { class: "row", onclick: () => toggleCall(c.id, el) },
      h("span", { class: "t" }, clock(c.started_at)),
      h("span", { class: "tool", style: { background: catColor(c.category) }, title: c.category }, c.tool),
      h("span", { class: "tgt" }, c.func ? [fnLink(c.func, c.func_name || fnName(c.func)), " "] : null, h("span", { class: "muted" }, c.target || "")),
      h("span", { class: "dur" }, c.status === "running" ? "…" : dur(c.duration_ms)),
      h("span", { class: "st" }, c.status === "running" ? h("span", { class: "spin" }) : c.status === "error" ? "✗" : "✓")),
    c.error ? h("div", { class: "err" }, c.error.split("\n")[0]) : null);
  if (tl.open.has(c.id)) fillCallDetail(c.id, el);
  return el;
}

async function toggleCall(id, el) {
  if (tl.open.has(id)) { tl.open.delete(id); el.querySelector(".tl-detail")?.remove(); return; }
  tl.open.add(id);
  fillCallDetail(id, el);
}

async function fillCallDetail(id, el) {
  const d = await api(`/api/call/${id}`);
  el.querySelector(".tl-detail")?.remove();
  const touched = d.touches.filter((t) => t.func);
  el.append(h("div", { class: "tl-detail" },
    h("div", { class: "lbl" }, "input"), h("pre", { class: "out" }, JSON.stringify(d.input, null, 2)),
    touched.length ? [h("div", { class: "lbl" }, "functions touched"), h("div", { class: "fnchips" },
      [...new Map(touched.map((t) => [t.func + t.role, t])).values()].slice(0, 60).map((t) => h("span", null, fnLink(t.func), h("span", { class: "faint small" }, ` ${t.role === "target" ? t.kind : t.kind}`))))] : null,
    h("div", { class: "lbl" }, d.status === "error" ? "error" : `output · ${(d.output_size || 0).toLocaleString()} bytes`),
    h("pre", { class: "out" }, d.status === "error" ? d.error : highlightMaybe(d.tool, d.output || ""))));
}

function timelineLive(calls) {
  if (state.tab !== "timeline") return;
  // cheap path: replace existing rows in place, full re-render for new ones
  let added = false;
  for (const c of calls) {
    const ex = $(`[data-call="${c.id}"]`);
    if (ex) ex.replaceWith(callEl(c)); else added = true;
  }
  if (added) renderTimeline();
}

async function loadOlder() {
  if (tl.oldest == null) return;
  const cl = await api(`/api/calls?db=${state.db}&before=${tl.oldest}&limit=400`);
  for (const c of cl.calls) state.calls.set(c.id, c);
  Object.assign(state.prompts, cl.prompts);
  if (cl.calls.length) tl.oldest = Math.min(...cl.calls.map((c) => c.id));
  tl.exhausted = cl.calls.length < 400;
  renderTimeline();
}

// ------------------------------------------------------------------ code highlighting
const C_KW = /^(if|else|for|while|do|return|goto|break|continue|switch|case|default|sizeof|struct|union|enum|typedef|const|volatile|static|unsigned|signed|__fastcall|__cdecl|__stdcall|__usercall|__noreturn|LABEL_\d+)$/;
const C_TY = /^(void|char|short|int|long|float|double|bool|_BOOL\d|_BYTE|_WORD|_DWORD|_QWORD|__int\d+|_OWORD|size_t|uint\d+_t|int\d+_t|id|SEL|Class|BOOL|NSString|NSObject)$/;
function highlightC(src) {
  const frag = document.createDocumentFragment();
  const re = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|\b(0x[0-9A-Fa-f]+|\d+)(?:u|LL|i64|ui64)*\b|([A-Za-z_]\w*)/g;
  let last = 0, m;
  while ((m = re.exec(src))) {
    if (m.index > last) frag.append(src.slice(last, m.index));
    let cls = null;
    if (m[1]) cls = "cm"; else if (m[2]) cls = "st2"; else if (m[3]) cls = "nu";
    else if (m[4]) cls = C_KW.test(m[4]) ? "kw" : C_TY.test(m[4]) ? "ty" : null;
    frag.append(cls ? h("span", { class: cls }, m[0]) : m[0]);
    last = m.index + m[0].length;
  }
  frag.append(src.slice(last));
  return frag;
}
function highlightMaybe(tool, text) {
  if (tool === "decompile" && !text.trimStart().startsWith("{")) return highlightC(text);
  if (tool === "decompile") {
    try { const j = JSON.parse(text); if (Array.isArray(j.results)) return highlightC(j.results.map((r) => `// ${r.address}\n${r.decompile || r.error || ""}`).join("\n")); } catch { /* raw */ }
  }
  return text;
}

// ------------------------------------------------------------------ drawer
async function openFunction(start) {
  state.drawerFn = start;
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  await refreshDrawer(true);
}
function closeDrawer() {
  state.drawerFn = null;
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
}

async function refreshDrawer(reset) {
  const start = state.drawerFn;
  if (!start) return;
  let d;
  try { d = await api(`/api/db/${state.db}/function/${start}`); }
  catch { fill($("#drawerBody"), h("div", { class: "empty" }, `Unknown function ${start}`)); return; }
  if (state.drawerFn !== start) return;
  const body = $("#drawerBody");
  const note = body.querySelector("textarea");
  if (!reset && note && document.activeElement === note) {  // don't clobber typing: refresh only history
    return;
  }
  const hs = h("div", { class: "hs" }, HUMAN.map((s) => h("button", {
    class: d.human_status === s ? "on" : "", style: d.human_status === s ? { color: huColor(s) } : null,
    onclick: async () => { const v = d.human_status === s ? null : s; await post(`/api/db/${state.db}/function/${start}`, { human_status: v }); refreshFunctions(); refreshDrawer(true); },
  }, h("span", { class: "dot", style: { background: huColor(s) } }), HUMAN_LABEL[s])));
  const saved = h("div", { class: "saved" }, d.note_updated ? `saved ${ago(d.note_updated)}` : "");
  let tmr = null;
  const ta = h("textarea", { placeholder: "Your notes on this function (what it does, why it matters, next steps)…",
    oninput: () => { clearTimeout(tmr); saved.textContent = "…"; tmr = setTimeout(async () => {
      await post(`/api/db/${state.db}/function/${start}`, { note: ta.value }); saved.textContent = "saved"; refreshFunctions(); }, 600); } });
  ta.value = d.note || "";
  const chips = (list) => list.length ? h("div", { class: "fnchips" }, list.map((f) => fnLink(f.start, f.name))) : h("div", { class: "muted small" }, "none known");
  const REF_LABEL = { str: "Strings", sel: "Objective-C selectors", class: "Objective-C classes", import: "Imported symbols" };
  const refs = Object.entries(d.references || {});

  fill(body,
    h("h2", null, displayName(d.name, d.demangled)),
    displayName(d.name, d.demangled) !== d.name ? h("div", { class: "dem big" }, d.name)
      : d.demangled && d.demangled !== d.name ? h("div", { class: "dem big" }, d.demangled) : null,
    h("div", { class: "meta" },
      h("span", { class: "mono" }, d.start), d.size ? h("span", null, `${d.size} bytes`) : h("span", { class: "faint" }, "size unknown"),
      h("span", { class: "badge", style: { background: stColor(d.stage) } }, d.stage), pills(d.flags),
      h("a", { onclick: (e) => copy(d.start, e.target) }, "copy address")),
    d.orig_name && d.orig_name !== d.name ? h("div", { class: "muted small", style: { marginTop: "4px" } }, "originally ", h("span", { class: "mono" }, d.orig_name)) : null,
    h("div", { class: "muted small", style: { marginTop: "4px" } },
      d.touch_count ? `${d.touch_count} targeted calls · first ${ago(d.first_touched)} · last ${ago(d.last_touched)}` : "never targeted directly"),
    understanding(d, start),
    h("h4", null, "Your review"), hs,
    h("h4", null, "Notes"), ta, saved,
    d.renames.length ? [h("h4", null, "Renames"), h("ul", { class: "list" }, d.renames.map((r) =>
      h("li", null, h("span", { class: "grow mono small" }, h("span", { class: "faint" }, r.old_name || "?"), " → ", r.new_name), h("span", { class: "faint small" }, ago(r.ts)))))] : null,
    d.comments.length ? [h("h4", null, "Comments set"), h("ul", { class: "list" }, d.comments.map((c) =>
      h("li", null, h("span", { class: "mono faint small" }, c.addr), h("span", { class: "grow" }, c.text))))] : null,
    d.strings.length ? [h("h4", null, "Strings seen in xref results"), h("ul", { class: "list" }, d.strings.map((s) => h("li", null, h("span", { class: "grow mono small" }, `"${s}"`))))] : null,
    refs.length ? [h("h4", null, "References"), refs.map(([kind, vals]) => h("div", { class: "refs" },
      h("div", { class: "lbl" }, `${REF_LABEL[kind] || kind} (${vals.length})`),
      h("div", { class: "refchips" }, vals.map((v) => h("span", { class: `ref ref-${kind}`, title: v }, kind === "str" ? `"${v}"` : v)))))] :
      (state.dbs.find((x) => x.id === state.db)?.map_imported_at ? null :
        h("div", { class: "muted small", style: { marginTop: "14px" } }, "Import the full map (Overview) to see the strings, selectors, classes and imports this function references.")),
    h("h4", null, `Callers (${d.callers.length})`), chips(d.callers),
    h("h4", null, `Callees (${d.callees.length})`), chips(d.callees),
    d.decompile ? [h("h4", null, `Latest pseudocode · ${ago(d.decompile.ts)}`), h("pre", { class: "out" }, highlightC(d.decompile.text))] : null,
    h("h4", null, `History (${d.history.length})`),
    h("ul", { class: "list hist" }, d.history.length ? d.history.map((c) => h("li", null,
      h("div", { class: "h1" },
        h("span", { class: "mono faint small" }, clock(c.started_at)),
        h("span", { class: "tool badge", style: { background: catColor(c.category) } }, c.tool),
        h("span", { class: "grow muted small mono" }, c.roles.map((r) => (r.role === "target" ? r.kind : `in ${r.kind} result`)).join(", ")),
        h("span", { class: "faint small" }, c.status === "error" ? "✗" : dur(c.duration_ms))),
      c.intent ? h("div", { class: "intent" }, c.intent.split("\n")[0]) : null)) : h("li", { class: "muted" }, "No calls recorded.")),
  );
}

// ------------------------------------------------------------------ explanations
const CONF_COLOR = { high: "--ok", medium: "--warn", low: "--faint" };
// the feature can be on globally (Settings) or for one client (--annotate-tools), so don't claim it's off
const EXPLAIN_HOWTO = "The LLM records explanations with idamap_annotate when the proxy offers it (Settings ⚙ or idamap proxy --annotate-tools).";

function understanding(d, start) {
  const list = d.explanations || [];
  if (!list.length) {
    return [h("h4", null, "Understanding"), h("div", { class: "muted small" }, "No explanation yet. " + EXPLAIN_HOWTO)];
  }
  return [h("h4", null, `Understanding (${list.length})`), h("div", { class: "expl-list" }, list.map((a, i) => h("div", {
    class: `expl ${a.status}` + (i > 0 ? " older" : ""),
  },
    h("div", { class: "expl-head" },
      h("span", { class: `badge st-${a.status}` }, a.status === "hypothesis" ? "unconfirmed" : a.status),
      a.confidence ? h("span", { class: "conf", style: { color: css(CONF_COLOR[a.confidence]) } }, `${a.confidence} confidence`) : null,
      a.framework ? h("span", { class: "hn" }, a.framework) : null,
      h("span", { class: "grow" }),
      h("span", { class: "faint small" }, `${a.harness || a.source} · ${ago(a.created_at)}`)),
    a.name_suggestion ? h("div", { class: "mono small" }, "suggested name: ", h("b", null, a.name_suggestion)) : null,
    h("div", { class: "expl-summary" }, a.summary),
    a.tags?.length ? h("div", { class: "chips" }, a.tags.map((t) => h("span", { class: "chip" }, t))) : null,
    a.evidence ? h("div", { class: "expl-evidence" }, h("span", { class: "faint" }, "evidence: "), a.evidence) : null,
    h("div", { class: "expl-actions" },
      a.status !== "confirmed" ? h("button", { class: "btn sm ok", onclick: () => review(a.id, "confirmed") }, "✓ Confirm") : null,
      a.status !== "rejected" ? h("button", { class: "btn sm bad", onclick: () => review(a.id, "rejected") }, "✗ Reject") : null,
      a.status !== "hypothesis" ? h("button", { class: "btn sm", onclick: () => review(a.id, "hypothesis") }, "Undo review") : null,
      a.name_suggestion ? h("button", { class: "btn sm", title: "Copy an IDAPython rename line", onclick: (e) =>
        copy(`idc.set_name(${start}, ${JSON.stringify(a.name_suggestion)}, idc.SN_NOWARN)`, e.target) }, "Copy rename") : null),
  )))];
}

async function review(id, status) {
  await post(`/api/db/${state.db}/annotation/${id}`, { status });
  refreshFunctions();
  refreshSummary();
  refreshDrawer(true);
}

// ------------------------------------------------------------------ settings
async function loadConfig() {
  try { const c = await api("/api/config"); state.config = c.values; state.configDesc = c.descriptions; } catch { state.config = {}; }
}

function openSettings() {
  state.drawerFn = null;
  $("#drawer").classList.add("open");
  const cfgRow = (key, title, body) => h("div", { class: "setting" },
    h("label", { class: "toggle big" },
      h("input", { type: "checkbox", checked: !!state.config[key], onchange: async (e) => {
        const r = await post("/api/config", { key, value: e.target.checked });
        state.config = r.values; renderTab(true);
      } }), h("b", null, title)),
    body);
  fill($("#drawerBody"),
    h("h2", null, "Settings"),
    h("div", { class: "muted small" }, "Optional features are off by default."),
    cfgRow("annotate_tools", "LLM explanations (idamap_annotate / idamap_lookup)", [
      h("p", { class: "muted" }, "The idamap proxy offers the LLM two extra tools. idamap_annotate records what the LLM understood about a function (summary, suggested name, tags, framework, confidence, evidence) as an unconfirmed hypothesis you confirm or reject here. idamap_lookup lets it reuse earlier knowledge, so functions are not re-reversed in every session. Nothing is written to the IDA database."),
      h("p", { class: "muted" }, "Needs the proxy (any MCP client): restart your MCP client after changing this. Claude Code hooks alone cannot add tools."),
      h("pre", { class: "out" }, "idamap mcp-config        # client config snippets\nidamap proxy --annotate-tools -- ida-mcp   # force on for one client")]),
    h("h4", null, "Data"),
    h("div", { class: "muted small mono" }, state.info.db_path));
}

// ------------------------------------------------------------------ theme
function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
}
function toggleTheme() {
  const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const next = cur === "light" ? "dark" : "light";
  store.set("theme", next);
  applyTheme(next);
  renderHeader();
  renderTab(true);
}

// ------------------------------------------------------------------ wiring
function wireUi() {
  $("#tabs").addEventListener("click", (e) => { const t = e.target.closest("button")?.dataset.tab; if (t) { showTab(t); renderTab(false); } });
  $("#dbSelect").addEventListener("change", (e) => { $("#followDb").checked = false; selectDb(+e.target.value); });
  $("#followDb").checked = store.get("followDb", true);
  $("#followDb").addEventListener("change", (e) => store.set("followDb", e.target.checked));
  $("#themeBtn").addEventListener("click", toggleTheme);
  $("#settingsBtn").addEventListener("click", async () => { await loadConfig(); openSettings(); });
  $("#drawerClose").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDrawer(); $("#exportMenu").hidden = true; } });
  $("#exportBtn").addEventListener("click", (e) => { e.stopPropagation(); $("#exportMenu").hidden = !$("#exportMenu").hidden; });
  document.addEventListener("click", () => $("#exportMenu").hidden = true);
  $("#exRename").addEventListener("click", async () => {
    const d = state.dbs.find((x) => x.id === state.db);
    const v = prompt("Label for this database (empty resets):", d?.label || d?.name || "");
    if (v === null) return;
    await post(`/api/db/${state.db}`, { label: v });
    await loadDbs(); renderHeader();
  });
  $("#exDelete").addEventListener("click", async () => {
    const d = state.dbs.find((x) => x.id === state.db);
    if (!d || !confirm(`Delete every idamap record for “${d.name}”? (Your IDA database is not touched.)`)) return;
    await fetch(`/api/db/${state.db}`, { method: "DELETE" });
    await loadDbs();
    if (state.dbs.length) selectDb(state.dbs[0].id); else { state.db = null; renderEmpty(); }
  });

  // map
  $$("#mapMode button").forEach((b) => b.classList.toggle("active", b.dataset.mode === mapState.mode));
  $("#mapMode").addEventListener("click", (e) => {
    const m = e.target.closest("button")?.dataset.mode; if (!m) return;
    mapState.mode = m; store.set("mapMode", m);
    $$("#mapMode button").forEach((b) => b.classList.toggle("active", b === e.target));
    renderMapLegend(); drawMap();
  });
  $("#mapSearch").addEventListener("input", (e) => { mapState.search = e.target.value.trim().toLowerCase(); drawMap(); });
  const grid = $("#grid");
  grid.addEventListener("mousemove", (e) => showTip(e, mapHit(e)));
  grid.addEventListener("mouseleave", () => showTip(null, null));
  grid.addEventListener("click", (e) => { const f = mapHit(e); if (f) openFunction(f.start); });
  const band = $("#band");
  const bandHit = (e) => { const r = band.getBoundingClientRect(); const x = Math.floor(e.clientX - r.left); return mapState.bandPx?.[x] || mapState.bandPx?.[x - 1] || mapState.bandPx?.[x + 1]; };
  band.addEventListener("mousemove", (e) => showTip(e, bandHit(e)));
  band.addEventListener("mouseleave", () => showTip(null, null));
  band.addEventListener("click", (e) => { const f = bandHit(e); if (f) openFunction(f.start); });
  window.addEventListener("resize", throttle(() => { if (state.tab === "map") { layoutMap(); drawMap(); } }, 200));

  // graph
  $("#graphMode").addEventListener("click", (e) => {
    const m = e.target.closest("button")?.dataset.mode; if (!m) return;
    graphState.mode = m; $$("#graphMode button").forEach((b) => b.classList.toggle("active", b === e.target)); loadGraph(true);
  });
  $("#graphLayout").addEventListener("click", (e) => {
    const l = e.target.closest("button")?.dataset.layout; if (!l) return;
    graphState.layout = l; $$("#graphLayout button").forEach((b) => b.classList.toggle("active", b === e.target));
    graphState.cy?.layout(layoutOpts()).run();
  });
  $("#graphTrail").addEventListener("change", () => loadGraph(true));
  $("#graphFit").addEventListener("click", () => graphState.cy?.fit(undefined, 30));
  const gl = $("#graphLegend");
  fill(gl, ...STAGES.slice(1).reverse().map((s) => h("span", null, h("i", { class: "sw", style: { background: stColor(s) } }), s)),
    h("span", null, h("i", { class: "sw", style: { border: `1px dashed ${css("--muted")}` } }), "unexplored"));

  // functions
  $("#fnSearch").addEventListener("input", throttle((e) => { fnState.q = e.target.value.trim().toLowerCase(); fnState.limit = 500; renderFunctions(); }, 150));
  $("#fnHuman").append(...HUMAN.map((s) => h("option", { value: s }, HUMAN_LABEL[s])), h("option", { value: "none" }, "not reviewed"));
  $("#fnHuman").addEventListener("change", (e) => { fnState.human = e.target.value; renderFunctions(); });
  $$("#fnTable th[data-sort]").forEach((th) => th.addEventListener("click", () => {
    if (fnState.sort === th.dataset.sort) fnState.asc = !fnState.asc; else { fnState.sort = th.dataset.sort; fnState.asc = th.dataset.sort === "name" || th.dataset.sort === "addr"; }
    store.set("fnSort", fnState.sort); renderFunctions();
  }));
  $("#fnMore").addEventListener("click", () => { fnState.limit += 1000; renderFunctions(); });

  // timeline
  $("#tlSearch").addEventListener("input", throttle((e) => { tl.q = e.target.value.trim().toLowerCase(); renderTimeline(); }, 150));
  $("#tlErrors").addEventListener("change", (e) => { tl.errors = e.target.checked; renderTimeline(); });
  $("#tlOldest").addEventListener("change", (e) => { tl.oldestFirst = e.target.checked; renderTimeline(); });
  $("#tlMore").addEventListener("click", loadOlder);
}

boot().catch((e) => { document.body.append(h("pre", { class: "out", style: { margin: "20px" } }, "idamap failed to start: " + e.stack)); });
