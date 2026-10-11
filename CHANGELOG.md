# Changelog

## Unreleased

- **Security hardening** (from a review before going public):
  - The HTTP proxy now validates `Host` and `Origin` (loopback only) and caps request bodies. Before, it forwarded
    everything and rewrote `Host` for ida-mcp, which also hid DNS-rebinding attempts from ida-mcp itself.
  - The web UI sends a strict Content-Security-Policy, `X-Frame-Options: DENY` and related headers, caps request
    bodies, and has an optional access token (`idamap serve --token`; always on with a non-loopback `--host`).
  - `~/.idamap` and the database are created readable by you only; a world-readable default directory from an
    earlier version is tightened.
  - The error logs (`hook_errors.log`, `proxy_errors.log`) are readable by you only, rotate at 1 MB and no longer
    contain the hook event (your prompt and the binary's output); they say what failed and for which tool.
  - Markdown logs HTML-escape text that comes from binaries and models; the IDA sync script title can no longer
    carry line breaks.
  - Model-facing answers and the usage hint say that names, strings and earlier explanations are data, not instructions.
  - CI: read-only token permissions, actions pinned to commit SHAs, Dependabot; `SECURITY.md`; provenance and
    SHA-256 of the vendored Cytoscape.js (verified against the npm package).

- **Guidance followed** (Overview card): counts from the recorded calls whether the model did what idamap's tools
  ask: started with `idamap_status`, looked a function up before analyzing it, explained what it analyzed, searched
  with `idamap_search` instead of a guessed `list_functions` filter, and how many already-explained functions it
  re-analyzed without a lookup. Per-session breakdown included; API: `/api/db/<id>/compliance`.
- The proxy records whether it offered idamap's tools to a session (`sessions.tools_offered`, schema v4), so
  sessions where the tools were off are not counted against the model.

## 0.3.0

- **Navigate the binary (opt-in, with the idamap tools)**: `idamap_search` (coverage-aware search by name, string,
  import, selector, class or explanation; optional "unexplored only") and `idamap_status` (coverage by stage,
  last inspected, where to look next). Both are answered by idamap.
- **App-bundle awareness**: reads `Info.plist` / `Frameworks/`, maps imported symbols to the framework that
  provides them and tells the model (and the UI: Overview card, function panel) which sibling binary holds the
  implementation and whether it was analyzed.
- **Automatic indexing** (`auto_map`, on by default, only with the tools on): the first search / status call makes
  the proxy run idamap's read-only export script in ida-mcp. Disable with `idamap config auto_map off`.
- `idamap_lookup` now shows callers / callees with addresses and framework hints for tiny import stubs.
- The proxy can now make its own upstream calls over stdio and Streamable HTTP; replies to them never reach the client.
- Export script marker is parsed even when the path contains spaces; `idamap_*` calls no longer create a
  placeholder database before a binary is open.

## 0.2.0

- **Any MCP client**: `idamap proxy` wraps ida-mcp over stdio (`idamap proxy -- ida-mcp`) or sits in front of
  `ida-mcp serve-http`, so Cursor, Codex, Claude Desktop, VS Code, Gemini CLI, Windsurf, … are recorded.
  Supports the MCP `initialize` handshake and handshake-free MCP 2026 (`_meta` clientInfo).
- `idamap mcp-config` prints ready-to-paste client configurations with absolute paths.
- Calls seen by both a Claude Code hook and the proxy are recorded once.
- **LLM explanations (opt-in)**: with `idamap config annotate_tools on` (or `--annotate-tools`) the proxy offers
  `idamap_annotate` / `idamap_lookup`. The model records what it understood about a function; you confirm or
  reject it in the UI; later sessions and other clients can read it back.
- Full-map export now includes demangled Swift / C++ names, IDA library flags and, per function, the strings,
  Objective-C selectors / classes and imported symbols it references.
- UI: client (harness) shown per session and call, prompt-less sessions grouped into work blocks, demangled
  names, explanations, references, settings panel.
- Security: the web UI rejects foreign `Host` headers (DNS rebinding) and cross-origin / non-JSON writes.
- **One record per binary**: IDBs of the same input (same SHA-256) share one research record, so re-creating
  or moving an IDB keeps history, notes and explanations. Existing split records are merged on upgrade.
- LLM-suggested names are shown next to IDA auto-names (`sub_…  bc_program_exec?`) until you rename.
- Large binaries: gzip for big API responses (full function list of a 115k-function app: 13 MB → 1.3 MB) and a
  much faster coverage map (≈90 ms redraw for 115k functions, live redraws throttled).
- Default UI port is now 8777 (8765 is `ida-mcp serve-http`'s default).
- The proxy exits cleanly with ida-mcp's exit code if ida-mcp dies, recording in-flight calls as failed.

## 0.1.0

- Claude Code hooks record every ida-mcp call; live web UI with coverage map, call graph, functions table,
  timeline (prompt → intent → calls), per-function review status and notes.
- IDAPython full-map exporter, Markdown research log, IDA coverage sync script.
