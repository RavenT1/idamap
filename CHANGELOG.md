# Changelog

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
