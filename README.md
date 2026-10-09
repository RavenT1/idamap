# idamap

**See what your LLM is doing in IDA.** idamap records every [ida-mcp](https://github.com/blacktop/ida-mcp-rs)
tool call your LLM makes and turns it into a live map of the reverse-engineering work: what was looked at, what
is running right now, and what is still unexplored.

> [!IMPORTANT]
> **Install [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) first.** idamap does not include or install it:
> it only sits in front of ida-mcp as a proxy. Set up ida-mcp-rs (and what it requires, such as IDA Pro) by
> following its README, and check that it works on its own before adding idamap.

![Overview: coverage, focus trail with the LLM's suggested names, tool usage](docs/overview.jpg)

An independent project, not affiliated with or endorsed by blacktop or Hex-Rays. Türkçe: [README.tr.md](README.tr.md)

## Why

An LLM driving IDA fires several tool calls a second, what it understood about a function disappears when the chat
ends, and the next session starts from scratch. idamap keeps a durable record of that work:

- **Coverage map**: which functions were reversed and how deep (`seen` → `explored` → `disassembled` →
  `decompiled` → `annotated`), plus a live "now" bar and a searchable functions table.
- **Call graph**: the functions worked on, the order they were explored in, and the unexplored neighbours.
- **Timeline**: your prompt → what the model said it would do → the calls it made, with inputs and outputs.
- **Function panel**: renames, comments, LLM explanations, referenced strings / imports, callers / callees, and your
  own review status and notes.

<table>
<tr><td><img src="docs/call-graph.jpg" alt="Call graph with exploration order"></td>
<td><img src="docs/function-panel.jpg" alt="Function panel with an LLM explanation to confirm or reject"></td></tr>
<tr><td><img src="docs/timeline.jpg" alt="Timeline with an idamap_annotate call expanded"></td>
<td><img src="docs/coverage-map.jpg" alt="Coverage map"></td></tr>
</table>

## Install

Requires Python ≥ 3.10 (no other dependencies) and a working [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs).

```sh
uv tool install git+https://github.com/RavenT1/idamap      # or: pipx install git+https://github.com/RavenT1/idamap
idamap serve --open                                         # http://127.0.0.1:8777
```

## Connect your MCP client

Replace the command your client uses to start ida-mcp with `idamap proxy -- ida-mcp`. `idamap mcp-config` prints
ready-made configs with absolute paths (`--client claude-code | cursor | claude-desktop | windsurf | gemini |
vscode | codex | http`):

```json
{ "mcpServers": { "ida": { "command": "/Users/you/.local/bin/idamap",
                           "args": ["proxy", "--", "/opt/homebrew/bin/ida-mcp"] } } }
```

Existing ida-mcp arguments (`--workspace`, `--read-only`, …) go after the ida-mcp path. For clients that connect over
HTTP, put the proxy in front of `ida-mcp serve-http`:

```sh
ida-mcp serve-http --bind 127.0.0.1:8765
idamap proxy --listen 127.0.0.1:8766 --upstream http://127.0.0.1:8765/
```

**Claude Code (optional, richer):** `idamap install` adds hooks to `~/.claude/settings.json` (restart Claude Code;
`idamap uninstall` removes them). Hooks also capture your prompt and what the model wrote before each call, which
MCP does not carry. Hooks and the proxy can be combined; each call is recorded once.

## Map the whole binary

By default idamap only knows the functions the LLM touched. To map everything (all functions, call edges, names,
and what each function references), have the LLM run `run_script(file="<path printed by: idamap export-script>")`,
or run that script in the IDA GUI and then `idamap import <json>`. With the tools below, idamap does this itself.

## Help the LLM navigate (optional, off by default)

```sh
idamap config annotate_tools on       # or per client: idamap proxy --annotate-tools -- ida-mcp
```

idamap adds four tools and a short usage hint to ida-mcp's MCP responses and answers the tools itself from its
local database (nothing is written to the IDA database). Restart the MCP client after changing the setting.

- **`idamap_search`**: coverage-aware search by name, string, import, selector, class or earlier explanation; can
  list only functions nobody has worked on yet.
- **`idamap_status`**: coverage by stage, what was inspected last, where to look next, and the app bundle.
- **`idamap_lookup`**: before analyzing a function, what is already known: explanations, your notes, renames,
  callers and callees.
- **`idamap_annotate`**: after analyzing a function, the model records a summary, a suggested name, tags,
  confidence and evidence.

Explanations are stored as **unconfirmed hypotheses**; you confirm or reject them in the function panel, and they
carry over between sessions and clients. Model-written notes are untrusted input: a malicious binary can try to
steer them, which is why they stay unconfirmed until you review them.

**Is the model using them?** The Overview's *Guidance followed* card counts, from the recorded calls, how often a
session started with `idamap_status`, looked a function up before analyzing it, explained what it analyzed and
searched with `idamap_search`, and how many already-explained functions it re-analyzed without a lookup. It is a
count, not a score, and covers only sessions where the tools were offered.

**App bundles.** In an `.app` / IPA the interesting code is often in a framework. idamap reads `Info.plist` and
`Frameworks/`, maps imported symbols to the framework that provides them, and tells the model which binary holds
the code and whether it was analyzed.

**Automatic indexing (`auto_map`, on by default with the tools).** Search and status need the whole binary
indexed, so the first call that needs it makes the proxy send one read-only `run_script` to ida-mcp (it writes one
JSON file under `~/.idamap/exports`; it appears as `idamap_map` in the timeline). To stop idamap from sending any
request to ida-mcp on its own: `idamap config auto_map off`.

## Export

- **Markdown research log**: `Export` menu or `idamap report <db-id>`.
- **IDA coverage sync script**: `Export` menu or `idamap ida-sync <db-id>`; colours functions by stage and adds an
  `[idamap]` comment in IDA. `CLEAR = True` removes it.

## How it works

```
any MCP client ──▶ idamap proxy ──▶ ida-mcp
                      │ queue + recorder thread
Claude Code ──hooks──▶ idamap hook ──┴──▶ ~/.idamap/idamap.db (SQLite)
                                                 ▲ poll
                                   idamap serve ──SSE──▶ browser
```

The proxy forwards bytes first and records on the side, so a parsing or database problem never delays or alters
the MCP stream. Records are **per binary**: another IDB of the same input (same SHA-256) continues the same record.

## Security and privacy

- Everything stays on your machine (`~/.idamap/`, or `IDAMAP_HOME`). idamap makes no network requests.
- The UI binds to `127.0.0.1` and rejects foreign `Host` headers and cross-origin writes. `idamap serve --host
  0.0.0.0` exposes your research data to your network.
- The database contains tool output (pseudocode, strings) from the binaries you analyze. Treat it like the IDA
  database itself.

## Compatibility

| | Status |
|---|---|
| macOS + ida-mcp-rs + **Claude Code**, **Codex CLI**, **omp** | tested end to end with real sessions |
| Linux, Python 3.10 and 3.13 | unit tests pass (fake ida-mcp); not tested with real IDA |
| Windows | not tested |
| Other MCP clients (Cursor, Claude Desktop, VS Code, Gemini CLI, …) | expected to work (standard MCP over stdio and Streamable HTTP), not verified |
| Other IDA MCP servers (e.g. mrexodia/ida-pro-mcp, Hex-Rays' own) | not tested; tool names may differ |

Reports and fixes for other setups are welcome.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Nothing appears | `idamap status`; restart the MCP client after changing its config; see `~/.idamap/*_errors.log` |
| Client can't start the server | use absolute paths (`idamap mcp-config` prints them) |
| Client shows as `mcp-client` | set a label: `idamap proxy --harness myclient -- ida-mcp` |
| Coverage shows only a few functions | map the whole binary (see above) |

## Development and credits

`python -m unittest discover -s tests -t .` (fake stdio and Streamable-HTTP MCP servers check that the proxy is
byte-transparent).

idamap exists because of [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) by blacktop, the headless IDA Pro MCP
server it accompanies, and the [Model Context Protocol](https://modelcontextprotocol.io).

## License

MIT. `idamap/web/vendor/cytoscape.min.js` is Cytoscape.js (MIT, © The Cytoscape Consortium).
