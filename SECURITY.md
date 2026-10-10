# Security policy

## Reporting a vulnerability

Please report security problems **privately**: use *Report a vulnerability* on the repository's **Security** tab
(GitHub private vulnerability reporting) rather than a public issue. Include what you did, what you expected and what
happened; a proof of concept helps. This is a small project maintained in spare time, so replies are best effort.

## What is in scope

idamap runs on your machine next to IDA and an MCP client. These parts are in scope:

- the web UI and its API (`idamap serve`)
- the MCP proxy (`idamap proxy`), including the HTTP mode
- the Claude Code hooks and `idamap install`
- the exports (Markdown log, IDA sync script, the export script that runs inside IDA)
- how the local database (`~/.idamap`) is created and protected

Out of scope: vulnerabilities in IDA Pro, ida-mcp-rs or an MCP client themselves (report those to their authors).

## Things worth knowing

- The database holds decompiled code, strings and notes from the binaries you analyse. `~/.idamap` is created
  readable by you only.
- The UI listens on `127.0.0.1` without a login, so any local user or process on the same machine can reach it. On a
  shared machine start it with `idamap serve --token`. A non-loopback `--host` always requires the token.
- Everything the UI and the tools show about a binary (names, strings) or about earlier work (model-written
  explanations) is untrusted input. The model-facing tools say so, but a model can still be steered by text it
  reads; keep explanations unconfirmed until you have reviewed them.
- The HTTP proxy puts a new port in front of ida-mcp, which can run code in IDA. It accepts only loopback `Host` and
  `Origin` values. Do not expose it beyond localhost.
