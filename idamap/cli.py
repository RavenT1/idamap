"""idamap command line."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import __version__
from . import store as S

HOOK_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")
MARK = "idamap.hook"


def _settings_path(scope: str, project_dir: str | None) -> Path:
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    base = Path(project_dir or os.getcwd()).resolve()
    return base / ".claude" / ("settings.json" if scope == "project" else "settings.local.json")


def _hook_command() -> str:
    """Command Claude Code runs; works whether idamap is installed or run from source."""
    py = sys.executable
    probe = subprocess.run([py, "-c", "import idamap"], cwd="/", capture_output=True)
    if probe.returncode == 0:
        return f'"{py}" -m {MARK}'
    src = Path(__file__).resolve().parent.parent
    return f'PYTHONPATH="{src}" "{py}" -m {MARK}'


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text() or "{}")


def _strip_ours(settings: dict) -> dict:
    hooks = settings.get("hooks") or {}
    for ev in list(hooks):
        groups = []
        for g in hooks[ev]:
            kept = [h for h in g.get("hooks", []) if MARK not in str(h.get("command", ""))]
            if kept:
                groups.append({**g, "hooks": kept})
        if groups:
            hooks[ev] = groups
        else:
            del hooks[ev]
    if hooks:
        settings["hooks"] = hooks
    else:
        settings.pop("hooks", None)
    return settings


def _write(path: Path, settings: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".idamap.bak"))
    path.write_text(json.dumps(settings, indent=2) + "\n")


def cmd_install(a) -> int:
    path = _settings_path(a.scope, a.project_dir)
    settings = _strip_ours(_load(path))
    cmd = _hook_command()
    hooks = settings.setdefault("hooks", {})
    for ev in HOOK_EVENTS:
        hooks.setdefault(ev, []).append(
            {"matcher": a.matcher, "hooks": [{"type": "command", "command": cmd, "timeout": 20}]})
    _write(path, settings)
    print(f"idamap hooks installed in {path}")
    print(f"  matcher: {a.matcher}\n  command: {cmd}")
    print("Restart Claude Code (or open /hooks) so the new hooks are picked up.")
    return 0


def cmd_uninstall(a) -> int:
    path = _settings_path(a.scope, a.project_dir)
    if not path.exists():
        print(f"nothing to do: {path} does not exist")
        return 0
    _write(path, _strip_ours(_load(path)))
    print(f"idamap hooks removed from {path}")
    return 0


def cmd_serve(a) -> int:
    from .server import serve

    serve(a.host, a.port, a.open, a.token)
    return 0


def cmd_status(a) -> int:
    from . import queries as Q

    print(f"idamap {__version__}")
    print(f"database : {S.db_path()}")
    for scope in ("user", "project", "local"):
        p = _settings_path(scope, a.project_dir)
        on = p.exists() and MARK in p.read_text()
        print(f"hooks    : {scope:<7} {'installed' if on else '-':<10} {p}")
    from . import config

    for k, v in config.load().items():
        print(f"setting  : {k} = {'on' if v is True else 'off' if v is False else v}")
    print("proxy    : route any MCP client through `idamap proxy -- ida-mcp` (see `idamap mcp-config`)")
    conn = S.connect()
    for d in Q.databases(conn):
        total = d["func_total"] or d["known"]
        print(f"  [{d['id']}] {d['name']:<30} calls={d['calls']:<5} touched={d['touched']}/{total} "
              f"decompiled={d['decompiled']} annotated={d['annotated']}")
    log = S.home() / "hook_errors.log"
    if log.exists() and log.stat().st_size:
        print(f"hook errors logged: {log} (last modified {time.ctime(log.stat().st_mtime)})")
    return 0


def cmd_import(a) -> int:
    from . import ingest

    conn = S.connect()
    r = ingest.import_export(conn, a.file, a.db)
    print(f"imported {r['functions']} functions, {r['edges']} edges into database #{r['db_id']}")
    return 0


def _emit(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text)
        print(f"written {out}")
    else:
        sys.stdout.write(text)


def cmd_report(a) -> int:
    from . import report

    _emit(report.markdown(S.connect(), a.db), a.output)
    return 0


def cmd_ida_sync(a) -> int:
    from . import report

    _emit(report.ida_sync_script(S.connect(), a.db), a.output)
    return 0


def cmd_export_script(a) -> int:
    print(Path(__file__).resolve().parent / "ida_scripts" / "export_map.py")
    return 0


def cmd_proxy(a) -> int:
    from . import config, proxy

    virtual = config.get("annotate_tools") if a.annotate_tools is None else a.annotate_tools
    if a.listen or a.upstream:
        if not (a.listen and a.upstream):
            sys.stderr.write("idamap proxy: --listen and --upstream go together\n")
            return 2
        return proxy.run_http(a.listen, a.upstream, a.harness, virtual)
    cmd = list(a.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if cmd and not shutil.which(cmd[0]) and not Path(cmd[0]).exists():
        sys.stderr.write(f"idamap proxy: '{cmd[0]}' not found. Pass the full path, e.g. idamap proxy -- /path/to/ida-mcp\n")
        return 127
    proxy.exit_now(proxy.run_stdio(cmd, a.harness, virtual))
    return 0  # unreachable


def cmd_config(a) -> int:
    from . import config

    if a.key is None:
        for k, v in config.load().items():
            print(f"{k:<16} {'on' if v is True else 'off' if v is False else v}   # {config.DESCRIPTIONS.get(k, '')}")
        print(f"\n(file: {S.home() / 'config.json'})")
        return 0
    if a.key not in config.DEFAULTS:
        sys.stderr.write(f"unknown setting {a.key!r}; known: {', '.join(config.DEFAULTS)}\n")
        return 2
    if a.value is None:
        print(config.get(a.key))
        return 0
    val = a.value.lower()
    if val not in ("on", "off", "true", "false", "1", "0", "yes", "no"):
        sys.stderr.write("value must be on or off\n")
        return 2
    config.set_value(a.key, val in ("on", "true", "1", "yes"))
    print(f"{a.key} = {'on' if config.get(a.key) else 'off'}")
    if a.key == "annotate_tools":
        print("Takes effect for proxies started from now on (restart your MCP client).")
    return 0


def _proxy_argv() -> list[str]:
    """Absolute command for MCP client configs (GUI apps don't inherit your shell PATH)."""
    exe = shutil.which("idamap")
    ida = shutil.which("ida-mcp") or "ida-mcp"
    head = [exe] if exe else [sys.executable, "-m", "idamap"]
    return head + ["proxy", "--", ida]


def cmd_mcp_config(a) -> int:
    argv = _proxy_argv()
    cmd, args = argv[0], argv[1:]
    env = {} if shutil.which("idamap") or _importable() else {"PYTHONPATH": str(Path(__file__).resolve().parent.parent)}
    std = {"command": cmd, "args": args, **({"env": env} if env else {})}
    blocks = {
        "claude-code": ("claude mcp add (shell)",
                        "claude mcp add ida -- " + " ".join(_q(x) for x in argv)
                        + "".join(f" -e {k}={_q(v)}" for k, v in env.items())),
        "cursor": ("~/.cursor/mcp.json  (or .cursor/mcp.json in a project)",
                   json.dumps({"mcpServers": {"ida": std}}, indent=2)),
        "claude-desktop": ("~/Library/Application Support/Claude/claude_desktop_config.json",
                           json.dumps({"mcpServers": {"ida": std}}, indent=2)),
        "windsurf": ("~/.codeium/windsurf/mcp_config.json", json.dumps({"mcpServers": {"ida": std}}, indent=2)),
        "omp": ("~/.omp/agent/mcp.json  (or set PI_CODING_AGENT_DIR)", json.dumps({"mcpServers": {"ida": std}}, indent=2)),
        "gemini": ("~/.gemini/settings.json", json.dumps({"mcpServers": {"ida": std}}, indent=2)),
        "vscode": (".vscode/mcp.json", json.dumps({"servers": {"ida": {"type": "stdio", **std}}}, indent=2)),
        "codex": ("~/.codex/config.toml",
                  "[mcp_servers.ida]\n" + f"command = {json.dumps(cmd)}\n" + f"args = {json.dumps(args)}\n"
                  + (f"env = {{ {', '.join(f'{k} = {json.dumps(v)}' for k, v in env.items())} }}\n" if env else "")),
        "http": ("any client that speaks Streamable HTTP",
                 "ida-mcp serve-http --bind 127.0.0.1:8765 &\n"
                 "idamap proxy --listen 127.0.0.1:8766 --upstream http://127.0.0.1:8765/\n"
                 "# point the client at http://127.0.0.1:8766/"),
    }
    names = list(blocks) if a.client == "all" else [a.client]
    for n in names:
        where, text = blocks[n]
        print(f"# {n} — {where}\n{text}\n")
    print("# Existing ida-mcp arguments (e.g. --workspace, --read-only) go after the ida-mcp path.")
    return 0


def _importable() -> bool:
    return subprocess.run([sys.executable, "-c", "import idamap"], cwd="/", capture_output=True).returncode == 0


def _q(s: str) -> str:
    import shlex

    return shlex.quote(s)


def cmd_hook(a) -> int:
    from .hook import main

    return main()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="idamap", description="Record and visualise LLM-driven ida-mcp reversing.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="start the web UI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8777)
    s.add_argument("--open", action="store_true", help="open the browser")
    s.add_argument("--token", action="store_true",
                   help="require a random token (kept in a cookie) for every request; always on with a non-loopback --host")
    s.set_defaults(fn=cmd_serve)

    for name, fn, hlp in (("install", cmd_install, "add Claude Code hooks"),
                          ("uninstall", cmd_uninstall, "remove Claude Code hooks")):
        s = sub.add_parser(name, help=hlp)
        s.add_argument("--scope", choices=["user", "project", "local"], default="user",
                       help="user: ~/.claude/settings.json (all projects); project/local: <dir>/.claude/")
        s.add_argument("--project-dir", help="project directory for project/local scope (default: cwd)")
        if name == "install":
            s.add_argument("--matcher", default="mcp__ida.*",
                           help="tool-name regex; adjust if your ida-mcp server is registered under another name")
        s.set_defaults(fn=fn)

    s = sub.add_parser("status", help="show hook install state and recorded databases")
    s.add_argument("--project-dir")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("import", help="import a full map JSON produced by export_map.py")
    s.add_argument("file")
    s.add_argument("--db", type=int, help="target database id (default: match by idb path / sha256)")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("report", help="Markdown research log for a database")
    s.add_argument("db", type=int)
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("ida-sync", help="IDAPython script that paints coverage into IDA")
    s.add_argument("db", type=int)
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_ida_sync)

    s = sub.add_parser("export-script", help="print path of the IDAPython full-map exporter")
    s.set_defaults(fn=cmd_export_script)

    s = sub.add_parser("proxy", help="transparent MCP proxy in front of ida-mcp (works with any MCP client)",
                       description="stdio:  idamap proxy -- ida-mcp [ida-mcp args]\n"
                                   "http:   idamap proxy --listen 127.0.0.1:8766 --upstream http://127.0.0.1:8765/",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("--listen", help="HTTP mode: address to listen on (host:port)")
    s.add_argument("--upstream", help="HTTP mode: URL of `ida-mcp serve-http`")
    s.add_argument("--harness", help="label for the client (default: from MCP clientInfo)")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--annotate-tools", dest="annotate_tools", action="store_true", default=None,
                   help="offer idamap_annotate / idamap_lookup to the LLM (default: `idamap config annotate_tools`)")
    g.add_argument("--no-annotate-tools", dest="annotate_tools", action="store_false")
    s.add_argument("command", nargs=argparse.REMAINDER, help="stdio mode: server command (default: ida-mcp)")
    s.set_defaults(fn=cmd_proxy)

    s = sub.add_parser("config", help="show or change settings (optional features are off by default)")
    s.add_argument("key", nargs="?")
    s.add_argument("value", nargs="?", help="on | off")
    s.set_defaults(fn=cmd_config)

    s = sub.add_parser("mcp-config", help="print MCP client config snippets that route ida-mcp through idamap")
    s.add_argument("--client", default="all",
                   choices=["all", "claude-code", "cursor", "claude-desktop", "windsurf", "omp", "gemini", "vscode", "codex", "http"])
    s.set_defaults(fn=cmd_mcp_config)

    s = sub.add_parser("hook", help="hook entry point (reads a Claude Code hook event on stdin)")
    s.set_defaults(fn=cmd_hook)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
