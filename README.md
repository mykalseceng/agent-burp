# agent-burp

`agent-burp` is a standalone CLI for driving Burp Suite through the bundled Burp extension in `burp-extension/`.

The goal is direct LLM-to-Burp execution through a stable CLI contract, without an MCP server translation layer in the middle.

It is built for:

- any LLM that can run shell commands
- plain Bash scripts and CI
- local, deterministic JSON output (`--json`)

## Why CLI-first (no MCP middle layer)

- This follows the same practical direction as [Vercel's agent-browser](https://github.com/vercel-labs/agent-browser): make a native CLI that AI agents can call directly.
- LLMs already know how to call shell tools; CLIs are agent-native.
- No MCP server process means fewer moving parts and less protocol overhead.
- Large traffic/results can stay on disk or in Burp state instead of bloating model context.
- The same command surface works for agents, humans, and CI pipelines.
- JSON output keeps tool calls deterministic and composable in larger automations.
- **This is still experimental research: large tool outputs can still blow the model context window, and this setup is intentionally being iterated for token-efficiency tradeoffs.**

## Architecture

`agent-burp` uses a local client-daemon model (still no MCP server required):

1. CLI command parses/validates args.
2. CLI talks to local daemon over Unix socket.
3. Daemon keeps a persistent WebSocket connection to the bundled Burp extension (`ws://127.0.0.1:8198` by default).
4. Daemon sends JSON-RPC methods directly to the Burp extension (`send_request`, `get_proxy_history`, etc.).

## Build

Build the Burp extension JAR:

```bash
cd /path/to/agent-burp/burp-extension
./gradlew build
```

The JAR is created at:

```text
burp-extension/build/libs/agent-burp-extension-1.4.0.jar
```

Build the Go CLI:

```bash
cd /path/to/agent-burp
go mod tidy
go build -o agent-burp ./cmd/agent-burp
```

## Load Burp Extension

1. Open Burp Suite.
2. Go to Extensions > Installed.
3. Click Add.
4. Select `burp-extension/build/libs/agent-burp-extension-1.4.0.jar`.
5. Confirm the extension output shows `agent-burp extension loaded`.

The extension opens a local WebSocket server on port `8198` by default. The Go daemon connects to that WebSocket directly; the TypeScript MCP server from the original bridge is not part of this repository and is not required.

## Install (macOS)

Install globally so `agent-burp` can be run from any directory:

```bash
cd /path/to/agent-burp
./install.sh
```

Optional custom install dir (no default path change):

```bash
TARGET_DIR="$HOME/.local/bin" ./install.sh
```

Uninstall:

```bash
./uninstall.sh
```

## Quick start

```bash
./agent-burp doctor --json
./agent-burp open --json
./agent-burp request --url https://example.com --json
./agent-burp history --domain example.com --limit 10 --json
```

## Config

Config precedence (low to high):

1. `~/.agent-burp/config.json`
2. `./agent-burp.json`
3. env vars
4. CLI flags

Example config:

```json
{
  "burpWsUrl": "ws://127.0.0.1:8198",
  "burpAuthToken": "",
  "requestTimeoutMs": 30000,
  "daemonSocketPath": "/Users/me/.agent-burp/run/daemon.sock",
  "output": "json",
  "debug": false,
  "logPath": "/Users/me/.agent-burp/logs/daemon.log"
}
```

Env vars:

- `AGENT_BURP_WS_URL`
- `AGENT_BURP_AUTH_TOKEN`
- `AGENT_BURP_TIMEOUT_MS`
- `AGENT_BURP_OUTPUT`
- `AGENT_BURP_SOCKET`
- `AGENT_BURP_DEBUG`
- `AGENT_BURP_LOG_PATH`

## Commands

- `doctor`
- `capabilities`
- `open`
- `close`
- `request`
- `http1`
- `http2`
- `transform url-encode|url-decode|base64-encode|base64-decode|random`
- `ws-history [--regex]`
- `editor get|set`
- `runtime task-engine|intercept`
- `job status|list|cancel`
- `crawl start`
- `export start`
- `replay export|run`
- `events subscribe|unsubscribe|status`
- `history`
- `sitemap`
- `scope get|add|remove`
- `repeater`
- `intruder`
- `audit start|status|stop`
- `scan start|status|stop`
- `issues`
- `rpc <method> --params <json|@file>`
- `daemon run|status|stop|restart|logs`

## Scanner workflow

- `audit start --url <url>` starts an active audit and submits the seed URL as the only base request.
- `audit start --url <url> --from-sitemap [--url-prefix <prefix>]` starts an active audit from matching Burp sitemap request/response items.
- `scan start --url <url> --crawl` runs a crawl first, then audits matching sitemap request/response items from the target origin.
- `crawl start --url <url>` remains discovery only.

## POST/body handling

Notes for new async/replay commands:

- `export start` uses `--out` (not `--output`)
- `replay export` uses `--out`
- `replay run` uses `--in`

`request` supports exactly one body source:

- `--body`
- `--body-file`
- `--body-stdin`
- `--body-base64`

Behavior:

- If body source exists and `--method` is omitted, method defaults to `POST`.
- If body exists and `Content-Type` is missing:
  - JSON body -> `application/json`
  - otherwise -> `text/plain; charset=utf-8`
- `--binary` with `--body-file` or `--body-stdin` base64-encodes bytes into `bodyBase64`.

Examples:

```bash
./agent-burp request \
  --url https://api.example.com/login \
  --method POST \
  --header "Content-Type: application/json" \
  --body '{"username":"test","password":"test123"}' \
  --json
```

```bash
cat payload.json | ./agent-burp request \
  --url https://api.example.com/import \
  --body-stdin \
  --content-type application/json \
  --json
```

## Exit codes

- `0` success
- `2` bad args / validation
- `3` daemon or Burp connect failure
- `4` Burp RPC error
- `5` timeout
