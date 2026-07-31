# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-chat interface over many OSINT MCP servers. LibreChat is the MCP-native host; the value this repo adds is the *packaging* of servers (a registry + a config generator), the API-key UX, and a custom orchestrator that turns any target into a dossier. LLM access (GigaChat / Claude / GPT / Ollama) is unified behind a LiteLLM OpenAI-compatible gateway.

The codebase, comments, and docs are written in **Russian** — match that when editing existing files.

## Commands

```bash
# First-time setup
cp .env.example .env                       # set at least GIGACHAT_CREDENTIALS + LITELLM_MASTER_KEY
pip install -r generator/requirements.txt  # generator deps (pyyaml, jinja2)

./scripts/up.sh          # build base image, generate configs, docker compose up -d --build
./scripts/down.sh        # stop stack; add --wipe to drop Mongo/Meili volumes
./scripts/regen.sh       # regenerate configs after editing the registry (calls generator/generate.py)
python generator/generate.py   # same, run directly

# Optional compose profiles
docker compose --profile local-llm up -d ollama ollama-init   # in-stack Ollama
docker compose --profile ratelimit up -d                       # Redis rate-limit
```

UI: http://localhost:3080 · LiteLLM: http://localhost:4000 · Reports index: http://localhost:8899

The full stack is two compose files layered: `docker-compose.yml` (infra: librechat, mongodb, meilisearch, litellm, gigachat-proxy, reports, ollama, redis) + the generated `docker-compose.mcp.yml` (one service per stdio MCP server). Scripts always pass both with `-f`.

### Verifying an LLM path
```bash
curl -s localhost:4000/v1/chat/completions -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H 'Content-Type: application/json' -d '{"model":"GigaChat","messages":[{"role":"user","content":"привет"}]}'
```
Model names to swap in: `GigaChat-2-Pro`, `claude-opus-4-8`, `claude-sonnet-5`, `gpt-4o`, `qwen2.5`.

### Tests
End-to-end scenario tests live in `tests/` and run **inside the orchestrator container** (they hit `http://orchestrator:8000/mcp` and the reports service on the docker network). They deliberately pause ~25s between cases to respect free-tier rate limits. Run with `docker exec` into the orchestrator container, e.g. `python /app/tests/verify_all.py`. `tests/verify_all.py` is the main pass/fail harness; each case asserts required and forbidden substrings in the generated report.

## Architecture

### Registry is the single source of truth
`registry/servers.yaml` has one entry per MCP server. `generator/generate.py` reads it and renders three files — **never hand-edit these, they get overwritten**:
- `config/librechat.yaml` — LLM endpoints + the `mcpServers` block
- `docker-compose.mcp.yml` — one service per `transport: stdio` server
- `config/catalog.json` — catalog metadata consumed by the orchestrator and UI

Adding/toggling a server = edit the registry, then `./scripts/regen.sh`. Field reference is in `registry/README.md`. The generator validates every entry (including disabled ones), fails loudly on bad records, and computes derived UI fields (key badges, sanitized titles, endpoints). Adding a server via `librechat.yaml` requires restarting the LibreChat host.

### Transports
- `transport: stdio` → built as a container from `servers/<id>/`, wrapped by **supergateway** (stdio→SSE, pinned to `3.4.3` because a local patch injects per-user keys from the `X-Mcp-Env` header). LibreChat reaches it at `http://<id>:8000`. All stdio servers inherit `servers/base/Dockerfile` (`osint-mcp-base:latest` — node + python + uv + supergateway).
- `install: remote` / `transport: http` → no container; LibreChat connects to the vendor's hosted URL directly.

### GigaChat path
GigaChat is not OpenAI-compatible (Sber OAuth, ~30-min token, Russian TLS CA). The `gigachat-proxy` sidecar (`gpt2giga`) exposes an OpenAI-compatible `/v1`; LiteLLM treats it as a plain openai provider, so the gateway starts even when Sber is unreachable (geo-restriction). Cloud (Claude/GPT) and Ollama models are added to `litellm/config.yaml` the same way.

### The orchestrator (custom code — the heart of the repo)
`servers/orchestrator/` is a FastMCP server exposing **only 4 tools** to LibreChat (`investigate`, `plan`, `catalog`, `call_server`). This solves the "hundreds of tools across ~20 servers" problem and enables the agentic presets: the model just calls `investigate(task=...)` and the routing/fan-out/report-building is deterministic, server-side Python (important because GigaChat/Ollama are weak at tool-calling). Module layout:
- `server.py` — MCP tools, target fan-out with soft deadline, report synthesis, chat summary. It is itself an **MCP client** to every other server via `mcp_client.py`.
- `recipes.py` — `detect_targets()` (regex target typing: username/email/domain/ip/hash/inn/url/ticker/company), `PREFERRED`/`CURATED` routing tables, ethical `harm_notice()` and `unsupported_notice()` gates run *before* any source is queried.
- `dossier.py` / `report.py` — deep domain dossier (deterministic tables + LLM narrative) and report file writing (`.md` + `.pdf`).
- `mcp_client.py` — minimal async MCP client (Streamable HTTP, parses both JSON and SSE responses); a fresh session per call.

Key behaviors to preserve when editing the orchestrator:
- Two separate models: `ORCHESTRATOR_MODEL` (routing) vs `ORCHESTRATOR_REPORT_MODEL` (dossier synthesis) — split so the writer can be upgraded independently via env, no code change.
- Every LLM call degrades gracefully to `None` → deterministic rules/report. Never let a missing key or LLM error break `investigate`.
- Per-server timeouts (`SERVER_TIMEOUT`) and a global `SOFT_DEADLINE` — slow sources (maigret/openosint cold-start) get more time; the investigation returns whatever finished and marks the rest "didn't respond in time". Cancelling a docker-run-wrapped source mid-call leaks a container, so timeouts are tuned around that.
- `reclassify()` re-labels "ok but the text is actually an error" as failures — but only for *short* responses, because a large successful report can legitimately contain strings like "403" from the targets it scanned.

### Reports & UI defaults
Reports land in `./reports` (bind-mounted into the orchestrator) as `.md`+`.pdf` and are served at `http://localhost:8899`. Weak models sometimes fabricate a plausible CDN link *without calling the tool*; the system prompt forbids it, and real reports only ever live on `localhost:8899`.

LibreChat client defaults (dark theme, Russian, orchestrator pre-selected in new chats) can't be set via config — they live in browser localStorage. `scripts/librechat-ui-defaults.sh` injects them into `index.html` on container start, reapplied on every boot so it survives image updates.

## Conventions
- Two system prompts: `config/system_prompt.md` (manual multi-server mode, with a `<!-- ROUTING_TABLE -->` marker the generator fills from the registry) and `config/system_prompt_auto.md` (agentic preset that just calls `investigate`).
- Paid servers start but stay silent until their key is in `.env` — this is expected, not a bug. Anonymous-capable freemium servers are marked with `anonymous_ok: true` in the registry only when verified by a real request.
- `enabled: false` in the registry excludes a server from generation entirely (used for servers whose wrappers aren't yet built or that need interactive OAuth, which breaks headless).
