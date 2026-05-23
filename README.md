# bounty-agent

Responsible bug bounty research agent for authorised security testing.

Orchestrates external tools (`nuclei`, `subfinder`, `waybackurls`, `httpx`, `dnsx`, `katana`, `naabu`) plus an in-process fuzzer and WAF detector. Every URL passes through a hard scope guard before any request leaves the process; every action is recorded in an append-only JSONL audit log; every scan is persisted to SQLite with a schema-versioned envelope.

## Scope and authorisation

This tool refuses to scan any host that is not in `scope.allowlist`. Every command that touches a target also requires `--authorized`. Intrusive tools (`katana`, `naabu`) further require `--intrusive`. Decisions, requests and findings land in the audit log.

Use only against targets you are authorised to test: bug bounty programs in scope, signed pentest engagements, your own systems, CTF environments. Do not use to evade WAFs in production, conduct mass scanning, or test without permission.

## Install

Local development (Python 3.11+):

```bash
pip install -e ".[dev]"
```

The external Go binaries are optional at install time; the agent degrades gracefully when a tool is missing (`tool.skipped` audit event, scan continues). For a self-contained runtime with every binary baked in, build the image:

```bash
docker build -f docker/Dockerfile -t bounty-agent:dev .
```

## Quick start

```bash
# 1. Generate a config file you can edit.
bounty-agent init-config -d my-config.yaml

# 2. Add your authorised hosts. Allowlist is mandatory.
#    Example my-config.yaml:
#      scope:
#        allowlist: [api.example.com, "*.staging.example.com"]
#      authorization:
#        acknowledged: true
#        program: "HackerOne / acme"
#        contact: "secops@acme.example"

# 3. Map the surface (passive only by default).
bounty-agent recon https://api.example.com --config my-config.yaml --authorized

# 4. Run the full scan against discovered URLs.
bounty-agent scan https://api.example.com --config my-config.yaml --authorized

# 5. Inspect.
bounty-agent history list https://api.example.com --config my-config.yaml
bounty-agent history diff https://api.example.com --config my-config.yaml
```

## Subcommands

| Command | Purpose |
|---|---|
| `scan <url>` | Full pipeline: recon → WAF detection → fuzzing → nuclei. Saves text/markdown/json reports and persists to SQLite. |
| `recon <url>` | Only the external tool pipeline. Useful for surface monitoring without paying for a full scan. |
| `tools list` | Show known external tools, whether each binary is on PATH, and whether it is intrusive. |
| `tools run <name> <url>` | Run a single tool wrapper directly. Same scope and authorisation gates as `scan`. |
| `history list <target>` | List recent scans for a target. |
| `history diff <target>` | Diff the two most recent scans: resolved vs new findings, plus surface delta (URLs added/removed). |
| `eval` | Run analysers against `tests/golden/` and report precision/recall/F1 per category. |
| `llm-classify <scan_id>` | Optional. Re-rank a stored scan through Claude Haiku 4.5 to filter false positives. Off by default. |
| `schema` | Print the versioned JSON Schema of `ScanResult`. |
| `audit` | Tail the audit log (JSONL). |
| `init-config` | Write a starter config to `./bounty-agent.yaml`. |
| `legacy-scan <url>` | Run the original single-file agent. Kept for parity. |

Every command that touches a network target requires `--authorized`. Add `--intrusive` to unlock `katana` (crawler) and `naabu` (port scan) inside the recon pipeline.

## Configuration

Configuration is loaded from YAML and may be overridden by environment variables prefixed `BOUNTY_AGENT_` (nested keys use `__` as separator). The shipped `config/default.yaml` documents every field. The fields you will actually edit:

```yaml
authorization:
  acknowledged: true
  program: "HackerOne / acme"
  contact: "secops@acme.example"

scope:
  allowlist:                # required, empty allowlist refuses everything
    - "api.acme.example"
    - "*.staging.acme.example"
  path_denylist:
    - "/logout"
    - "/admin/delete"

agent:
  min_delay_seconds: 1.0    # jitter floor between requests
  max_delay_seconds: 3.0
  max_requests_per_minute: 20

tools:
  subfinder: true           # passive
  waybackurls: true         # passive
  httpx: true               # probe
  dnsx: false               # intrusive, gated by --intrusive
  katana: false
  naabu: false

tools_cache:
  enabled: true
  ttl_seconds: 21600        # cache subfinder/waybackurls results 6h

llm:
  enabled: false            # opt in; reads ANTHROPIC_API_KEY
  model: claude-haiku-4-5
```

## Architecture

```
target ──▶ scope.check ──▶ recon pipeline:
                            subfinder ──▶ dnsx (optional) ──▶ subdomains
                            waybackurls ──▶ historical URLs
                            katana (optional intrusive) ──▶ crawled URLs
                            httpx ──▶ alive URLs
                            naabu (optional intrusive) ──▶ port findings
                        ──▶ WAF detection (best effort)
                        ──▶ ResponsibleFuzzer per category (sql, xss, path...)
                        ──▶ NucleiScanner per endpoint
                        ──▶ ScanResult (Pydantic v2, schema versioned)
                        ──▶ reports/{text, markdown, json}
                        ──▶ SQLite history (scans + findings + tool_cache)
                        ──▶ optional: LLM post-processor (Claude Haiku 4.5)
```

Subsystems live in their own packages and can be swapped or stubbed:

- [core/](src/bounty_agent/core) Pydantic models, JSON Schema export, `ScopePolicy`
- [recon/](src/bounty_agent/recon) WAF detector, tool pipeline, endpoint enum, app fingerprint
- [fuzzing/](src/bounty_agent/fuzzing) `ResponsibleFuzzer`, payload registry, analysers
- [scanners/nuclei.py](src/bounty_agent/scanners/nuclei.py) async `nuclei` wrapper
- [tools/](src/bounty_agent/tools) plugin contract + 6 external CLI wrappers
- [persistence/](src/bounty_agent/persistence) SQLAlchemy 2.0, `ScanRepository`, `SqlToolCache`
- [reporting/](src/bounty_agent/reporting) text, markdown (jinja2), JSON renderers
- [scoring/impact.py](src/bounty_agent/scoring/impact.py) contextual severity scoring
- [llm/classifier.py](src/bounty_agent/llm/classifier.py) optional Anthropic SDK post-processor
- [notifications/webhook.py](src/bounty_agent/notifications/webhook.py) optional Slack-shaped webhook
- [orchestrator.py](src/bounty_agent/orchestrator.py) glue

## Audit log

Every privileged action is appended as a JSONL line to `logs/audit.log` (configurable). Sample events: `scan.started`, `scan.preset_targets`, `tool.started`, `tool.refused`, `recon.cache_hit`, `nuclei.timeout`, `llm.classified`, `notifications.sent`.

```bash
bounty-agent audit --tail 50
```

## Evaluation

The agent ships with a small golden dataset under `tests/golden/`. Each case is a labelled (request, response) pair that the analysers must classify correctly. Add a case every time a real-world false positive or missed finding shows up.

```bash
bounty-agent eval
```

Prints precision, recall and F1 per category plus overall. Exits non-zero on regression.

## Development

```bash
pip install -e ".[dev]"
pre-commit install

ruff check .
ruff format --check .
mypy src
pytest
```

CI matrix runs lint, format check, mypy and pytest on Python 3.11 and 3.12, then builds the runtime Docker image.

## Roadmap

The repo is at `v0.1`. Capability is stable; the next iterations focus on quality and coverage rather than features:

- expand `tests/golden/` from real scans
- add `tools/` wrappers for one or two more popular OSS scanners
- richer `history diff` (severity-weighted delta, exportable)
- batch `llm-classify` over multiple scans

## License

MIT
