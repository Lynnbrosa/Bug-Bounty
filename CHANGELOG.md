# Changelog

All notable changes to bounty-agent are tracked here. The project follows
semantic versioning loosely: bug-fixing patches bump the patch number,
new detection capabilities bump the minor, breaking changes bump the
major.

## [0.3.0] - 2026-05-28

### Added — bug-bounty-grade detection

- **OOB callback receiver** (`bounty-agent oob serve` + `oob status`)
  with token registry, JSONL-persisted callback log, and HTTP API
  (`/__oob/callbacks`) for cross-machine polling. Payloads in
  `config/payloads-oob.yaml` carry the `{OOB_URL}` placeholder; the
  fuzzer rewrites it at runtime, the correlator pairs callbacks back
  to issuing tokens and emits CRITICAL findings with confidence 1.0.
- **Exploit chain reasoner** (`bounty_agent.exploit.chain_reasoner`)
  backed by Claude Opus 4.7. Takes a ScanResult, returns an ordered
  ExploitChain with business impact and calibrated confidence.
- **Auto-PoC generator** (`bounty_agent.exploit.poc_generator`)
  backed by Claude Sonnet 4.5. Writes a runnable Python PoC per
  finding (or per chain step), wired to a stdout marker so the
  optional `PocValidator` can confirm by execution.
- **Adaptive payload generation** (`bounty_agent.fuzzing.adaptive`).
  Pre-scan call to the LLM with the target's tech stack; returns
  bespoke payloads per category that merge into the static catalogue.
- **Prompt-injection analyzer** (`PromptInjectionAnalyzer`) plus a
  new `ai_prompt_injection` payload category. Detects PWNED marker,
  system-prompt leak fragments, and known model self-disclosure.
- **CORS misconfiguration probe** (`CorsProbeScanner`) — 4 forged
  Origin variants per URL, severity gated by Allow-Credentials.
- **Open-redirect probe** (`OpenRedirectScanner`) — 6 bypass payloads
  across 14 candidate parameter names; uses existing param when
  present, falls back to the full list otherwise.
- **Cookie security audit** (`CookieSecurityAuditor`) — session-cookie
  detection plus Secure/HttpOnly/SameSite enforcement.
- **CSP audit** (`CspAuditor`) — flags missing header, unsafe-inline
  / unsafe-eval, wildcard sources, missing frame-ancestors and
  object-src directives.
- **OpenAPI 3.x ingestion** (`bounty_agent.ingest.openapi`). Converts
  a spec to `targets.txt` + `post-targets.json` ready for the scan
  command.
- **Continuous diff + webhook alerting** (`bounty_agent.continuous`).
  Stable-identity hash over `(url, title, severity, payload)` plus
  an async WebhookNotifier for new/closed findings.
- **Visual content fingerprint** (`bounty_agent.visual.fingerprint`)
  — sha-256 over a noise-redacted body, plus title + meta-generator
  extraction. Foundation for the future playwright screenshot
  extension.
- **Dry-run mode** (`bounty-agent scan --dry-run`) — renders the
  planned scan (scope evaluation, phase enablement, estimated
  request count) without sending a single byte.
- **Demo command** (`bounty-agent demo`) — end-to-end visual test of
  every subsystem, rendered as Rich panels. Reproducible offline
  with `--no-use-llm`.

### Added — external tool wrappers

- **nmap** (`bounty_agent.tools.nmap`) — service version + NSE
  default scripts, XML parsing into structured findings.
- **arjun** — hidden HTTP parameter discovery.
- **subjack** — subdomain takeover detection (S3, Heroku, GitHub
  Pages, etc.).
- **trufflehog** — 700+ credential detectors with secret redaction.

### Added — auth + JWT

- **Login flow** (`bounty_agent.auth`) with JSONPath or regex token
  extraction; bearer header injected on every downstream request.
- **JWT manipulation scanner** (`JwtAttackScanner`) — alg:none and
  signature stripping against URLs that returned 4xx unauthenticated.

### Changed

- Default analyzers expanded: SqlInjection (Node/Sequelize/SQLite
  markers added), NoSqlInjection (new), AuthBypass (new),
  ReflectedXss (now accepts JSON with HTML-active chars), Prompt
  Injection (new).
- Fuzzer auto-discovers query parameters from the URL instead of
  hard-coding `q`; falls back to a curated 9-param list when the URL
  has no query string.
- Fuzzer fuzzes the last URL path segment when it looks like a
  numeric ID (`/api/Users/1` -> IDOR shape).
- POST/PUT/PATCH body fuzzing via the new `--post-targets` JSON file
  and `__FUZZ__` marker.
- Sensitive scanner expanded from 6 to 17 signatures; body_window
  bumped to 32 768 bytes for HTML listings; %2500.md null-byte
  bypass attempted on 401/403 responses with backup-shaped URLs.
- Audit log gained `fuzzer.started` / `fuzzer.finished` /
  `oob.*` / `cors.*` / `open_redirect.*` events.

### Fixed

- httpx CLI path collision noted in README troubleshooting; wrappers
  use `shutil.which` so installation to `~/go/bin` resolves first.
- ruff/mypy/pytest hygiene across 320 tests; CI matrix runs 3.11 + 3.12.

### Metadata

- `pyproject.toml` author updated to the real committer (Lynn Bueno
  Rosa).
- `project.urls` point at `github.com/Lynnbrosa/Bug-Bounty`.
- `docs/BOUNTY_GUIDE.md` flagged as legacy doc; current source of
  truth is the README.

## [0.1.0] - 2025-XX-XX

Initial public release. Single-file research script plus first cut of
the modular pipeline (scope guard, ResponsibleFuzzer, NucleiScanner,
SensitivePathScanner, structured ScanResult, SQLite persistence,
markdown/JSON reports).
