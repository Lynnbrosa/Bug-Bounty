# bounty-agent

Responsible bug bounty research agent for authorized security testing.

Integrates Nuclei, async fuzzing and WAF detection with hard scope guards, structured findings, audit logging and SQLite history.

## Scope and authorization

This tool refuses to run against any host that is not in the configured allowlist. Authorization is required, recorded in the audit log and surfaced in every report.

Use only against targets you are authorized to test (bug bounty programs, pentest engagements, your own systems, CTF environments).

## Quick start

```bash
pip install -e ".[dev]"
bounty-agent init-config
# edit config/default.yaml and add your allowed hosts
bounty-agent scan https://your-authorized-target.example --authorized
```

## Project status

Under refactor. The original single-file agent lives in `src/bounty_agent/legacy.py` and stays callable via `bounty-agent legacy-scan <url>` while the modular rewrite progresses.

See `BOUNTY_GUIDE.md` and `EXEMPLOS_AVANCADOS.md` for the original reference material that drives the roadmap.

## Development

```bash
pip install -e ".[dev]"
pre-commit install
pytest
ruff check .
mypy src
```

## License

MIT
