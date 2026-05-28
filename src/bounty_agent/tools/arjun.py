"""arjun wrapper (s0md3v/Arjun).

Hidden HTTP parameter discovery. arjun fires hundreds of probes with
candidate parameter names from its built-in wordlist and a behavioral
diff against a baseline to identify which params the backend actually
processes.

Why this matters: the fuzzer currently falls back to a hand-written list
of common param names (``q``, ``id``, ``search``, ...) when the URL has
no query string. arjun replaces that guess with empirical discovery,
shrinking the per-endpoint fuzz budget and lifting recall on backends
that accept obscure params (``debug``, ``preview``, ``api_key``,
custom names, etc.).

JSON output (``-oJ -``) is parsed into the param names; orchestrator
treats them as the priority list for that endpoint.
"""

from __future__ import annotations

import json
from typing import ClassVar

from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class Arjun(BaseSubprocessTool):
    name: ClassVar[str] = "arjun"
    description: ClassVar[str] = "Hidden HTTP parameter discovery."
    intrusive: ClassVar[bool] = True
    binary: ClassVar[str] = "arjun"
    timeout_seconds: ClassVar[int] = 300

    # Reasonable defaults: GET by default, 25 threads, the medium wordlist.
    method: ClassVar[str] = "GET"
    threads: ClassVar[int] = 25
    delay_seconds: ClassVar[float] = 0.0

    def build_args(self, target: str) -> list[str]:
        return [
            "-u",
            target,
            "-m",
            self.method,
            "-t",
            str(self.threads),
            "-d",
            str(self.delay_seconds),
            "-oJ",
            "-",  # JSON to stdout
            "--disable-redirects",  # arjun uses its own redirect handling; reduce noise
            "--stable",  # slower but lower FP
        ]

    def parse_stdout(self, stdout: str, target: str) -> ToolResult:
        """arjun emits a JSON document with the discovered params per URL.

        Shape (truncated):

            {
                "https://example.com/search": {
                    "params": ["q", "debug", "preview"],
                    "method": "GET",
                    ...
                }
            }
        """
        items: list[str] = []
        text = stdout.strip()
        if not text:
            return ToolResult(tool=self.name, target=target, items=items)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ToolResult(tool=self.name, target=target, items=items)

        # arjun's JSON sometimes nests by URL, sometimes is a flat dict for
        # one URL. Be permissive: accept either shape.
        if isinstance(data, dict) and "params" in data:
            items.extend(str(p) for p in (data.get("params") or []))
        elif isinstance(data, dict):
            for _url, payload in data.items():
                if isinstance(payload, dict):
                    items.extend(str(p) for p in (payload.get("params") or []))
        return ToolResult(tool=self.name, target=target, items=items)


__all__ = ["Arjun"]
