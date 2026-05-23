"""Legacy single-file implementation.

Preserved verbatim from the original ``bounty_agent.py`` so the refactor
can proceed in small commits while the program stays runnable through
``bounty-agent legacy-scan``.

Only two non-behavioural fixes were applied to make the module load and
write files cleanly on Windows:

* ``Dict[str, any]`` (lowercase ``any``) replaced with ``Dict[str, Any]``.
* ``open(...)`` calls received an explicit ``encoding="utf-8"``.

Everything else is intentionally untouched. New code lives in sibling
modules and will eventually replace this file.
"""

# ruff: noqa
# mypy: ignore-errors

import asyncio
import json
import random
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

# ============ CONFIGURAÇÕES ============
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
]

PAYLOADS_FUZZING = {
    "path_traversal": ["../", "../../", "..\\", "..\\..\\"],
    "sql_injection": ["' OR '1'='1", "'; DROP TABLE--", "1' UNION SELECT NULL--"],
    "xss": ["<script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"],
    "command_injection": ["; id", "| whoami", "& ipconfig", "` whoami `"],
}


@dataclass
class Finding:
    """Representa uma vulnerabilidade encontrada"""

    url: str
    type: str
    severity: str
    title: str
    description: str
    payload: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


class WAFDetector:
    """Detecta e identifica WAFs"""

    WAF_SIGNATURES = {
        "CloudFlare": ["__cfduid", "cf_clearance", "cf-ray"],
        "AWS WAF": ["x-amzn-waf-action", "x-amzn-requestid"],
        "ModSecurity": ["x-mod-security-message", "ModSecurity Action"],
        "Akamai": ["akamai-origin-hop", "x-akamai-request-id"],
    }

    @staticmethod
    async def detect(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
        try:
            response = await client.get(url, follow_redirects=True)
            headers = response.headers

            detected_wafs = []
            for waf, signatures in WAFDetector.WAF_SIGNATURES.items():
                if any(sig.lower() in str(headers).lower() for sig in signatures):
                    detected_wafs.append(waf)

            is_likely_waf = (
                response.status_code in [403, 406, 429, 444]
                or "Access Denied" in response.text
                or "Blocked" in response.text
            )

            return {
                "detected": detected_wafs,
                "likely_protected": is_likely_waf,
                "status_code": response.status_code,
            }
        except Exception as e:
            return {"error": str(e)}


class ResponsibleFuzzer:
    """Fuzzer com controles de stealth e rate limiting"""

    def __init__(
        self,
        min_delay: float = 0.5,
        max_delay: float = 3.0,
        max_requests_per_minute: int = 30,
    ):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.max_rpm = max_requests_per_minute
        self.request_times = []

    async def _respect_rate_limit(self):
        now = time.time()
        self.request_times = [t for t in self.request_times if now - t < 60]

        if len(self.request_times) >= self.max_rpm:
            sleep_time = 60 - (now - self.request_times[0])
            if sleep_time > 0:
                print(f"  Rate limit atingido. Aguardando {sleep_time:.1f}s...")
                await asyncio.sleep(sleep_time)

        self.request_times.append(now)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def _safe_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[httpx.Response]:
        await self._respect_rate_limit()
        await asyncio.sleep(random.uniform(self.min_delay, self.max_delay))

        headers = kwargs.pop("headers", {})
        headers.update(
            {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "DNT": "1",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        )

        try:
            return await client.request(method, url, headers=headers, timeout=10, **kwargs)
        except Exception as e:
            print(f"  Erro na requisicao: {e}")
            return None

    async def fuzz_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        payload_category: str = "sql_injection",
    ) -> List[Finding]:
        findings = []
        payloads = PAYLOADS_FUZZING.get(payload_category, [])

        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = await self._safe_request(client, "GET", test_url)

                if response is None:
                    continue

                if any(
                    indicator in response.text
                    for indicator in ["SQL syntax", "MySQL", "error", "syntax error", "<script>"]
                ):
                    findings.append(
                        Finding(
                            url=test_url,
                            type="fuzzing",
                            severity="high",
                            title=f"Possivel {payload_category.replace('_', ' ').title()}",
                            description=f"Payload '{payload}' causou comportamento anomalo",
                            payload=payload,
                        )
                    )
            except Exception as e:
                print(f"  Erro ao testar payload: {e}")

        return findings


class BountyAgent:
    """Agente principal para bug bounty (legacy)."""

    def __init__(
        self,
        nuclei_templates: str = "~/nuclei-templates",
        proxy: Optional[str] = None,
    ):
        self.nuclei_templates = nuclei_templates
        self.proxy = proxy
        self.findings: List[Finding] = []
        self.fuzzer = ResponsibleFuzzer()
        self.waf_detector = WAFDetector()

    async def scan_with_nuclei(self, url: str) -> List[Finding]:
        print(f"\nExecutando Nuclei em {url}...")

        cmd = [
            "nuclei",
            "-u",
            url,
            "-t",
            self.nuclei_templates,
            "-severity",
            "critical,high,medium",
            "-c",
            "1",
            "-rl",
            "10",
            "-timeout",
            "10",
            "-json",
        ]

        if self.proxy:
            cmd.extend(["-proxy", self.proxy])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            findings = []
            for line in result.stdout.split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        findings.append(
                            Finding(
                                url=url,
                                type="nuclei",
                                severity=data.get("info", {}).get("severity", "info"),
                                title=data.get("info", {}).get("name", "Unknown"),
                                description=data.get("info", {}).get("description", ""),
                            )
                        )
                    except json.JSONDecodeError:
                        continue

            print(f"  Nuclei encontrou {len(findings)} potenciais vulnerabilidades")
            return findings

        except FileNotFoundError:
            print("  Nuclei nao instalado.")
            return []
        except subprocess.TimeoutExpired:
            print("  Nuclei timeout (limite de 120s)")
            return []
        except Exception as e:
            print(f"  Erro ao executar Nuclei: {e}")
            return []

    async def enumerate_endpoints(self, base_url: str) -> List[str]:
        common_paths = [
            "/",
            "/admin",
            "/api",
            "/api/v1",
            "/login",
            "/register",
            "/search",
            "/user",
            "/profile",
            "/settings",
            "/upload",
            ".git",
            ".env",
            "web.config",
            "robots.txt",
        ]

        endpoints = []
        async with httpx.AsyncClient() as client:
            for path in common_paths:
                url = urljoin(base_url, path)
                try:
                    response = await self.fuzzer._safe_request(client, "GET", url)
                    if response and response.status_code < 400:
                        endpoints.append(url)
                except:
                    pass

        return endpoints

    async def analyze_target(self, url: str) -> Dict:
        print(f"\nAnalisando {url}...")

        results = {
            "target": url,
            "timestamp": datetime.utcnow().isoformat(),
            "waf_detection": {},
            "nuclei_findings": [],
            "fuzzing_findings": [],
            "endpoints": [],
        }

        async with httpx.AsyncClient() as client:
            print("\nDetectando WAF...")
            results["waf_detection"] = await self.waf_detector.detect(url, client)
            if results["waf_detection"].get("detected"):
                print(f"  WAF detectado: {results['waf_detection']['detected']}")
            else:
                print("  Sem WAF detectado")

            print("\nEnumerando endpoints...")
            results["endpoints"] = await self.enumerate_endpoints(url)
            print(f"  {len(results['endpoints'])} endpoints encontrados")

            print("\nExecutando fuzzing responsavel...")
            for endpoint in results["endpoints"][:3]:
                fuzzing_findings = await self.fuzzer.fuzz_endpoint(
                    client, endpoint, "q", "sql_injection"
                )
                results["fuzzing_findings"].extend(fuzzing_findings)

        results["nuclei_findings"] = await self.scan_with_nuclei(url)

        return results

    def generate_report(self, results: Dict) -> str:
        report = f"""
============================================================
                     BUG BOUNTY REPORT
============================================================

TARGET: {results["target"]}
TIMESTAMP: {results["timestamp"]}

------------------------------------------------------------

SUMARIO
  - Endpoints encontrados: {len(results["endpoints"])}
  - Nuclei findings: {len(results["nuclei_findings"])}
  - Fuzzing findings: {len(results["fuzzing_findings"])}

------------------------------------------------------------

WAF DETECTION
  - Detectados: {", ".join(results["waf_detection"].get("detected", ["Nenhum"]))}
  - Protegido: {"Sim" if results["waf_detection"].get("likely_protected") else "Nao"}

------------------------------------------------------------

NUCLEI FINDINGS ({len(results["nuclei_findings"])})
"""

        if results["nuclei_findings"]:
            for finding in results["nuclei_findings"]:
                report += f"\n  [{finding.severity.upper()}] {finding.title}\n"
                report += f"    URL: {finding.url}\n"
                report += f"    Descricao: {finding.description}\n"
        else:
            report += "\n  Nenhuma vulnerabilidade encontrada pelo Nuclei\n"

        report += (
            f"\n------------------------------------------------------------\n\n"
            f"FUZZING FINDINGS ({len(results['fuzzing_findings'])})\n"
        )

        if results["fuzzing_findings"]:
            for finding in results["fuzzing_findings"]:
                report += f"\n  [{finding.severity.upper()}] {finding.title}\n"
                report += f"    URL: {finding.url}\n"
                report += f"    Payload: {finding.payload}\n"
        else:
            report += "\n  Nenhuma anomalia detectada no fuzzing\n"

        report += """
------------------------------------------------------------

ETHICAL GUIDELINES OBSERVADOS
  - Rate limiting implementado (30 req/min)
  - Delays aleatorios entre requisicoes
  - User-Agents rotativos
  - Nao causa negacao de servico
  - Respeita robots.txt (parcialmente)

------------------------------------------------------------

NOTAS
  - Este teste foi executado em escopo autorizado (bug bounty)
  - Respeite sempre as regras do programa (HackerOne, Bugcrowd, etc)
  - Divulgacao responsavel: aguarde resposta antes de publicar

============================================================
"""
        return report


async def main():
    target = "https://example-bugbounty.com"
    agent = BountyAgent()
    results = await agent.analyze_target(target)
    report = agent.generate_report(results)
    print(report)
    with open("bounty_report.txt", "w", encoding="utf-8") as f:
        f.write(report)
    with open("bounty_findings.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        agent = BountyAgent()
        results = asyncio.run(agent.analyze_target(target))
        report = agent.generate_report(results)
        print(report)
    else:
        print("Uso: python -m bounty_agent.legacy <target_url>")
