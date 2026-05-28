# Bug Bounty Agent - Guia Completo (legacy)

> **Aviso de status:** este documento descreve o agente em sua forma
> monolítica original (script único, Python 3.8+, dependências manuais).
> A partir da v0.2 o agente foi refatorado em pacote modular sob
> `src/bounty_agent/`, exige **Python 3.11+** e é instalado via
> `pip install -e .`. Para a documentação atual, consulte o
> [README.md](../README.md) na raiz. Este guia fica como referência
> histórica e para quem ainda usa o subcomando `bounty-agent legacy-scan`.

## Índice
1. [Setup e Instalação](#setup)
2. [Configuração](#configuração)
3. [Uso Básico](#uso-básico)
4. [Técnicas Avançadas](#técnicas-avançadas)
5. [Ética e Responsabilidade](#ética)
6. [Troubleshooting](#troubleshooting)

---

## Setup e Instalação {#setup}

### Pré-requisitos (legacy, single-file)
```bash
# Python 3.8+ (legacy — versão modular exige 3.11+)
python3 --version

# Instalar dependências
pip install httpx tenacity

# Nuclei (scanner de templates)
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Subfinder (subdomínio enumeration)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx (prober de hosts)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Estrutura do Projeto
```
bounty-project/
├── bounty_agent.py          # Agente principal
├── config.yaml              # Configurações
├── targets.txt              # Lista de URLs alvo
├── nuclei-templates/        # Templates Nuclei customizados
├── reports/                 # Relatórios gerados
└── logs/                    # Logs de execução
```

---

## ⚙️ Configuração {#configuração}

### Arquivo config.yaml (opcional)
```yaml
agent:
  min_delay: 0.5
  max_delay: 3.0
  max_requests_per_minute: 30
  timeout: 10

nuclei:
  severity: [critical, high, medium]
  templates: ~/nuclei-templates
  concurrency: 1
  rate_limit: 10

fuzzing:
  payloads_per_param: 5
  timeout: 10
  categories:
    - sql_injection
    - xss
    - path_traversal

fuzzing:
  enabled: true
  max_endpoints: 5

waf:
  detect: true
  bypass_techniques:
    - encoding
    - case_variation
    - comment_injection

proxy:
  enabled: false
  # Usar com cuidado - somente proxies legítimos
  # urls: [socks5://localhost:1080]
```

### Variáveis de Ambiente
```bash
export NUCLEI_TEMPLATES="$HOME/nuclei-templates"
export BOUNTY_TARGET="https://target.com"
export BOUNTY_PROXY=""  # Deixar vazio para não usar
```

---

## 💻 Uso Básico {#uso-básico}

### 1. Scan Simples
```bash
python bounty_agent.py https://target-autorizaodo.com
```

### 2. Scan com Múltiplos Targets
```bash
# targets.txt
https://app1.bounty.com
https://app2.bounty.com
https://api.bounty.com

# Executar
while read url; do
  python bounty_agent.py "$url"
done < targets.txt
```

### 3. Integração em Script
```python
import asyncio
from bounty_agent import BountyAgent

async def scan_multiple_targets(urls):
    agent = BountyAgent()
    for url in urls:
        results = await agent.analyze_target(url)
        agent.generate_report(results)

# Usar
urls = ["https://target1.com", "https://target2.com"]
asyncio.run(scan_multiple_targets(urls))
```

---

## 🔧 Técnicas Avançadas {#técnicas-avançadas}

### 1. Fuzzing Customizado
```python
# Adicionar payloads customizados
custom_payloads = {
    "ssti": ["{{ 7*7 }}", "${7*7}", "<%= 7*7 %>"],
    "ldap_injection": ["*", "*)(uid=*", "*))(&(uid=*"],
    "xml_xxe": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>']
}

PAYLOADS_FUZZING.update(custom_payloads)
```

### 2. Detecção de WAF Avançada
```python
# Técnicas de bypass
class WAFBypass:
    @staticmethod
    async def encode_payload(payload: str) -> List[str]:
        """Variações de encoding para bypass"""
        variations = [
            payload,
            payload.upper(),
            payload.lower(),
            payload.replace(" ", "+"),
            payload.replace(" ", "%20"),
            payload.replace("'", "%27"),
            # URL double encoding
            urllib.parse.quote(urllib.parse.quote(payload)),
        ]
        return variations
    
    @staticmethod
    async def comment_injection(payload: str) -> str:
        """Injetar comentários para bypass"""
        return f"' /*! or */ '1'='1"  # MySQL
```

### 3. Integração com Subdomain Enumeration
```python
import subprocess

async def enumerate_subdomains(domain: str) -> List[str]:
    """Encontra subdomínios automaticamente"""
    cmd = ["subfinder", "-d", domain, "-json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    subdomains = []
    for line in result.stdout.split("\n"):
        if line.strip():
            data = json.loads(line)
            subdomains.append(data["host"])
    
    return subdomains

# Usar
subdomains = asyncio.run(enumerate_subdomains("example.com"))
for subdomain in subdomains:
    await agent.analyze_target(f"https://{subdomain}")
```

### 4. Relatórios com Severidade Contextual
```python
def calculate_impact(finding: Finding, target_context: Dict) -> float:
    """Score de impacto baseado em contexto"""
    
    base_score = {
        "critical": 9.0,
        "high": 7.0,
        "medium": 5.0,
        "low": 3.0,
        "info": 1.0
    }[finding.severity]
    
    # Aumentar score se servidor é crítico
    if target_context.get("is_production"):
        base_score *= 1.5
    
    # Reduzir se não é autenticado
    if target_context.get("requires_auth"):
        base_score *= 0.7
    
    return min(base_score, 10.0)
```

### 5. Monitoramento Contínuo
```python
import schedule

def schedule_bounty_scans():
    """Scans automáticos em horários específicos"""
    
    targets = ["https://app1.com", "https://app2.com"]
    
    def run_scan():
        for target in targets:
            try:
                results = asyncio.run(agent.analyze_target(target))
                # Comparar com scan anterior
                if has_new_findings(results):
                    send_notification(results)
            except Exception as e:
                log_error(e)
    
    # Executar todo dia às 2AM (menos impacto)
    schedule.every().day.at("02:00").do(run_scan)
    
    while True:
        schedule.run_pending()
        time.sleep(60)
```

---

## ⚖️ Ética e Responsabilidade {#ética}

### ✅ Checklist ANTES de Executar
- [ ] **Escopo Autorizado**: Confirmar que o target está no programa
  - HackerOne: Verificar programa na plataforma
  - Bugcrowd: Confirmar programa ativo
  - Direto com empresa: Email de autorização assinado
  
- [ ] **In Scope Definido**:
  - Subdomínios permitidos
  - Funcionalidades proibidas (admin, usuários reais, etc)
  - Endpoints excluídos
  
- [ ] **Limites Técnicos**:
  - Max 30 requisições/minuto (não causa DoS)
  - Delays entre 0.5-3 segundos
  - Timeouts de 10 segundos
  - Sem parallelização agressiva
  
- [ ] **Protocolos de Divulgação**:
  - Ler programa rules
  - Respeitar períodos de divulgação
  - Não publicar até confirmação
  - Seguir responsible disclosure

### 📝 Documento de Autorização
```
DATA: [data]
ALVO: [domínio]
TIPO: [Bug Bounty/Pentest/Pesquisa]
PROGRAMA: [HackerOne/Bugcrowd/Direto]
ESCOPO: [subdomínios/endpoints permitidos]
DURAÇÃO: [de X a Y]
CONTATO: [email responsável]

Autorizo a execução de testes de segurança dentro dos
limites especificados acima. Entendo que estes testes
podem impactar momentaneamente os serviços.

Assinado: _____________________
```

### 🚨 O Que NÃO Fazer
```python
# ❌ NÃO FAZER - Acessar dados sensíveis
sensitive_data = client.get("/admin/users").json()

# ❌ NÃO FAZER - Causar dano permanente
delete_request = client.delete("/api/critical-database")

# ❌ NÃO FAZER - Usar múltiplos IPs para evitar detection
async def aggressive_fuzzing():  # Causa DoS
    for i in range(1000):
        await client.get(url)

# ❌ NÃO FAZER - Acessar dados de outros usuários
other_user_data = client.get(f"/api/users/{random_id}")

# ✅ FAZER - Sempre reportar responsavelmente
# - Documente tudo
# - Não reutilize exploits sem permissão
# - Aguarde resposta da empresa antes de divulgar
```

### 📄 Relatório Profissional
```
[TITULO]
[Vulnerabilidade Encontrada em Target X]

[SUMÁRIO EXECUTIVO]
- Tipo: SQL Injection
- Severidade: High
- Impacto: Acesso não autorizado a dados sensíveis
- Exploração: Moderada dificuldade

[DESCRIÇÃO TÉCNICA]
1. Endpoint afetado: /api/search?q=
2. Método HTTP: GET
3. Parâmetro vulnerável: q
4. Tipo de ataque: SQL Injection

[PROVA DE CONCEITO]
URL: https://target.com/api/search?q=test' OR '1'='1
Resposta: [dados sensíveis retornados]

[IMPACTO]
- Exposição de dados de usuários
- Possível escalação para RCE
- Violação de GDPR/compliance

[RECOMENDAÇÃO]
- Usar prepared statements
- Input validation rigorosa
- WAF para proteção em tempo real

[TIMELINE]
- 2024-01-15: Vulnerability discovered
- 2024-01-16: Report submitted
- 2024-02-15: Target given 30 days to fix
- 2024-03-15: Expected patch deployment
```

---

## 🔍 Troubleshooting {#troubleshooting}

### Problema: "Nuclei not found"
```bash
# Solução: Adicionar à PATH
export PATH=$PATH:~/go/bin

# Ou instalar novamente
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### Problema: "Too many requests (429)"
```python
# Aumentar delays
agent = BountyAgent()
agent.fuzzer.min_delay = 2.0
agent.fuzzer.max_delay = 5.0
agent.fuzzer.max_requests_per_minute = 15
```

### Problema: "Connection timeout"
```python
# Usar proxy ou aumentar timeout
agent = BountyAgent(proxy="http://proxy.local:8080")

# Ou aumentar timeout
async with httpx.AsyncClient(timeout=30.0) as client:
    # requisições
```

### Problema: "WAF bloqueando requests"
```python
# 1. Adicionar mais delays
delays = [1, 2, 3, 4, 5]
for delay in delays:
    await asyncio.sleep(delay)
    # fazer requisição

# 2. Usar diferentes User-Agents
# (já implementado, mas pode customizar)

# 3. Considerar legitimate proxies
# (apenas para testing autorizado)

# 4. Aguardar e retentar
await asyncio.sleep(300)  # 5 minutos
```

### Problema: "Out of memory"
```python
# Limitar concurrent operations
semaphore = asyncio.Semaphore(5)

async def limited_fuzz():
    async with semaphore:
        # fuzzing com limite
```

---

## 📊 Métricas e Relatórios

### Exemplo de Saída
```
╔════════════════════════════════════════════════════════════════╗
║                     BUG BOUNTY REPORT                          ║
╚════════════════════════════════════════════════════════════════╝

TARGET: https://example-bounty.com
TIMESTAMP: 2024-01-20T15:30:00

📊 SUMÁRIO
  • Endpoints encontrados: 12
  • Nuclei findings: 3
  • Fuzzing findings: 1

🛡️  WAF DETECTION
  • Detectados: CloudFlare
  • Protegido: Sim

🔴 NUCLEI FINDINGS (3)
  [HIGH] SQL Injection in /api/search
    URL: https://example-bounty.com/api/search
    Descrição: Entrada não sanitizada em parâmetro q

  [MEDIUM] XSS Reflected in /comment
    URL: https://example-bounty.com/comment
    Descrição: Escaping inadequado de input HTML
```

---

## 🎓 Recursos Adicionais

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Nuclei Templates**: https://github.com/projectdiscovery/nuclei-templates
- **HackerOne Guides**: https://www.hackerone.com/knowledge-center
- **Bugcrowd University**: https://www.bugcrowd.com/university/
- **PortSwigger Web Security**: https://portswigger.net/web-security

---

## 📞 Suporte

Para problemas:
1. Verificar logs em `logs/`
2. Aumentar verbosidade: `--verbose`
3. Consultar documentação do Nuclei: `nuclei -h`
4. Community: PortSwigger Academy, Hack The Box

---

**Lembrete**: Sempre test responsavelmente. Bug bounty é sobre encontrar e reportar vulnerabilidades, não explorar sistemas. 🛡️

