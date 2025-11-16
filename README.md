# Webmaster Domain Tool

Komplexní nástroj pro webmastery, který analyzuje a přehledně zobrazuje všechny důležité informace o doméně.

## Funkce

### DNS Analýza
- ✅ A/AAAA záznamy (IPv4/IPv6)
- ✅ MX záznamy (mail servery)
- ✅ TXT záznamy
- ✅ NS záznamy (nameservery)
- ✅ SOA záznamy
- ✅ CAA záznamy (Certificate Authority Authorization)
- ✅ CNAME záznamy
- ✅ **DNSSEC validace**
  - Kontrola DNSKEY a DS záznamů
  - Validace chain of trust
  - Upozornění na neplatnou konfiguraci
- ✅ Kontrola domény i www varianty

### HTTP/HTTPS Analýza
- ✅ Testování všech variant (http/https, s/bez www)
- ✅ Sledování všech redirectů v řetězci
- ✅ Detailní informace o každém kroku
- ✅ Kontrola response časů
- ✅ Detekce problémů s redirecty
- ✅ Upozornění na insecure HTTP

### SSL/TLS Certifikáty
- ✅ Validace certifikátů
- ✅ Kontrola platnosti a expirace
- ✅ Informace o vydavateli (issuer)
- ✅ Subject Alternative Names (SAN)
- ✅ Počet dnů do expirace
- ✅ Podpora TLS protokolů (1.0, 1.1, 1.2, 1.3)
- ✅ Upozornění na deprecated protokoly

### Email Security
- ✅ **SPF** (Sender Policy Framework)
  - Validace SPF záznamu
  - Analýza mechanismů
  - Kontrola politiky (soft fail / hard fail)
- ✅ **DKIM** (DomainKeys Identified Mail)
  - Kontrola DKIM selektorů
  - Validace public key
  - Podpora vlastních selektorů
- ✅ **DMARC** (Domain-based Message Authentication)
  - Validace DMARC politiky
  - Kontrola reportovacích adres
  - Analýza subdomain politiky

### RBL (Realtime Blacklist) Check
- ✅ Kontrola IP adres proti blacklistům
- ✅ Podpora hlavních RBL služeb
  - Spamhaus ZEN
  - SpamCop
  - Barracuda Central
  - SORBS
- ✅ Kontrola A záznamů i MX serverů
- ✅ Konfigurovatelné RBL servery

### Security Headers
- ✅ Strict-Transport-Security (HSTS)
- ✅ Content-Security-Policy (CSP)
- ✅ X-Frame-Options
- ✅ X-Content-Type-Options
- ✅ Referrer-Policy
- ✅ Permissions-Policy
- ✅ X-XSS-Protection
- ✅ Content-Type
- ✅ Security score (0-100)
- ✅ Detailní doporučení pro každý header

## Instalace

### Přes uvx (doporučeno)

Spuštění přímo z gitu bez instalace:

```bash
uvx --from git+https://github.com/orgoj/webmaster-domain-tool webmaster-domain-tool analyze example.com
```

Nebo zkrácený alias:

```bash
uvx --from git+https://github.com/orgoj/webmaster-domain-tool wdt analyze example.com
```

### Instalace přes uv

```bash
uv tool install git+https://github.com/orgoj/webmaster-domain-tool
```

### Instalace z lokálního projektu (pro vývoj)

```bash
git clone https://github.com/orgoj/webmaster-domain-tool.git
cd webmaster-domain-tool
uv sync
```

Spuštění v dev módu:

```bash
uv run webmaster-domain-tool analyze example.com
```

## Použití

### Základní použití

```bash
webmaster-domain-tool analyze example.com
```

Nebo zkrácený příkaz:

```bash
wdt analyze example.com
```

### Konfigurace

Nástroj podporuje konfigurační soubory pro defaultní nastavení:

```bash
# Vytvoření user config souboru
wdt create-config

# Config bude vytvořen v ~/.config/webmaster-domain-tool/config.toml
```

**Pořadí načítání configu** (vyšší přepisuje nižší):
1. Package default config
2. System-wide config (`/etc/webmaster-domain-tool/config.toml`)
3. User config (`~/.config/webmaster-domain-tool/config.toml`)
4. Home config (`~/.webmaster-domain-tool.toml`)
5. Local config (`.webmaster-domain-tool.toml` v aktuálním adresáři)
6. **CLI parametry mají vždy přednost!**

**Vlastní config file:**

```bash
# Použití vlastního config souboru
wdt analyze --config /path/to/config.toml example.com
wdt analyze -c myconfig.toml example.com
```

**Příklad konfigurace:**

```toml
[dns]
nameservers = ["1.1.1.1", "8.8.8.8"]
timeout = 5.0
check_dnssec = true

[http]
timeout = 10.0
max_redirects = 10

[email]
dkim_selectors = ["default", "google", "k1"]
check_rbl = true
rbl_servers = ["zen.spamhaus.org", "bl.spamcop.net"]

[output]
color = true
verbosity = "normal"  # quiet, normal, verbose, debug

[analysis]
skip_dns = false
skip_email = false
```

### Možnosti

#### Verbosity (úrovně výstupu)

```bash
# Quiet mode - pouze chyby
wdt analyze --quiet example.com
wdt analyze -q example.com

# Normal mode - default
wdt analyze example.com

# Verbose mode - detailní informace
wdt analyze --verbose example.com
wdt analyze -v example.com

# Debug mode - velmi detailní výstup
wdt analyze --debug example.com
wdt analyze -d example.com
```

#### Přeskočení určitých kontrol

```bash
# Přeskočit DNS analýzu
wdt analyze --skip-dns example.com

# Přeskočit HTTP/HTTPS analýzu
wdt analyze --skip-http example.com

# Přeskočit SSL/TLS analýzu
wdt analyze --skip-ssl example.com

# Přeskočit email security (SPF, DKIM, DMARC)
wdt analyze --skip-email example.com

# Přeskočit security headers
wdt analyze --skip-headers example.com

# Kombinace - pouze DNS a SSL
wdt analyze --skip-http --skip-email --skip-headers example.com
```

#### DKIM selektory

Standardně se kontrolují běžné selektory (default, google, k1, k2, selector1, selector2, dkim, mail, s1, s2).
Můžete specifikovat vlastní selektory:

```bash
# Vlastní DKIM selektory
wdt analyze --dkim-selectors "selector1,selector2,custom" example.com
```

#### HTTP nastavení

```bash
# Vlastní timeout (default: 10s)
wdt analyze --timeout 5 example.com
wdt analyze -t 5 example.com

# Maximální počet redirectů (default: 10)
wdt analyze --max-redirects 5 example.com
```

#### DNS nastavení

```bash
# Vlastní DNS servery
wdt analyze --nameservers "8.8.8.8,1.1.1.1" example.com
```

#### RBL (Blacklist) kontrola

```bash
# Vypnout RBL kontrolu
wdt analyze --no-check-rbl example.com

# Zapnout RBL kontrolu (pokud je vypnutá v configu)
wdt analyze --check-rbl example.com
```

Standardně se kontrolují:
- Spamhaus ZEN (`zen.spamhaus.org`)
- SpamCop (`bl.spamcop.net`)
- Barracuda Central (`b.barracudacentral.org`)
- SORBS (`dnsbl.sorbs.net`)

Vlastní RBL servery můžete nastavit v config souboru.

#### Output nastavení

```bash
# Vypnout barevný výstup
wdt analyze --no-color example.com
```

### Příklady komplexního použití

```bash
# Rychlá kontrola s vlastními DNS servery
wdt analyze --nameservers "1.1.1.1,8.8.8.8" example.com

# Detailní analýza s debug výstupem
wdt analyze --debug --timeout 15 example.com

# Pouze email security s vlastními DKIM selektory
wdt analyze --skip-dns --skip-http --skip-ssl --skip-headers \
    --dkim-selectors "google,default,mail" example.com

# Verbose výstup bez barev (pro logování)
wdt analyze -v --no-color example.com > domain-report.txt

# Rychlá kontrola bez email security
wdt analyze --skip-email --timeout 5 example.com
```

## Výstup

Nástroj zobrazuje přehledný barevný výstup rozdělený do sekcí:

### 1. DNS Records
- Tabulka všech DNS záznamů pro doménu i www.doménu
- TTL hodnoty
- **DNSSEC status** (enabled/disabled, validace)
- Warnings pro chybějící nebo problematické záznamy

### 2. HTTP/HTTPS Analysis
- Strom redirectů pro každou URL variantu
- Status kódy s barvami (zelená 200, žlutá 3xx, červená 4xx/5xx)
- Response časy
- Upozornění na insecure redirecty

### 3. SSL/TLS Certificates
- Detaily certifikátů (subject, issuer)
- Platnost a expirace (barevné podle urgence)
- SAN (Subject Alternative Names)
- Podporované TLS protokoly
- Warnings pro expired nebo brzy expirující certifikáty

### 4. Email Security
- ✅/✗ status pro SPF, DKIM, DMARC
- Detaily záznamů
- Validace a doporučení
- Warnings pro slabé konfigurace

### 5. Security Headers
- Security score (0-100)
- Tabulka všech security headers
- Doporučení pro chybějící headers
- Detailní warnings pro každý header

### 6. RBL (Blacklist) Check
- Tabulka kontrolovaných IP adres
- Status každé IP (CLEAN / LISTED)
- Seznam blacklistů kde je IP nalezena
- Warnings pro nalezené blacklisty

### 7. Summary
- Celkový počet chyb a warnings
- Přehledné shrnutí

## Požadavky

- Python 3.10+
- Dependencies (automaticky instalované):
  - `dnspython` - DNS dotazy a DNSSEC validace
  - `httpx` - HTTP requesty
  - `cryptography` - SSL/TLS analýza
  - `rich` - barevný terminálový výstup
  - `typer` - CLI framework
  - `pydantic` - validace dat a settings
  - `tomli` - TOML config parser (Python <3.11)

## Vývoj

### Setup vývojového prostředí

```bash
git clone https://github.com/orgoj/webmaster-domain-tool.git
cd webmaster-domain-tool
uv sync --dev
```

### Spuštění testů

```bash
uv run pytest
```

### Code quality

```bash
# Black formatting
uv run black src/

# Ruff linting
uv run ruff check src/

# Type checking
uv run mypy src/
```

## Struktura projektu

```
webmaster-domain-tool/
├── src/
│   └── webmaster_domain_tool/
│       ├── __init__.py
│       ├── cli.py                 # CLI interface (Typer)
│       ├── config.py              # Config management
│       ├── default_config.toml    # Default configuration
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── dns_analyzer.py        # DNS analýza + DNSSEC
│       │   ├── http_analyzer.py       # HTTP/HTTPS analýza
│       │   ├── ssl_analyzer.py        # SSL/TLS analýza
│       │   ├── email_security.py      # SPF, DKIM, DMARC
│       │   ├── security_headers.py    # Security headers
│       │   └── rbl_checker.py         # RBL blacklist check
│       └── utils/
│           ├── __init__.py
│           ├── logger.py       # Logging setup
│           └── output.py       # Rich output formatting
├── tests/
├── pyproject.toml
├── LICENSE
└── README.md
```

## Roadmap / Budoucí vylepšení

- [x] **DNSSEC validace** ✅
- [x] **RBL (blacklist) kontrola** ✅
- [x] **Config soubor pro defaultní nastavení** ✅
- [ ] Export do JSON/YAML/HTML formátu
- [ ] Kontrola robots.txt / sitemap.xml
- [ ] Batch analýza více domén
- [ ] Continuous monitoring s alertingem
- [ ] Web UI / API
- [ ] Plugin systém pro vlastní analyzery

## Přispívání

Pull requesty jsou vítány! Pro větší změny prosím nejprve otevřete issue pro diskuzi.

## Licence

MIT

## Autor

Webmaster Tools

## Podpora

Pro bugy a feature requesty použijte [GitHub Issues](https://github.com/orgoj/webmaster-domain-tool/issues).
