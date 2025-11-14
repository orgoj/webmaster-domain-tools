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
uvx --from git+https://github.com/orgoj/webmaster-domain-tool webmaster-domain-tool example.com
```

Nebo zkrácený alias:

```bash
uvx --from git+https://github.com/orgoj/webmaster-domain-tool wdt example.com
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
uv run webmaster-domain-tool example.com
```

## Použití

### Základní použití

```bash
webmaster-domain-tool example.com
```

Nebo zkrácený příkaz:

```bash
wdt example.com
```

### Možnosti

#### Verbosity (úrovně výstupu)

```bash
# Quiet mode - pouze chyby
wdt --quiet example.com
wdt -q example.com

# Normal mode - default
wdt example.com

# Verbose mode - detailní informace
wdt --verbose example.com
wdt -v example.com

# Debug mode - velmi detailní výstup
wdt --debug example.com
wdt -d example.com
```

#### Přeskočení určitých kontrol

```bash
# Přeskočit DNS analýzu
wdt --skip-dns example.com

# Přeskočit HTTP/HTTPS analýzu
wdt --skip-http example.com

# Přeskočit SSL/TLS analýzu
wdt --skip-ssl example.com

# Přeskočit email security (SPF, DKIM, DMARC)
wdt --skip-email example.com

# Přeskočit security headers
wdt --skip-headers example.com

# Kombinace - pouze DNS a SSL
wdt --skip-http --skip-email --skip-headers example.com
```

#### DKIM selektory

Standardně se kontrolují běžné selektory (default, google, k1, k2, selector1, selector2, dkim, mail, s1, s2).
Můžete specifikovat vlastní selektory:

```bash
# Vlastní DKIM selektory
wdt --dkim-selectors "selector1,selector2,custom" example.com
```

#### HTTP nastavení

```bash
# Vlastní timeout (default: 10s)
wdt --timeout 5 example.com
wdt -t 5 example.com

# Maximální počet redirectů (default: 10)
wdt --max-redirects 5 example.com
```

#### DNS nastavení

```bash
# Vlastní DNS servery
wdt --nameservers "8.8.8.8,1.1.1.1" example.com
```

#### Output nastavení

```bash
# Vypnout barevný výstup
wdt --no-color example.com
```

### Příklady komplexního použití

```bash
# Rychlá kontrola s vlastními DNS servery
wdt --nameservers "1.1.1.1,8.8.8.8" example.com

# Detailní analýza s debug výstupem
wdt --debug --timeout 15 example.com

# Pouze email security s vlastními DKIM selektory
wdt --skip-dns --skip-http --skip-ssl --skip-headers \
    --dkim-selectors "google,default,mail" example.com

# Verbose výstup bez barev (pro logování)
wdt -v --no-color example.com > domain-report.txt

# Rychlá kontrola bez email security
wdt --skip-email --timeout 5 example.com
```

## Výstup

Nástroj zobrazuje přehledný barevný výstup rozdělený do sekcí:

### 1. DNS Records
- Tabulka všech DNS záznamů pro doménu i www.doménu
- TTL hodnoty
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

### 6. Summary
- Celkový počet chyb a warnings
- Přehledné shrnutí

## Požadavky

- Python 3.10+
- Dependencies (automaticky instalované):
  - `dnspython` - DNS dotazy
  - `httpx` - HTTP requesty
  - `cryptography` - SSL/TLS analýza
  - `rich` - barevný terminálový výstup
  - `typer` - CLI framework
  - `pydantic` - validace dat

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
│       ├── cli.py              # CLI interface (Typer)
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── dns_analyzer.py        # DNS analýza
│       │   ├── http_analyzer.py       # HTTP/HTTPS analýza
│       │   ├── ssl_analyzer.py        # SSL/TLS analýza
│       │   ├── email_security.py      # SPF, DKIM, DMARC
│       │   └── security_headers.py    # Security headers
│       └── utils/
│           ├── __init__.py
│           ├── logger.py       # Logging setup
│           └── output.py       # Rich output formatting
├── tests/
├── pyproject.toml
└── README.md
```

## Roadmap / Budoucí vylepšení

- [ ] Export do JSON/YAML/HTML formátu
- [ ] Kontrola blacklistů (RBL)
- [ ] DNS DNSSEC validace
- [ ] Kontrola robots.txt / sitemap.xml
- [ ] Batch analýza více domén
- [ ] Config soubor pro defaultní nastavení
- [ ] Continuous monitoring s alertingem
- [ ] Web UI / API

## Přispívání

Pull requesty jsou vítány! Pro větší změny prosím nejprve otevřete issue pro diskuzi.

## Licence

MIT

## Autor

Webmaster Tools

## Podpora

Pro bugy a feature requesty použijte [GitHub Issues](https://github.com/orgoj/webmaster-domain-tool/issues).
