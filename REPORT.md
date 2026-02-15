# Webmaster Domain Tools - Analýza a Návrhy Vylepšení

## Datum: 2026-02-14
## Branch: nanobot

---

## 1. Současný Stav Nástroje

### 1.1 Architektura
Nástroj používá **modulární plugin systém** s následujícími komponentami:

- **Registry** (`core/registry.py`) - Automatická registrace analyzerů pomocí dekorátorů
- **Protocol** (`analyzers/protocol.py`) - Definice rozhraní `AnalyzerPlugin`
- **Config Manager** (`core/config_manager.py`) - Hierarchická konfigurace (TOML)
- **Renderery** - CLI, JSON, JSON Lines výstupy
- **GUI** - Flet-based aplikace (`flet_app.py`)

### 1.2 Existující Analyzátory

| ID | Název | Kategorie | Závislosti | Popis |
|----|------|-----------|------------|-------|
| `dns` | DNS Analysis | general | - | DNS záznamy, DNSSEC validace |
| `whois` | WHOIS Information | general | - | Registrace domény, expirace |
| `http` | HTTP/HTTPS Analysis | general | dns | Redirect chain, SSL verifikace |
| `ssl` | SSL/TLS Certificates | security | - | Certifikáty, TLS verze |
| `email` | Email Security | security | dns | SPF, DKIM, DMARC, BIMI, MTA-STS |
| `headers` | Security Headers | security | http | HTTP bezpečnostní hlavičky |
| `verification` | Site Verification | general | dns, http | Google, Facebook, Pinterest verify |
| `rbl` | RBL Blacklist Check | security | dns | IP blacklist kontrola |
| `cdn` | CDN Detection | general | dns | Detekce CDN providerů |
| `seo` | SEO Files | seo | http | robots.txt, sitemap.xml, llms.txt |
| `favicon` | Favicon Analysis | seo | http | Detekce a validace favicon |
| `html` | HTML Validator | seo | http | HTML validace, SEO, accessibility |
| `domain-validator` | Domain Config Validator | advanced | dns, http, email, cdn | Profilová validace infrastruktury |
| `social-media` | Social Media | seo | http | Open Graph, Twitter Cards |
| `performance` | Performance Analysis | performance | http | TTFB, velikost zdrojů, HTTP/2 |

### 1.3 CLI Příkazy

```bash
wdt analyze <domain>              # Analýza domény
wdt analyze --domain-file <file>  # Hromadná analýza
wdt analyze --only <analyzers>    # Pouze vybrané analyzátory
wdt analyze --skip <analyzers>    # Přeskočit analyzátory
wdt analyze --format json         # JSON výstup
wdt analyze --format jsonlines    # JSON Lines (pro bulk)
wdt list-analyzers                # Seznam analyzerů
wdt create-config                 # Vytvořit config
wdt create-validator-profile      # Wizard pro profil
wdt test-validator-profile        # Test profilu
wdt version                       # Verze
```

### 1.4 GUI Aplikace

- Flet-based desktop aplikace
- Spuštění: `wdt-app` nebo `uv run wdt-app`
- Podpora konfiguračních profilů (backend hotov, GUI částečně)

---

## 2. Návrhy Nových Analyzerů

### 2.1 Priorita: VYSOKÁ 🔴

#### 2.1.1 Core Web Vitals Analyzer (`core-web-vitals`)
**Kategorie:** performance  
**Závislosti:** http

**Co by dělal:**
- Měření LCP (Largest Contentful Paint)
- Měření FID (First Input Delay) / INP (Interaction to Next Paint)
- Měření CLS (Cumulative Layout Shift)
- Integrace s Google PageSpeed Insights API

**Proč je to důležité:**
- Core Web Vitals jsou ranking faktor Google
- Klienti často nevědí, jak si stojí
- Přímý dopad na SEO a UX

**Implementační přístupy:**
1. **API přístup** - Google PageSpeed Insights API (zdarma, s limity)
2. **Browser automation** - Playwright/Puppeteer (přesnější, ale těžší)
3. **Hybrid** - API pro základ, browser pro detaily

---

#### 2.1.2 Accessibility Audit Analyzer (`accessibility`)
**Kategorie:** compliance  
**Závislosti:** http

**Co by dělal:**
- WCAG 2.1 AA kontrola
- Kontrast barev
- Keyboard navigation check
- ARIA atributy validace
- Screen reader kompatibilita

**Proč je důležité:**
- Legislativní požadavky (EU Directive 2016/2102)
- E-commerce povinnosti
- ROI přes accessibility

**Implementační přístupy:**
1. **axe-core** - Integrace Deque axe engine (industry standard)
2. **Pa11y** - CLI nástroj pro accessibility
3. **Lighthouse** - Google Lighthouse accessibility audit

---

#### 2.1.3 Mobile Readiness Analyzer (`mobile`)
**Kategorie:** seo  
**Závislosti:** http

**Co by dělal:**
- Google Mobile-Friendly Test API
- Viewport meta kontrola
- Touch target velikosti
- Font size čitelnost
- Responsive design check

**Proč je důležité:**
- Mobile-first indexing
- Většina trafficu z mobilů
- Přímý dopad na SEO

---

### 2.2 Priorita: STŘEDNÍ 🟡

#### 2.2.1 Lighthouse Scores Analyzer (`lighthouse`)
**Kategorie:** performance  
**Závislosti:** http

**Co by dělal:**
- Performance score (0-100)
- Accessibility score
- Best Practices score
- SEO score
- PWA readiness

**Implementace:**
- Google PageSpeed Insights API
- Nebo Lighthouse CI pro lokální běh

---

#### 2.2.2 Broken Links Analyzer (`broken-links`)
**Kategorie:** seo  
**Závislosti:** http

**Co by dělal:**
- Kontrola interních odkazů
- Kontrola externích odkazů
- Detekce 404, 500, timeout
- Report broken redirectů

**Implementace:**
- Crawl HTML, extrahovat odkazy
- HEAD request pro rychlost
- Rate limiting pro externí domény

---

#### 2.2.3 Cookies & Consent Analyzer (`cookies-consent`)
**Kategorie:** compliance  
**Závislosti:** http

**Co by dělal:**
- Detekce cookies (session, persistent, third-party)
- Identifikace consent managerů (Cookiebot, OneTrust, etc.)
- GDPR compliance indikátory
- Kategorizace cookies (necessary, analytics, marketing)

**Proč je důležité:**
- GDPR/ePrivacy compliance
- Consent Mode v Google Analytics
- Riziko pokut

---

#### 2.2.4 Third-party Audit Analyzer (`thirdparty`)
**Kategorie:** security  
**Závislosti:** http

**Co by dělal:**
- Seznam všech externích domén
- Tracking scripts (GA, GTM, Facebook Pixel)
- Advertising networks
- Social media integrations
- Risk assessment third parties

**Proč je důležité:**
- Security risk assessment
- Performance impact
- Privacy compliance

---

#### 2.2.5 Technology Stack Detector (`technology`)
**Kategorie:** general  
**Závislosti:** http

**Co by dělal:**
- CMS detekce (WordPress, Drupal, Joomla)
- JS frameworks (React, Vue, Angular, Next.js)
- Analytics tools (GA4, GTM, Matomo)
- Advertising platforms
- Server technology (nginx, Apache, Cloudflare)

**Implementace:**
- Wappalyzer-style detection
- HTTP headers analysis
- HTML meta tags
- JS global variables

---

### 2.3 Priorita: NÍZKÁ 🟢

#### 2.3.1 Structured Data Validator (`structured-data`)
**Kategorie:** seo  
**Závislosti:** http

**Co by dělal:**
- JSON-LD detekce a validace
- Schema.org markup kontrola
- Rich snippets typy (Product, Article, FAQ, etc.)
- Google Rich Results Test API

---

#### 2.3.2 Security Vulnerability Scanner (`security-vulns`)
**Kategorie:** security  
**Závislosti:** http, technology

**Co by dělal:**
- Zjištění verze CMS/frameworků
- CVE database lookup
- Known vulnerabilities report
- Recommendations

**Implementace:**
- CVE NVD API
- WPScan API pro WordPress
- Snyk vulnerability DB

---

#### 2.3.3 Content Quality Analyzer (`content-quality`)
**Kategorie:** seo  
**Závislosti:** http

**Co by dělal:**
- Word count
- Readability score (Flesch-Kincaid)
- Duplicate content check
- Keyword density
- Heading structure analysis

---

#### 2.3.4 Internationalization Checker (`i18n`)
**Kategorie:** seo  
**Závislosti:** http

**Co by dělal:**
- hreflang tags
- Language declarations
- RTL support
- Localized content detection

---

## 3. Možné Přístupy k Implementaci

### 3.1 API Integrace (Doporučeno pro začátek)

**Výhody:**
- Rychlá implementace
- Přesná data od Google
- Žádná údržba browser automation

**Nevýhody:**
- Rate limits
- Závislost na externí službě
- Možné náklady při vysokém volumenu

**Dostupná API:**
- Google PageSpeed Insights API (zdarma, 25k calls/day)
- Google Mobile-Friendly Test API
- Mozilla Observatory API
- SSL Labs API
- Security Headers API

### 3.2 Browser Automation (Playwright)

**Výhody:**
- Plná kontrola
- Přesná měření
- Offline capable

**Nevýhody:**
- Složitější implementace
- Vyšší nároky na zdroje
- Delší běh

**Použití pro:**
- Core Web Vitals (přesná měření)
- Accessibility audit (axe-core)
- Screenshots

### 3.3 Statická Analýza (pouze HTML)

**Výhody:**
- Rychlá
- Lehká
- Žádné externí závislosti

**Nevýhody:**
- Omezená přesnost
- Neodhalí JS-renderovaný obsah

**Použití pro:**
- SEO checks
- Basic accessibility
- Structured data
- Technology detection

### 3.4 Hybridní Přístup (Doporučeno)

```
┌─────────────────────────────────────────────────────────────┐
│                    ANALYZER PIPELINE                        │
├─────────────────────────────────────────────────────────────┤
│  1. FAST CHECKS (static HTML analysis)                      │
│     - SEO elements, meta tags, headings                     │
│     - Basic accessibility (alt tags, lang, semantic HTML)   │
│     - Technology detection                                  │
│     - Structured data                                       │
│                                                             │
│  2. MEDIUM CHECKS (HTTP-based)                              │
│     - Performance (TTFB, size, HTTP/2)                      │
│     - Security headers                                      │
│     - Broken links (sampling)                               │
│     - Cookies detection                                     │
│                                                             │
│  3. DEEP CHECKS (optional, API/automation)                  │
│     - Core Web Vitals (PageSpeed API)                       │
│     - Full accessibility audit (axe-core)                   │
│     - Mobile readiness (Google API)                         │
│     - Lighthouse scores                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Konkrétní Implementační Plán

### Fáze 1: Rychlé výhry (1-2 týdny)

| Analyzátor | Přístup | Úsilí | ROI |
|------------|---------|-------|-----|
| Technology Detector | Statická analýza | 4h | Vysoké |
| Cookies/Consent | HTML parsing | 6h | Vysoké |
| Structured Data | JSON-LD parsing | 4h | Střední |
| Broken Links (sampling) | HTTP HEAD | 8h | Vysoké |

### Fáze 2: API integrace (2-3 týdny)

| Analyzátor | API | Úsilí | Poznámky |
|------------|-----|-------|----------|
| Core Web Vitals | PageSpeed Insights | 8h | Cache výsledků |
| Mobile Readiness | Mobile-Friendly API | 4h | Rate limit |
| Lighthouse | PageSpeed Insights | 4h | Stejné API |

### Fáze 3: Advanced (3-4 týdny)

| Analyzátor | Přístup | Úsilí | Poznámky |
|------------|---------|-------|----------|
| Accessibility | axe-core + Playwright | 16h | Nejkomplexnější |
| Security Vulnerabilities | CVE API | 12h | Needs version detection |
| Third-party Audit | HTML analysis + risk DB | 8h | Build domain database |

---

## 5. Konfigurace Nových Analyzerů

### Příklad konfigurace pro `default_config.toml`:

```toml
# -----------------------------------------------------------------------------
# Core Web Vitals (via PageSpeed Insights API)
# -----------------------------------------------------------------------------
[core-web-vitals]
enabled = true
# API key (optional, increases rate limits)
api_key = ""
# Cache results for N seconds (default: 1 hour)
cache_ttl = 3600
# Strategy: "mobile" or "desktop"
strategy = "mobile"
# Categories to check
check_lcp = true
check_fid = true  # or INP
check_cls = true

# -----------------------------------------------------------------------------
# Accessibility Audit
# -----------------------------------------------------------------------------
[accessibility]
enabled = true
# WCAG level: "a", "aa", "aaa"
wcag_level = "aa"
# Check types
check_contrast = true
check_keyboard = true
check_aria = true
check_alt_tags = true
check_labels = true
# Max pages to check (for multi-page sites)
max_pages = 1

# -----------------------------------------------------------------------------
# Mobile Readiness
# -----------------------------------------------------------------------------
[mobile]
enabled = true
# Use Google Mobile-Friendly API
use_api = true
api_key = ""
# Static checks (no API needed)
check_viewport = true
check_touch_targets = true
check_font_size = true

# -----------------------------------------------------------------------------
# Cookies & Consent
# -----------------------------------------------------------------------------
[cookies-consent]
enabled = true
# Detect cookies
detect_cookies = true
# Known consent managers
detect_consent_managers = true
# Check for privacy policy link
check_privacy_link = true

# -----------------------------------------------------------------------------
# Third-party Audit
# -----------------------------------------------------------------------------
[thirdparty]
enabled = true
# Categorize third parties
categorize = true
# Risk assessment
assess_risk = true
# Known trackers database
use_tracker_database = true

# -----------------------------------------------------------------------------
# Technology Detection
# -----------------------------------------------------------------------------
[technology]
enabled = true
# Detection depth
check_cms = true
check_frameworks = true
check_analytics = true
check_advertising = true
check_servers = true
```

---

## 6. Shrnutí

### Co už nástroj umí (15 analyzerů):
✅ DNS analýza s DNSSEC  
✅ WHOIS informace  
✅ HTTP/HTTPS redirect chain  
✅ SSL/TLS certifikáty  
✅ Email security (SPF, DKIM, DMARC, BIMI, MTA-STS)  
✅ Security headers  
✅ Site verification  
✅ RBL blacklist check  
✅ CDN detekce  
✅ SEO files (robots, sitemap, llms.txt)  
✅ Favicon analýza  
✅ HTML validace + základní accessibility  
✅ Social media (OG, Twitter Cards)  
✅ Performance (TTFB, velikosti, HTTP/2)  
✅ Domain config validator  

### Co chybí (prioritizováno):

**🔴 VYSOKÁ PRIORITA:**
1. Core Web Vitals - ranking faktor
2. Accessibility Audit - legislativa
3. Mobile Readiness - mobile-first

**🟡 STŘEDNÍ PRIORITA:**
4. Lighthouse scores - komplexní overview
5. Broken links - UX a SEO
6. Cookies/Consent - GDPR
7. Third-party audit - security + privacy
8. Technology detection - competitive analysis

**🟢 NÍZKÁ PRIORITA:**
9. Structured data - rich snippets
10. Security vulnerabilities - advanced security
11. Content quality - SEO content
12. Internationalization - multi-language

### Doporučený postup:
1. Začít s **Technology Detector** (snadné, vysoká hodnota)
2. Přidat **Cookies/Consent** (GDFO compliance)
3. Integrovat **PageSpeed Insights API** pro Core Web Vitals
4. Implementovat **Accessibility** s axe-core

---

*Report vytvořen nanobotem - analýza bez commitování*
