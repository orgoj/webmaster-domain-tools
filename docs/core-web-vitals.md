# Core Web Vitals Analyzer

Analyzátor Core Web Vitals pro Webmaster Domain Tools.

## Přehled

Tento analyzátor měří klíčové metrix výkonu webu pomocí Google PageSpeed Insights API:

- **LCP** (Largest Contentful Paint) - čas do vykreslení největšího obsahu
- **INP** (Interaction to Next Paint) - rychlost odezvy na interakce (nahrazuje FID)
- **CLS** (Cumulative Layout Shift) - vizuální stabilita stránky

## Použití

### Základní analýza

```bash
wdt analyze example.com --only core-web-vitals
```

### S dalšími analyzátory

```bash
wdt analyze example.com --skip whois
```

### JSON výstup

```bash
wdt analyze example.com --only core-web-vitals --format json
```

### Verbose mód

```bash
wdt analyze example.com --only core-web-vitals -v verbose
```

## Metriky

### LCP (Largest Contentful Paint)

Měří čas do vykreslení největšího vizuálního elementu na stránce.

| Hodnocení | Hodnota |
|-----------|---------|
| ✅ Good | ≤ 2.5s |
| ⚠️ Needs Improvement | ≤ 4.0s |
| ❌ Poor | > 4.0s |

### INP (Interaction to Next Paint)

Měří rychlost odezvy na interakce uživatele během celé návštěvy stránky.

| Hodnocení | Hodnota |
|-----------|---------|
| ✅ Good | ≤ 200ms |
| ⚠️ Needs Improvement | ≤ 500ms |
| ❌ Poor | > 500ms |

> **Poznámka:** INP je nová metrika nahrazující FID (First Input Delay).
> Pro stránky s nedostatečným provozem může být zobrazeno FID.

### CLS (Cumulative Layout Shift)

Měří vizuální stabilitu - jak moc se elementy posouvají během načítání.

| Hodnocení | Hodnota |
|-----------|---------|
| ✅ Good | ≤ 0.1 |
| ⚠️ Needs Improvement | ≤ 0.25 |
| ❌ Poor | > 0.25 |

## Zdroje dat

### Field Data (CrUX)

Real-world data od uživatelů Chrome z Chrome User Experience Report.
- Vyžaduje dostatečný provoz na stránce
- Odráží skutečnou zkušenost uživatelů

### Lab Data (Lighthouse)

Syntetická měření v kontrolovaném prostředí.
- Dostupná vždy
- Konzistentní výsledky
- Zahrnuje další metriky (TTFB, FCP, Speed Index, TTI)

## Konfigurace

Analyzátor lze konfigurovat v `.webmaster-domain-tool.toml`:

```toml
[analyzers.core-web-vitals]
enabled = true
timeout = 30.0
strategy = "desktop"  # nebo "mobile"
locale = "en"
# api_key = "YOUR_API_KEY"  # Volitelné - zvyšuje quota
```

### API Key

Google PageSpeed Insights API je zdarma, ale má denní limit požadavků.
Pro vyšší quota můžete nastavit vlastní API klíč:

1. Získejte API klíč z [Google Cloud Console](https://console.cloud.google.com/)
2. Povolte PageSpeed Insights API
3. Přidejte klíč do konfigurace

## Výstup

### Normalní mód

```
Core Web Vitals (Field Data)

  LCP (Largest Contentful Paint)     ✓ 1.2s
  INP (Interaction to Next Paint)    ✓ 85ms
  CLS (Cumulative Layout Shift)      ✓ 0.02

Performance Score

  Lighthouse Score                   95/100
```

### Verbose mód

Zahrnuje i lab data a target hodnoty.

### Debug mód

Zahrnuje diagnostiky, API info a další detaily.

## JSON Output

```json
{
  "domain": "example.com",
  "success": true,
  "performance_score": 95,
  "core_web_vitals": {
    "lcp": {
      "display_name": "LCP",
      "value": 1200,
      "unit": "ms",
      "rating": "good"
    },
    "inp": {
      "display_name": "INP",
      "value": 85,
      "unit": "ms",
      "rating": "good"
    },
    "cls": {
      "display_name": "CLS",
      "value": 0.02,
      "unit": "",
      "rating": "good"
    }
  },
  "opportunities": [...],
  "diagnostics": [...]
}
```

## Optimization Opportunities

Analyzátor také vrací seznam příležitostí pro optimalizaci:

- Eliminate render-blocking resources
- Properly size images
- Reduce unused JavaScript
- Remove unused CSS
- Serve images in next-gen formats
- a další...

## Chyby a varování

### No field data available

Stránka má nedostatečný provoz pro CrUX data.
- Field data nejsou k dispozici
- Použijte lab data (Lighthouse)

### API quota exceeded

Denní limit API byl vyčerpán.
- Počkejte na reset (GMT midnight)
- nebo použijte vlastní API klíč

## Implementační detaily

- Používá Google PageSpeed Insights API v5
- HTTP klient: httpx
- Timeout: 30s (konfigurovatelné)
- Podporuje desktop a mobile strategie

## Související zdroje

- [Web Vitals](https://web.dev/vitals/)
- [LCP](https://web.dev/lcp/)
- [INP](https://web.dev/inp/)
- [CLS](https://web.dev/cls/)
- [PageSpeed Insights API](https://developers.google.com/speed/docs/insights/v5/get-started)
