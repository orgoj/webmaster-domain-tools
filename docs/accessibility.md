# Accessibility Analyzer

WCAG 2.1 AA compliance checker for web accessibility.

## Overview

The Accessibility analyzer performs static HTML analysis to identify accessibility issues according to WCAG 2.1 guidelines at the AA level.

## Usage

```bash
# Run accessibility audit only
wdt analyze example.com --only accessibility

# Run with other analyzers
wdt analyze example.com --only http,accessibility

# JSON output
wdt analyze example.com --only accessibility --format json
```

## Checks Performed

### 1. Images (WCAG 1.1.1 - Non-text Content)

- Detects images missing `alt` attributes
- Recognizes decorative images (`alt=""` or `role="presentation"`)
- Checks for alternative text via `aria-label` or `title`

**Compliance Level:** A

### 2. Headings (WCAG 1.3.1 - Info and Relationships)

- Verifies presence of H1 heading
- Checks for multiple H1 headings (should be only one)
- Validates heading hierarchy (no skipped levels: H1 → H3)

**Compliance Level:** A/AA

### 3. Links (WCAG 2.4.4 - Link Purpose)

- Detects empty links (no text content)
- Identifies generic link text ("click here", "read more", etc.)
- Checks for `aria-label` alternatives

**Compliance Level:** A

### 4. Forms (WCAG 1.3.1, 4.1.2)

- Validates form fields have associated labels
- Checks for `for` attribute on `<label>` elements
- Recognizes `aria-label` and `aria-labelledby` alternatives
- Warns about placeholder-only labeling

**Compliance Level:** A

### 5. Keyboard Accessibility (WCAG 2.1.1)

- Detects positive `tabindex` values (discouraged)
- Identifies potential keyboard accessibility issues

**Compliance Level:** A

### 6. Language (WCAG 3.1.1 - Language of Page)

- Checks for `lang` attribute on `<html>` element

**Compliance Level:** A

## Scoring

The accessibility score ranges from 0-100:

| Score | Status |
|-------|--------|
| 90-100 | Excellent - Minor or no issues |
| 75-89 | Good - Some improvements needed |
| 50-74 | Needs Work - Significant issues |
| 0-49 | Poor - Major accessibility problems |

### Scoring Factors

- **Errors:** -10 points each
- **Warnings:** -3 points each
- **Proper H1:** +5 points
- **Good alt coverage (≥90%):** +5 points
- **Language specified:** +5 points

## Output Example

```
Accessibility Audit

  Accessibility Score: ✓ 100/100
  Issues: 1 (1 errors, 0 warnings)
  
  Images (WCAG 1.1.1)
    Alt Tags: 37/37
    
  Headings (WCAG 1.3.1)
    H1 Count: 1
    
  Links (WCAG 2.4.4)
    Descriptive: 23/23
    
  Forms (WCAG 1.3.1)
    Labels: 4/4
```

## Configuration

Add to `default_config.toml`:

```toml
[accessibility]
enabled = true
wcag_level = "aa"
check_alt_tags = true
check_aria = true
check_headings = true
check_forms = true
check_links = true
check_keyboard = true
max_links_to_check = 100
max_images_to_check = 100
```

## Limitations

### Static Analysis Only

This analyzer performs **static HTML analysis**. It cannot detect:

- **Color contrast issues** - Requires computed styles
- **Dynamic content** - JavaScript-rendered content not analyzed
- **Focus indicators** - Visual focus states not checked
- **Screen reader testing** - Actual screen reader behavior varies

### Recommendations for Full Audit

For comprehensive accessibility testing, combine this analyzer with:

1. **axe-core** - Browser extension for detailed analysis
2. **Lighthouse** - Chrome DevTools accessibility audit
3. **WAVE** - Web Accessibility Evaluation Tool
4. **Manual testing** - Keyboard navigation, screen reader testing

## WCAG Reference

| Criterion | Level | Description |
|-----------|-------|-------------|
| 1.1.1 | A | Non-text Content |
| 1.3.1 | A | Info and Relationships |
| 2.1.1 | A | Keyboard |
| 2.4.3 | A | Focus Order |
| 2.4.4 | A | Link Purpose (In Context) |
| 2.4.6 | AA | Headings and Labels |
| 3.1.1 | A | Language of Page |
| 4.1.2 | A | Name, Role, Value |

## Dependencies

This analyzer depends on:
- `http` - To determine the accessible URL
