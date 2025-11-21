# Environment Diagnostic Tool

Tento adresář obsahuje diagnostický script pro porovnání Python/Flet prostředí.

## Účel

Debugovat problém, proč `ft.Colors.GREEN` existuje v jednom prostředí, ale ne v druhém, přestože oba mají:
- Python 3.13.8
- Flet 0.28.3
- Stejný uv.lock

## Použití

```bash
# Spusť diagnostic script
uv run python3 env_test/check_environment.py

# Výstup se uloží do:
env_test/environment.json
```

## Co script zjišťuje

1. **Python info**: verze, executable path, platform
2. **Flet info**: verze, module path, dostupné Colors
3. **ft.Colors attributes**: všechny dostupné barvy (mělo by být 381)
4. **File hashes**: kontrolní součty Flet souborů
5. **GREEN colors**: seznam všech GREEN* variant

## Porovnání

1. **Claude spustí** script → vytvoří `environment.json`
2. **Uživatel spustí** script → vytvoří svůj `environment.json`
3. **Diff:** porovnáme oba soubory a najdeme rozdíl

## Očekávané výsledky

U Claude (funguje):
```
ft.Colors.GREEN exists: True
Total Colors attributes: 381
GREEN-related colors: ['GREEN', 'GREEN_100', ..., 'LIGHT_GREEN_ACCENT_700']
```

U uživatele (nefunguje):
```
ft.Colors.GREEN exists: False
Total Colors attributes: ???
GREEN-related colors: ???
```

Rozdíl v těchto datech nám prozradí, co je špatně.
