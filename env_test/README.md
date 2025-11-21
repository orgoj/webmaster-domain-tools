# Environment Comparison Tool

Nástroj pro porovnání kompletních Python/Flet prostředí mezi Claude a Michaelem.

## 🎯 Cíl

Najít **JAKÝKOLIV** rozdíl mezi prostředími - nejen ft.Colors.GREEN, ale úplně všechno:
- Python verze a cesty
- Flet verze a cesty
- Všechny dostupné Colors
- File hashe Flet modulů
- Package verze
- Platformové info

## 📁 Struktura

```
env_test/
├── check_environment.py       # Script pro generování snapshotů
├── compare_environments.py    # Script pro porovnání
├── claude/
│   └── environment.json       # Claude snapshot (už commitnutý)
├── michael/
│   └── environment.json       # Michael snapshot (TY VYTVOŘÍŠ)
└── diff_report.txt           # Výsledek porovnání
```

## 🔧 Kroky pro Michaela

### 1. Stáhni nejnovější změny

```bash
git pull
```

### 2. Vygeneruj SVŮJ environment snapshot

**DŮLEŽITÉ: Použij `uv run`, NE systémový python3!**

```bash
uv run python3 env_test/check_environment.py --user michael
```

Tohle vytvoří: `env_test/michael/environment.json`

### 3. Commitni a pushni svůj snapshot

```bash
git add env_test/michael/environment.json
git commit -m "Add Michael environment snapshot"
git push
```

### 4. Spusť porovnání

```bash
uv run python3 env_test/compare_environments.py
```

Výsledek se uloží do: `env_test/diff_report.txt`

### 5. Prohlédni rozdíly

```bash
cat env_test/diff_report.txt
```

## 📊 Co snapshot obsahuje

1. **Python info**:
   - Verze (3.13.8)
   - Executable path
   - Platform info

2. **Flet info**:
   - Verze (0.28.3)
   - Module path
   - File path

3. **ft.Colors**:
   - Všechny dostupné Colors (mělo by být 381)
   - Seznam GREEN* variant
   - has_GREEN: true/false

4. **File hashes**:
   - SHA256 hash `flet/__init__.py`
   - SHA256 hash `flet/colors.py` (pokud existuje)

5. **Packages**:
   - flet version
   - flet-desktop version

## 🔍 Očekávané výsledky

### U Claude (už máme):
```
ft.Colors.GREEN exists: True
Total Colors attributes: 381
```

### U Michaela (ty zjistíš):
```
ft.Colors.GREEN exists: False  ???
Total Colors attributes: ???
```

## ⚠️ Poznámky

- **VŽDY používej `uv run python3`**, nikdy ne systemový python3
- Snapshot zachycuje stav TVÉHO prostředí po `uv sync`
- Pokud uvidíš rozdíly v file hashích → máme různé Flet soubory!
- Pokud uvidíš rozdíly v Colors → máme různé Flet verze/buildy

## 🚀 Quick Start

```bash
# Michael spustí:
git pull
uv run python3 env_test/check_environment.py --user michael
git add env_test/michael/ && git commit -m "Add Michael env" && git push
uv run python3 env_test/compare_environments.py
cat env_test/diff_report.txt
```

Hotovo! Pak pošleš diff_report.txt a uvidíme přesně co je jinak.
