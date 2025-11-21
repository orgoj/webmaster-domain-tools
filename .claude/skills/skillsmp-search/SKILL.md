---
name: skillsmp-search
description: Search and install Claude Code skills from SkillsMP marketplace using their REST API. Use when searching for skills, installing skills from SkillsMP, querying the marketplace API, or exploring 13,000+ available Claude Code extensions. Covers API endpoints, query parameters, response parsing, and installation workflows.
---

# SkillsMP Marketplace - Search & Install Skills

## Overview

**SkillsMP** (https://skillsmp.com) is an independent community marketplace aggregating **13,613+ Claude Code skills** from GitHub repositories.

**Key Features:**
- REST API for programmatic access
- Semantic search with keyword filtering
- 13 categories (Development, Tools, Data & AI, DevOps, Business, etc.)
- Quality filtering (minimum 2 GitHub stars)
- Popularity sorting by GitHub stats

**API Base:** `https://skillsmp.com/api/skills`

## API Structure

### Request Parameters

```bash
GET https://skillsmp.com/api/skills?page=1&limit=100&sortBy=stars&search=python
```

**Parameters:**
- `page` (integer): Page number (starts at 1)
- `limit` (integer): Results per page (max ~200, recommended 100)
- `sortBy` (string): Sort method - `stars` (popularity), `updated` (recent), `name` (alphabetical)
- `search` (string): Keyword search (case-insensitive, searches name + description)
- `marketplaceOnly` (boolean): Filter for skills with marketplace.json support

### Response Structure

```json
{
  "skills": [
    {
      "id": "author-repo-skill-name",
      "name": "skill-name",
      "author": "github-username",
      "authorAvatar": "https://avatars.githubusercontent.com/...",
      "description": "Skill description...",
      "githubUrl": "https://github.com/author/repo/tree/branch/path/to/skill",
      "stars": 12345,
      "forks": 678,
      "updatedAt": 1763533659,
      "hasMarketplace": false,
      "path": "SKILL.md",
      "branch": "main"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 100,
    "total": 13613,
    "totalPages": 137,
    "hasNext": true,
    "hasPrev": false
  }
}
```

## Search Techniques

### Basic Keyword Search

```bash
# Single keyword
curl -s "https://skillsmp.com/api/skills?search=python&limit=50&sortBy=stars"

# Multiple keywords (space-separated)
curl -s "https://skillsmp.com/api/skills?search=python%20CLI%20typer&limit=50"

# Technology stack
curl -s "https://skillsmp.com/api/skills?search=react%20hooks&sortBy=stars"
```

### Filtering with jq

```bash
# Filter by description keywords
curl -s "https://skillsmp.com/api/skills?limit=200&sortBy=stars" | \
  jq -r '.skills[] | select(.description | test("dns|network|security"; "i")) |
  "\(.name) | \(.author) | \(.description[:80])"'

# Find skills by author
curl -s "https://skillsmp.com/api/skills?limit=100" | \
  jq -r '.skills[] | select(.author == "wshobson") | .name'

# High-star skills (>1000 stars)
curl -s "https://skillsmp.com/api/skills?sortBy=stars&limit=100" | \
  jq '.skills[] | select(.stars > 1000) | {name, stars, author}'
```

### Advanced Search Patterns

```bash
# Combine search terms with OR logic (use multiple queries)
for term in "python" "fastapi" "typer"; do
  curl -s "https://skillsmp.com/api/skills?search=$term&limit=20"
done

# Search across multiple pages
for page in {1..3}; do
  curl -s "https://skillsmp.com/api/skills?page=$page&limit=100&search=testing"
done
```

## Installation Process

### Step 1: Find Skills

```bash
# Search and extract installation URLs
curl -s "https://skillsmp.com/api/skills?search=python&limit=50&sortBy=stars" | \
  jq -r '.skills[] | select(.name | test("packaging|testing")) |
  {name, author, githubUrl, branch, path}'
```

### Step 2: Construct Raw GitHub URL

**Formula:**
```
https://raw.githubusercontent.com/{author}/{repo}/{branch}/{path_to_skill}/SKILL.md
```

**Example transformation:**
- `githubUrl`: `https://github.com/wshobson/agents/tree/main/plugins/python-development/skills/python-packaging`
- `branch`: `main`
- `path`: `SKILL.md`
- **Raw URL**: `https://raw.githubusercontent.com/wshobson/agents/main/plugins/python-development/skills/python-packaging/SKILL.md`

**Parse githubUrl path:**
```bash
# Extract path from githubUrl
githubUrl="https://github.com/wshobson/agents/tree/main/plugins/python-development/skills/python-packaging"
author="wshobson"
repo="agents"
branch="main"
skill_path="plugins/python-development/skills/python-packaging"

raw_url="https://raw.githubusercontent.com/${author}/${repo}/${branch}/${skill_path}/SKILL.md"
```

### Step 3: Download & Install

**Project skills** (`./.claude/skills/`):
```bash
mkdir -p .claude/skills/external
curl -sL "https://raw.githubusercontent.com/author/repo/branch/path/SKILL.md" \
  -o .claude/skills/external/skill-name.md
```

**Global skills** (`~/.claude/skills/`):
```bash
mkdir -p ~/.claude/skills
curl -sL "https://raw.githubusercontent.com/author/repo/branch/path/SKILL.md" \
  -o ~/.claude/skills/skill-name.md
```

### Step 4: Verify Installation

```bash
# Check file exists and has content
ls -lh .claude/skills/external/skill-name.md
head -20 .claude/skills/external/skill-name.md
```

## Best Practices

### Search Strategy

1. **Start broad, narrow down:**
   - First: `search=python` (500+ results)
   - Then: `search=python CLI` (50 results)
   - Finally: `search=python CLI typer` (10 results)

2. **Sort by relevance:**
   - `sortBy=stars` for proven quality
   - `sortBy=updated` for latest skills
   - Check `updatedAt` timestamp

3. **Pagination:**
   - Don't assume page 1 has everything
   - Use `hasNext` to iterate through pages
   - Check `total` count first

### Installation Tips

1. **Always review skill content** before installing:
   ```bash
   curl -s "https://raw.githubusercontent.com/author/repo/branch/path/SKILL.md" | less
   ```

2. **Organize by category:**
   ```bash
   mkdir -p .claude/skills/{python,networking,security,gui}
   ```

3. **Use consistent naming:**
   - Keep original skill name from SkillsMP
   - Add `.md` extension
   - Avoid spaces in filenames

4. **Check for dependencies:**
   - Some skills reference other skills
   - Install dependency skills first
   - Read skill documentation

### Quality Indicators

**High-quality skills typically have:**
- ⭐ High star count (>100)
- 📅 Recent updates (within 6 months)
- 👤 Active maintainer (check author's other skills)
- 📝 Clear description
- 🏢 Known organizations (anthropics, pytorch, metabase)

**Avoid:**
- ❌ 0-2 star repos (untested)
- ❌ Very old skills (>2 years) without updates
- ❌ Vague descriptions
- ❌ Duplicate skills (check for better versions)

## Complete Workflow Example

```bash
# 1. Search for Python testing skills
curl -s "https://skillsmp.com/api/skills?search=python%20testing&limit=50&sortBy=stars" | \
  jq -r '.skills[] | "\(.name) (\(.stars)⭐) - \(.description[:80])"'

# 2. Get detailed info for top result
curl -s "https://skillsmp.com/api/skills?search=python%20testing&limit=1&sortBy=stars" | \
  jq '.skills[0] | {name, author, githubUrl, branch}'

# Output:
# {
#   "name": "python-testing-patterns",
#   "author": "wshobson",
#   "githubUrl": "https://github.com/wshobson/agents/tree/main/plugins/python-development/skills/python-testing-patterns",
#   "branch": "main"
# }

# 3. Construct raw URL
raw_url="https://raw.githubusercontent.com/wshobson/agents/main/plugins/python-development/skills/python-testing-patterns/SKILL.md"

# 4. Preview content
curl -s "$raw_url" | head -30

# 5. Install if satisfied
curl -sL "$raw_url" -o .claude/skills/external/python-testing-patterns.md

# 6. Verify
echo "✓ Installed: $(wc -l < .claude/skills/external/python-testing-patterns.md) lines"
```

## Automated Installation Script

```bash
#!/bin/bash
# install-skillsmp.sh - Search and install skills from SkillsMP

search_query="${1:-python}"
max_results="${2:-20}"
target_dir=".claude/skills/external"

mkdir -p "$target_dir"

echo "🔍 Searching SkillsMP for: $search_query"

curl -s "https://skillsmp.com/api/skills?search=$search_query&limit=$max_results&sortBy=stars" | \
  jq -r '.skills[] | @json' | while IFS= read -r skill; do
    name=$(echo "$skill" | jq -r '.name')
    author=$(echo "$skill" | jq -r '.author')
    stars=$(echo "$skill" | jq -r '.stars')
    branch=$(echo "$skill" | jq -r '.branch')
    github_url=$(echo "$skill" | jq -r '.githubUrl')

    # Extract repo and path
    repo=$(echo "$github_url" | sed -E 's|https://github.com/[^/]+/([^/]+)/.*|\1|')
    skill_path=$(echo "$github_url" | sed -E 's|https://github.com/[^/]+/[^/]+/tree/[^/]+/(.+)|\1|')

    raw_url="https://raw.githubusercontent.com/${author}/${repo}/${branch}/${skill_path}/SKILL.md"

    echo "  [$stars⭐] $name"
    echo "      → $raw_url"
    echo "      Install? [y/N]"
    read -r response

    if [[ "$response" =~ ^[Yy]$ ]]; then
      curl -sL "$raw_url" -o "${target_dir}/${name}.md"
      echo "      ✓ Installed to ${target_dir}/${name}.md"
    fi
  done

echo "✅ Installation complete"
ls -1 "$target_dir"
```

**Usage:**
```bash
chmod +x install-skillsmp.sh
./install-skillsmp.sh "python CLI" 10
```

## Common Issues

**Issue: Empty search results**
- Try broader search terms
- Check spelling
- Use fewer keywords initially

**Issue: GitHub raw URL 404**
- Verify `branch` value (main vs master)
- Check if skill file is named differently
- Visit `githubUrl` directly to confirm path

**Issue: Rate limiting**
- SkillsMP API has generous limits
- Add delays between requests if batch processing
- Use `sleep 1` between bulk downloads

**Issue: Skill activation**
- Skills activate automatically based on description keywords
- No restart needed
- Test by asking Claude about the skill's domain

## Related Resources

- **SkillsMP Homepage:** https://skillsmp.com
- **API Endpoint:** https://skillsmp.com/api/skills
- **GitHub Skills:** Search GitHub for `.claude/skills/` directories
- **Anthropic Skills:** https://github.com/anthropics/skills

## Quick Reference

```bash
# Search
curl -s "https://skillsmp.com/api/skills?search=KEYWORD&limit=50&sortBy=stars"

# Get skill details
curl -s "URL" | jq '.skills[] | {name, author, githubUrl, stars}'

# Construct raw URL
https://raw.githubusercontent.com/AUTHOR/REPO/BRANCH/PATH/SKILL.md

# Install project skill
curl -sL "RAW_URL" -o .claude/skills/external/SKILL_NAME.md

# Install global skill
curl -sL "RAW_URL" -o ~/.claude/skills/SKILL_NAME.md

# Verify
ls -lh .claude/skills/external/
```
