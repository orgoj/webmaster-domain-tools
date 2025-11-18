# PWA Icons - TODO

⚠️ **REQUIRED FOR PWA FUNCTIONALITY**

The following icon files are referenced in `manifest.json` and `index.html` but need to be created:

## Required Icons

### 1. icon-192.png
- **Size**: 192x192 pixels
- **Format**: PNG with transparency
- **Used for**: Android home screen, PWA install prompt
- **Referenced in**:
  - `manifest.json` line 17
  - `index.html` (apple-touch-icon)

### 2. icon-512.png
- **Size**: 512x512 pixels
- **Format**: PNG with transparency
- **Used for**: Android splash screen, high-DPI displays
- **Referenced in**: `manifest.json` line 22

### 3. screenshot.png (Optional)
- **Size**: 1280x720 pixels (16:9 aspect ratio)
- **Format**: PNG
- **Used for**: JSON-LD structured data, app store listings
- **Referenced in**: `index.html` line 83 (JSON-LD)

## How to Generate Icons

### Option 1: Using ImageMagick (if available)
```bash
# From the webapp directory
convert public/favicon.svg -resize 192x192 public/icon-192.png
convert public/favicon.svg -resize 512x512 public/icon-512.png
```

### Option 2: Using Online Tools
1. Go to https://realfavicongenerator.net/ or https://www.favicon-generator.org/
2. Upload `public/favicon.svg`
3. Download the generated PWA icons
4. Save as `public/icon-192.png` and `public/icon-512.png`

### Option 3: Using Design Software
1. Open `public/favicon.svg` in Figma/Sketch/Photoshop
2. Export as PNG with these dimensions:
   - 192x192 → `icon-192.png`
   - 512x512 → `icon-512.png`
3. Place in `public/` directory

## Creating Screenshot

1. Deploy the app or run locally with `npm run dev`
2. Open the app in a browser
3. Enter "example.com" and click Analyze
4. Take a screenshot when results are displayed
5. Resize to 1280x720 pixels
6. Save as `public/screenshot.png`

OR

- Remove the screenshot reference from `index.html` line 83 if not needed

## Verification

After creating the icons, verify they work:

1. **Check manifest**:
   ```bash
   # Icons should appear in Chrome DevTools > Application > Manifest
   npm run dev
   # Open http://localhost:5173
   # F12 → Application tab → Manifest
   ```

2. **Test PWA install**:
   - Build and deploy the app
   - Open on mobile Chrome
   - Look for "Add to Home Screen" prompt

## Current Status

- ✅ `manifest.json` - Created and configured
- ✅ `favicon.svg` - Exists (219 bytes)
- ❌ `icon-192.png` - **MISSING** (required)
- ❌ `icon-512.png` - **MISSING** (required)
- ❌ `screenshot.png` - **MISSING** (optional)

## Impact if Not Created

- PWA installation will fail
- Manifest validation errors in browser console
- Apple Touch Icon won't display on iOS
- Missing icons in structured data

**Priority: HIGH** - Create these before production deployment!
