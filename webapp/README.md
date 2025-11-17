# Domain Analyzer - Web Application

Free domain analysis tool powered by Google DNS-over-HTTPS API. Analyze DNS records, DNSSEC, email security (SPF/DMARC), and more - all in your browser with zero server costs.

## Features

✅ **DNS Records Analysis**
- A, AAAA, MX, TXT, NS, CNAME, SOA, CAA records
- Real-time queries via Google DoH API
- DNS CNAME/A record coexistence validation

✅ **DNSSEC Validation**
- Checks for DNSSEC-enabled domains
- Authenticated data (AD) flag verification

✅ **Email Security**
- SPF (Sender Policy Framework) validation
- DMARC policy checking
- Best practices recommendations

✅ **Browser-Based**
- No backend server required
- Rate limits on Google/Cloudflare, not your infrastructure
- Privacy-friendly - no data stored

✅ **Modern UI**
- Clean, responsive design
- Collapsible sections for easy navigation
- Color-coded errors and warnings
- Mobile-friendly

## Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Fast build tool
- **Tailwind CSS** - Styling
- **Google DoH API** - DNS queries

## Getting Started

### Prerequisites

- Node.js 18+ (or use `nvm`/`fnm`)
- npm or yarn or pnpm

### Installation

```bash
cd webapp
npm install
```

### Development

```bash
npm run dev
```

Opens at `http://localhost:3000`

### Build for Production

```bash
npm run build
```

Output in `dist/` directory ready for deployment.

### Preview Production Build

```bash
npm run preview
```

## Deployment

### Cloudflare Pages (Recommended - Free)

1. Connect GitHub repository
2. Build command: `npm run build`
3. Build output directory: `dist`
4. Auto-deploy on push

### Vercel / Netlify

1. Import project
2. Framework preset: Vite
3. Build command: `npm run build`
4. Publish directory: `dist`

### Static Hosting

Upload `dist/` folder to any static hosting:
- AWS S3 + CloudFront
- GitHub Pages
- Nginx/Apache

## Configuration

### Google Ads Integration

Edit `src/App.tsx` and replace the placeholder in the footer with your Google Ads code:

```tsx
{/* Replace with actual Google Ads script */}
<div className="mt-6">
  <ins className="adsbygoogle"
       style={{ display: 'block' }}
       data-ad-client="ca-pub-XXXXXXXXXX"
       data-ad-slot="XXXXXXXXXX"
       data-ad-format="auto"></ins>
</div>
```

### Customization

- **Colors**: Edit `tailwind.config.js`
- **API endpoint**: Change `GOOGLE_DOH_API` in `src/services/dnsService.ts`
- **Features**: Add/remove analyzers in `dnsService.ts`

## Limitations (Browser-Based)

Due to browser security restrictions, the following features are NOT available:

❌ **SSL/TLS Certificate Analysis** - Requires raw socket access
❌ **Security Headers** - CORS blocks reading response headers
❌ **RBL Blacklist Checks** - Requires DNS queries to blacklist servers
❌ **HTTP Redirect Analysis** - CORS restrictions

For full functionality, use the [Python CLI tool](../README.md) or consider the planned **Flet desktop/mobile app**.

## API Rate Limits

Uses Google Public DNS API which is generally rate-limited per client IP:
- **Google DoH**: Very generous (exact limits not published)
- **Cloudflare DoH**: ~600 requests/minute

For typical usage, these limits are sufficient and FREE.

## Privacy

- All queries are client-side
- No data stored on any server
- DNS queries go directly to Google DNS
- No cookies or tracking (except Google Ads if enabled)

## Project Structure

```
webapp/
├── src/
│   ├── components/       # React components
│   │   ├── DomainInput.tsx
│   │   ├── ResultSection.tsx
│   │   └── LoadingSpinner.tsx
│   ├── services/         # Google DoH API integration
│   │   └── dnsService.ts
│   ├── types/            # TypeScript types
│   │   └── dns.ts
│   ├── styles/           # Tailwind CSS
│   │   └── index.css
│   ├── App.tsx           # Main app component
│   └── main.tsx          # Entry point
├── public/               # Static assets
├── index.html            # HTML template
├── package.json
├── tsconfig.json
├── vite.config.ts
└── tailwind.config.js
```

## Contributing

This is part of the [Webmaster Domain Tools](../README.md) project. Contributions welcome!

## License

MIT License - see [LICENSE](../LICENSE)

## Related Projects

- **Python CLI**: Full-featured analysis tool with SSL, headers, RBL
- **Flet App** (planned): Desktop/mobile app with full Python backend

---

**Questions?** Open an issue on [GitHub](https://github.com/orgoj/webmaster-domain-tools)
