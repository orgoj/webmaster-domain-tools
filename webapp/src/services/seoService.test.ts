import { describe, it, expect, vi, beforeEach } from 'vitest';
import { analyzeRobotsTxt, analyzeSitemap, detectFavicons, analyzeSEO } from './seoService';

// Mock fetch globally
global.fetch = vi.fn() as typeof fetch;

// Mock DOMParser
global.DOMParser = class DOMParser {
  parseFromString(str: string, type: string) {
    if (type === 'text/xml') {
      // Simple mock for sitemap parsing
      const urlLocs = str.match(/<url>[\s\S]*?<loc>(.*?)<\/loc>[\s\S]*?<\/url>/g)?.map((m) => {
        const match = m.match(/<loc>(.*?)<\/loc>/);
        return match ? match[1] : '';
      }).filter(Boolean) || [];

      const sitemapLocs = str.match(/<sitemap>[\s\S]*?<loc>(.*?)<\/loc>[\s\S]*?<\/sitemap>/g)?.map((m) => {
        const match = m.match(/<loc>(.*?)<\/loc>/);
        return match ? match[1] : '';
      }).filter(Boolean) || [];

      return {
        querySelector: (selector: string) => {
          if (selector === 'parsererror') return null;
          if (selector.includes('lastmod')) {
            return str.includes('<lastmod>')
              ? { textContent: '2024-01-01T00:00:00Z' }
              : null;
          }
          return null;
        },
        querySelectorAll: (selector: string) => {
          if (selector === 'url > loc') {
            return urlLocs.map((url) => ({ textContent: url }));
          }
          if (selector === 'sitemap > loc') {
            return sitemapLocs.map((url) => ({ textContent: url }));
          }
          return [];
        },
      };
    } else if (type === 'text/html') {
      // Simple mock for HTML parsing
      const links: Array<{ getAttribute: (attr: string) => string | null }> = [];

      if (str.includes('rel="icon"')) {
        links.push({
          getAttribute: (attr: string) => {
            if (attr === 'href') return '/favicon.png';
            if (attr === 'sizes') return '32x32';
            return null;
          },
        });
      }

      return {
        querySelectorAll: (selector: string) => {
          if (selector.includes('link')) {
            return links;
          }
          return [];
        },
      };
    }
    return { querySelector: () => null, querySelectorAll: () => [] };
  }
} as unknown as typeof DOMParser;

describe('seoService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('analyzeRobotsTxt', () => {
    it('should successfully parse robots.txt with all directives', async () => {
      const robotsTxt = `# Robots.txt
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/
Sitemap: https://example.com/sitemap.xml

User-agent: Googlebot
Allow: /
`;

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve(robotsTxt),
      } as Response);

      const result = await analyzeRobotsTxt('example.com');

      expect(result.found).toBe(true);
      expect(result.content).toBe(robotsTxt);
      expect(result.rules.userAgents).toContain('*');
      expect(result.rules.userAgents).toContain('Googlebot');
      expect(result.rules.disallowed).toContain('/admin/');
      expect(result.rules.disallowed).toContain('/private/');
      expect(result.rules.allowed).toContain('/public/');
      expect(result.rules.sitemaps).toContain('https://example.com/sitemap.xml');
      expect(result.errors).toHaveLength(0);
    });

    it('should handle missing robots.txt (404)', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      } as Response);

      const result = await analyzeRobotsTxt('example.com');

      expect(result.found).toBe(false);
      expect(result.warnings).toContain('No robots.txt file found');
    });

    it('should warn when robots.txt disallows all', async () => {
      const robotsTxt = `User-agent: *
Disallow: /`;

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve(robotsTxt),
      } as Response);

      const result = await analyzeRobotsTxt('example.com');

      expect(result.warnings).toContain('robots.txt disallows all crawlers from entire site');
    });

    it('should warn when no sitemap reference found', async () => {
      const robotsTxt = `User-agent: *
Disallow: /admin/`;

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve(robotsTxt),
      } as Response);

      const result = await analyzeRobotsTxt('example.com');

      expect(result.warnings).toContain('No sitemap references found in robots.txt');
    });

    it('should handle fetch errors', async () => {
      vi.mocked(global.fetch).mockRejectedValue(new Error('Network error'));

      const result = await analyzeRobotsTxt('example.com');

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('Failed to fetch robots.txt');
    });
  });

  describe('analyzeSitemap', () => {
    it('should successfully parse sitemap.xml with URLs', async () => {
      const sitemapXml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/</loc>
    <lastmod>2024-01-01T00:00:00Z</lastmod>
  </url>
  <url>
    <loc>https://example.com/about</loc>
  </url>
  <url>
    <loc>https://example.com/contact</loc>
  </url>
</urlset>`;

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve(sitemapXml),
      } as Response);

      const result = await analyzeSitemap('example.com');

      expect(result.found).toBe(true);
      expect(result.urlCount).toBe(3);
      expect(result.urls).toContain('https://example.com/');
      expect(result.urls).toContain('https://example.com/about');
      expect(result.urls).toContain('https://example.com/contact');
      expect(result.lastModified).toBe('2024-01-01T00:00:00Z');
    });

    it('should handle sitemap index files', async () => {
      const sitemapIndex = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://example.com/sitemap1.xml</loc>
  </sitemap>
  <sitemap>
    <loc>https://example.com/sitemap2.xml</loc>
  </sitemap>
</sitemapindex>`;

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve(sitemapIndex),
      } as Response);

      const result = await analyzeSitemap('example.com');

      expect(result.found).toBe(true);
      expect(result.urlCount).toBe(2);
      expect(result.urls).toContain('https://example.com/sitemap1.xml');
      expect(result.urls).toContain('https://example.com/sitemap2.xml');
    });

    it('should warn when sitemap not found', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 404,
      } as Response);

      const result = await analyzeSitemap('example.com');

      expect(result.found).toBe(false);
      expect(result.warnings).toContain('No sitemap.xml found at common locations');
    });

    it('should warn when sitemap is empty', async () => {
      const emptySitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
</urlset>`;

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve(emptySitemap),
      } as Response);

      const result = await analyzeSitemap('example.com');

      expect(result.warnings).toContain('Sitemap found but contains no URLs');
    });

    it('should warn when sitemap exceeds 50,000 URLs', async () => {
      // Create a large sitemap
      const urls = Array.from({ length: 50001 }, (_, i) => `<loc>https://example.com/page${i}</loc>`);
      const largeSitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>${urls.join('</url><url>')}</url>
</urlset>`;

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve(largeSitemap),
      } as Response);

      const result = await analyzeSitemap('example.com');

      expect(result.urlCount).toBeGreaterThan(50000);
      expect(result.warnings.some((w) => w.includes('maximum recommended is 50,000'))).toBe(true);
    });
  });

  describe('detectFavicons', () => {
    it('should detect favicon.ico at default location', async () => {
      vi.mocked(global.fetch).mockImplementation((url: string) => {
        if (url.includes('favicon.ico')) {
          return Promise.resolve({
            ok: true,
            status: 200,
          } as Response);
        }
        return Promise.resolve({
          ok: false,
          status: 404,
        } as Response);
      });

      const result = await detectFavicons('example.com');

      expect(result.found).toBe(true);
      expect(result.locations.length).toBeGreaterThan(0);
      expect(result.locations[0].url).toContain('favicon.ico');
      expect(result.locations[0].type).toBe('ico');
      expect(result.locations[0].source).toBe('default-location');
    });

    it('should detect multiple favicon formats', async () => {
      vi.mocked(global.fetch).mockImplementation((url: string) => {
        if (url.includes('favicon.ico') || url.includes('favicon.png')) {
          return Promise.resolve({
            ok: true,
            status: 200,
          } as Response);
        }
        return Promise.resolve({
          ok: false,
          status: 404,
        } as Response);
      });

      const result = await detectFavicons('example.com');

      expect(result.found).toBe(true);
      expect(result.locations.length).toBeGreaterThanOrEqual(2);
      const types = result.locations.map((l) => l.type);
      expect(types).toContain('ico');
      expect(types).toContain('png');
    });

    it('should detect apple-touch-icon', async () => {
      vi.mocked(global.fetch).mockImplementation((url: string) => {
        if (url.includes('apple-touch-icon')) {
          return Promise.resolve({
            ok: true,
            status: 200,
          } as Response);
        }
        return Promise.resolve({
          ok: false,
          status: 404,
        } as Response);
      });

      const result = await detectFavicons('example.com');

      expect(result.found).toBe(true);
      expect(result.locations.some((l) => l.source === 'apple-touch')).toBe(true);
    });

    it('should parse favicon from HTML link tags', async () => {
      const html = `<!DOCTYPE html>
<html>
<head>
  <link rel="icon" type="image/png" href="/favicon.png" sizes="32x32">
</head>
<body></body>
</html>`;

      vi.mocked(global.fetch).mockImplementation((url: string) => {
        if (url.endsWith('/')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            text: () => Promise.resolve(html),
          } as Response);
        }
        return Promise.resolve({
          ok: false,
          status: 404,
        } as Response);
      });

      const result = await detectFavicons('example.com');

      expect(result.found).toBe(true);
      expect(result.locations.some((l) => l.source === 'link-tag')).toBe(true);
    });

    it('should warn when no favicon found', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 404,
      } as Response);

      const result = await detectFavicons('example.com');

      expect(result.found).toBe(false);
      expect(result.warnings).toContain('No favicon found at any common location');
    });
  });

  describe('analyzeSEO', () => {
    it('should perform complete SEO analysis', async () => {
      const robotsTxt = `User-agent: *
Allow: /
Sitemap: https://example.com/sitemap.xml`;

      const sitemapXml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
</urlset>`;

      vi.mocked(global.fetch).mockImplementation((url: string) => {
        if (url.includes('robots.txt')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            text: () => Promise.resolve(robotsTxt),
          } as Response);
        }
        if (url.includes('sitemap')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            text: () => Promise.resolve(sitemapXml),
          } as Response);
        }
        if (url.includes('favicon.ico')) {
          return Promise.resolve({
            ok: true,
            status: 200,
          } as Response);
        }
        return Promise.resolve({
          ok: false,
          status: 404,
        } as Response);
      });

      const result = await analyzeSEO('example.com');

      expect(result.domain).toBe('example.com');
      expect(result.robotsTxt.found).toBe(true);
      expect(result.sitemap.found).toBe(true);
      expect(result.favicon.found).toBe(true);
    });
  });
});
