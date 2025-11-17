import type {
  RobotsTxtResult,
  SitemapResult,
  FaviconResult,
  SEOAnalysisResult,
} from '../types/seo';

/**
 * Analyze robots.txt file
 */
export async function analyzeRobotsTxt(domain: string): Promise<RobotsTxtResult> {
  const result: RobotsTxtResult = {
    found: false,
    rules: {
      userAgents: [],
      disallowed: [],
      allowed: [],
      sitemaps: [],
    },
    errors: [],
    warnings: [],
  };

  try {
    const response = await fetch(`https://${domain}/robots.txt`, {
      method: 'GET',
      redirect: 'follow',
    });

    if (!response.ok) {
      if (response.status === 404) {
        result.warnings.push('No robots.txt file found');
        return result;
      }
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const content = await response.text();
    result.found = true;
    result.content = content;

    // Parse robots.txt
    const lines = content.split('\n');
    let currentUserAgent = '';

    for (const line of lines) {
      const trimmed = line.trim();

      // Skip comments and empty lines
      if (trimmed.startsWith('#') || trimmed === '') {
        continue;
      }

      // Parse directives
      const colonIndex = trimmed.indexOf(':');
      if (colonIndex === -1) continue;

      const directive = trimmed.substring(0, colonIndex).trim().toLowerCase();
      const value = trimmed.substring(colonIndex + 1).trim();

      switch (directive) {
        case 'user-agent':
          currentUserAgent = value;
          if (!result.rules.userAgents.includes(value)) {
            result.rules.userAgents.push(value);
          }
          break;

        case 'disallow':
          if (value) {
            result.rules.disallowed.push(value);
          }
          break;

        case 'allow':
          if (value) {
            result.rules.allowed.push(value);
          }
          break;

        case 'sitemap':
          if (value) {
            result.rules.sitemaps.push(value);
          }
          break;
      }
    }

    // Warnings
    if (result.rules.userAgents.length === 0) {
      result.warnings.push('No User-agent directives found in robots.txt');
    }

    if (result.rules.disallowed.includes('/')) {
      result.warnings.push('robots.txt disallows all crawlers from entire site');
    }

    if (result.rules.sitemaps.length === 0) {
      result.warnings.push('No sitemap references found in robots.txt');
    }
  } catch (error) {
    if (error instanceof Error) {
      result.errors.push(`Failed to fetch robots.txt: ${error.message}`);
    } else {
      result.errors.push('Failed to fetch robots.txt: Unknown error');
    }
  }

  return result;
}

/**
 * Analyze sitemap.xml file
 */
export async function analyzeSitemap(domain: string): Promise<SitemapResult> {
  const result: SitemapResult = {
    found: false,
    urls: [],
    urlCount: 0,
    errors: [],
    warnings: [],
  };

  const sitemapUrls = [
    `https://${domain}/sitemap.xml`,
    `https://${domain}/sitemap_index.xml`,
    `https://${domain}/sitemap-index.xml`,
  ];

  for (const sitemapUrl of sitemapUrls) {
    try {
      const response = await fetch(sitemapUrl, {
        method: 'GET',
        redirect: 'follow',
      });

      if (!response.ok) {
        continue; // Try next URL
      }

      const content = await response.text();
      result.found = true;

      // Parse XML to extract URLs
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(content, 'text/xml');

      // Check for parse errors
      const parserError = xmlDoc.querySelector('parsererror');
      if (parserError) {
        result.errors.push('Failed to parse sitemap.xml: Invalid XML');
        return result;
      }

      // Extract URLs from <url><loc> tags
      const urlElements = xmlDoc.querySelectorAll('url > loc');
      urlElements.forEach((locElement) => {
        const url = locElement.textContent?.trim();
        if (url) {
          result.urls.push(url);
        }
      });

      // Extract URLs from <sitemap><loc> tags (sitemap index)
      const sitemapElements = xmlDoc.querySelectorAll('sitemap > loc');
      sitemapElements.forEach((locElement) => {
        const url = locElement.textContent?.trim();
        if (url) {
          result.urls.push(url);
        }
      });

      result.urlCount = result.urls.length;

      // Extract lastmod if available
      const lastModElement = xmlDoc.querySelector('url > lastmod, sitemap > lastmod');
      if (lastModElement) {
        result.lastModified = lastModElement.textContent?.trim();
      }

      // Warnings
      if (result.urlCount === 0) {
        result.warnings.push('Sitemap found but contains no URLs');
      } else if (result.urlCount > 50000) {
        result.warnings.push(
          `Sitemap contains ${result.urlCount} URLs (maximum recommended is 50,000)`
        );
      }

      break; // Found sitemap, stop trying
    } catch (error) {
      // Continue to next URL
    }
  }

  if (!result.found) {
    result.warnings.push('No sitemap.xml found at common locations');
  }

  return result;
}

/**
 * Detect favicons from various locations
 */
export async function detectFavicons(domain: string): Promise<FaviconResult> {
  const result: FaviconResult = {
    found: false,
    locations: [],
    errors: [],
    warnings: [],
  };

  const faviconChecks = [
    { url: `https://${domain}/favicon.ico`, type: 'ico' as const, source: 'default-location' as const },
    { url: `https://${domain}/favicon.png`, type: 'png' as const, source: 'default-location' as const },
    { url: `https://${domain}/favicon.svg`, type: 'svg' as const, source: 'default-location' as const },
    {
      url: `https://${domain}/apple-touch-icon.png`,
      type: 'png' as const,
      source: 'apple-touch' as const,
    },
    {
      url: `https://${domain}/apple-touch-icon-precomposed.png`,
      type: 'png' as const,
      source: 'apple-touch' as const,
    },
  ];

  // Check default favicon locations
  await Promise.all(
    faviconChecks.map(async (check) => {
      try {
        const response = await fetch(check.url, {
          method: 'HEAD',
          redirect: 'follow',
        });

        if (response.ok) {
          result.found = true;
          result.locations.push({
            url: check.url,
            type: check.type,
            source: check.source,
          });
        }
      } catch (error) {
        // Ignore errors for individual favicon checks
      }
    })
  );

  // Try to fetch HTML and parse <link> tags
  try {
    const response = await fetch(`https://${domain}/`, {
      method: 'GET',
      redirect: 'follow',
    });

    if (response.ok) {
      const html = await response.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');

      // Find all icon link tags
      const iconLinks = doc.querySelectorAll(
        'link[rel="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]'
      );

      iconLinks.forEach((link) => {
        const href = link.getAttribute('href');
        if (!href) return;

        // Resolve relative URLs
        let fullUrl = href;
        if (href.startsWith('/')) {
          fullUrl = `https://${domain}${href}`;
        } else if (!href.startsWith('http')) {
          fullUrl = `https://${domain}/${href}`;
        }

        // Determine type from href
        let type: 'ico' | 'png' | 'svg' | 'other' = 'other';
        if (href.endsWith('.ico')) type = 'ico';
        else if (href.endsWith('.png')) type = 'png';
        else if (href.endsWith('.svg')) type = 'svg';

        // Get size attribute if available
        const sizes = link.getAttribute('sizes');

        // Check if already in locations
        if (!result.locations.some((loc) => loc.url === fullUrl)) {
          result.found = true;
          result.locations.push({
            url: fullUrl,
            size: sizes || undefined,
            type,
            source: 'link-tag',
          });
        }
      });
    }
  } catch (error) {
    result.warnings.push('Could not parse HTML for favicon link tags');
  }

  if (!result.found) {
    result.warnings.push('No favicon found at any common location');
  }

  return result;
}

/**
 * Perform complete SEO analysis
 */
export async function analyzeSEO(domain: string): Promise<SEOAnalysisResult> {
  const [robotsTxt, sitemap, favicon] = await Promise.all([
    analyzeRobotsTxt(domain),
    analyzeSitemap(domain),
    detectFavicons(domain),
  ]);

  return {
    domain,
    robotsTxt,
    sitemap,
    favicon,
  };
}
