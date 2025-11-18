/**
 * Robots.txt analysis result
 */
export interface RobotsTxtResult {
  found: boolean;
  content?: string;
  rules: {
    userAgents: string[];
    disallowed: string[];
    allowed: string[];
    sitemaps: string[];
  };
  errors: string[];
  warnings: string[];
}

/**
 * Sitemap.xml analysis result
 */
export interface SitemapResult {
  found: boolean;
  urls: string[];
  urlCount: number;
  lastModified?: string;
  errors: string[];
  warnings: string[];
}

/**
 * Favicon detection result
 */
export interface FaviconResult {
  found: boolean;
  locations: Array<{
    url: string;
    size?: string;
    type: 'ico' | 'png' | 'svg' | 'other';
    source: 'link-tag' | 'default-location' | 'apple-touch' | 'manifest';
  }>;
  errors: string[];
  warnings: string[];
}

/**
 * Complete SEO analysis result
 */
export interface SEOAnalysisResult {
  domain: string;
  robotsTxt: RobotsTxtResult;
  sitemap: SitemapResult;
  favicon: FaviconResult;
}
