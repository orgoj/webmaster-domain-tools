import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  exportToJSON,
  exportToCSV,
  exportToTXT,
  exportToHTML,
  exportAnalysis,
  type CombinedAnalysisResult,
} from './exportService';
import type { DomainAnalysisResult } from '../types/dns';
import type { SEOAnalysisResult } from '../types/seo';

describe('exportService', () => {
  let mockDNSResult: DomainAnalysisResult;
  let mockSEOResult: SEOAnalysisResult;
  let mockCombinedResult: CombinedAnalysisResult;

  beforeEach(() => {
    mockDNSResult = {
      domain: 'example.com',
      timestamp: new Date('2024-01-01T00:00:00Z'),
      dnsRecords: {
        A: [{ type: 'A', name: 'example.com', value: '93.184.216.34', ttl: 3600 }],
        AAAA: [],
        MX: [{ type: 'MX', name: 'example.com', value: '10 mail.example.com', ttl: 3600 }],
        TXT: [{ type: 'TXT', name: 'example.com', value: 'v=spf1 ~all', ttl: 3600 }],
        NS: [{ type: 'NS', name: 'example.com', value: 'ns1.example.com', ttl: 3600 }],
        CNAME: [],
        SOA: [],
        CAA: [],
      },
      dnssec: {
        enabled: true,
        validated: true,
      },
      emailSecurity: {
        spf: {
          found: true,
          record: 'v=spf1 ~all',
          valid: true,
        },
        dmarc: {
          found: true,
          record: 'v=DMARC1; p=quarantine',
          policy: 'quarantine',
        },
        dkim: {
          found: false,
        },
      },
      errors: ['Test error'],
      warnings: ['Test warning'],
    };

    mockSEOResult = {
      domain: 'example.com',
      robotsTxt: {
        found: true,
        content: 'User-agent: *\nAllow: /',
        rules: {
          userAgents: ['*'],
          disallowed: [],
          allowed: ['/'],
          sitemaps: ['https://example.com/sitemap.xml'],
        },
        errors: [],
        warnings: [],
      },
      sitemap: {
        found: true,
        urls: ['https://example.com/', 'https://example.com/about'],
        urlCount: 2,
        errors: [],
        warnings: [],
      },
      favicon: {
        found: true,
        locations: [
          { url: 'https://example.com/favicon.ico', type: 'ico', source: 'default-location' },
        ],
        errors: [],
        warnings: [],
      },
    };

    mockCombinedResult = {
      dns: mockDNSResult,
      seo: mockSEOResult,
    };
  });

  describe('exportToJSON', () => {
    it('should export DNS results to valid JSON', () => {
      const json = exportToJSON({ dns: mockDNSResult });
      const parsed = JSON.parse(json);

      expect(parsed.dns.domain).toBe('example.com');
      expect(parsed.dns.dnsRecords.A).toHaveLength(1);
      expect(parsed.dns.dnsRecords.A[0].value).toBe('93.184.216.34');
    });

    it('should export combined results to valid JSON', () => {
      const json = exportToJSON(mockCombinedResult);
      const parsed = JSON.parse(json);

      expect(parsed.dns.domain).toBe('example.com');
      expect(parsed.seo.robotsTxt.found).toBe(true);
      expect(parsed.seo.sitemap.urlCount).toBe(2);
    });

    it('should format JSON with proper indentation', () => {
      const json = exportToJSON(mockCombinedResult);

      expect(json).toContain('\n');
      expect(json).toContain('  '); // Should have indentation
    });
  });

  describe('exportToCSV', () => {
    it('should export DNS results to CSV with headers', () => {
      const csv = exportToCSV({ dns: mockDNSResult });
      const lines = csv.split('\n');

      expect(lines[0]).toContain('Category,Type,Name,Value,TTL');
    });

    it('should include DNS records in CSV', () => {
      const csv = exportToCSV({ dns: mockDNSResult });

      expect(csv).toContain('DNS,A,');
      expect(csv).toContain('93.184.216.34');
      expect(csv).toContain('DNS,MX,');
      expect(csv).toContain('mail.example.com');
    });

    it('should include DNSSEC status in CSV', () => {
      const csv = exportToCSV({ dns: mockDNSResult });

      expect(csv).toContain('DNSSEC,Status');
      expect(csv).toContain('Validated');
    });

    it('should include email security in CSV', () => {
      const csv = exportToCSV({ dns: mockDNSResult });

      expect(csv).toContain('Email Security,SPF');
      expect(csv).toContain('v=spf1 ~all');
      expect(csv).toContain('Email Security,DMARC');
      expect(csv).toContain('quarantine');
    });

    it('should include SEO data in CSV', () => {
      const csv = exportToCSV(mockCombinedResult);

      expect(csv).toContain('SEO,Robots.txt');
      expect(csv).toContain('SEO,Sitemap');
      expect(csv).toContain('SEO,Favicon');
    });

    it('should include errors and warnings in CSV', () => {
      const csv = exportToCSV({ dns: mockDNSResult });

      expect(csv).toContain('Error,,,');
      expect(csv).toContain('Test error');
      expect(csv).toContain('Warning,,,');
      expect(csv).toContain('Test warning');
    });

    it('should properly escape CSV values with quotes', () => {
      const resultWithQuotes = {
        ...mockDNSResult,
        dnsRecords: {
          ...mockDNSResult.dnsRecords,
          TXT: [
            {
              type: 'TXT' as const,
              name: 'example.com',
              value: 'value with "quotes"',
              ttl: 3600,
            },
          ],
        },
      };

      const csv = exportToCSV({ dns: resultWithQuotes });

      expect(csv).toContain('value with ""quotes""');
    });
  });

  describe('exportToTXT', () => {
    it('should export results to readable plain text', () => {
      const txt = exportToTXT({ dns: mockDNSResult });

      expect(txt).toContain('DOMAIN ANALYSIS REPORT: example.com');
      expect(txt).toContain('='.repeat(80));
    });

    it('should include DNS records section', () => {
      const txt = exportToTXT({ dns: mockDNSResult });

      expect(txt).toContain('DNS RECORDS');
      expect(txt).toContain('A Records (1)');
      expect(txt).toContain('93.184.216.34');
    });

    it('should include DNSSEC section', () => {
      const txt = exportToTXT({ dns: mockDNSResult });

      expect(txt).toContain('DNSSEC');
      expect(txt).toContain('Enabled:   Yes');
      expect(txt).toContain('Validated: Yes');
    });

    it('should include email security section', () => {
      const txt = exportToTXT({ dns: mockDNSResult });

      expect(txt).toContain('EMAIL SECURITY');
      expect(txt).toContain('SPF:');
      expect(txt).toContain('DMARC:');
      expect(txt).toContain('DKIM:');
    });

    it('should include SEO analysis when available', () => {
      const txt = exportToTXT(mockCombinedResult);

      expect(txt).toContain('SEO ANALYSIS');
      expect(txt).toContain('Robots.txt:');
      expect(txt).toContain('Sitemap.xml:');
      expect(txt).toContain('Favicons:');
    });

    it('should include errors and warnings sections', () => {
      const txt = exportToTXT({ dns: mockDNSResult });

      expect(txt).toContain('ERRORS');
      expect(txt).toContain('Test error');
      expect(txt).toContain('WARNINGS');
      expect(txt).toContain('Test warning');
    });

    it('should end with proper footer', () => {
      const txt = exportToTXT({ dns: mockDNSResult });

      expect(txt).toContain('END OF REPORT');
    });
  });

  describe('exportToHTML', () => {
    it('should export results to valid HTML', () => {
      const html = exportToHTML({ dns: mockDNSResult });

      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('</html>');
      expect(html).toContain('<title>');
    });

    it('should include domain name in title', () => {
      const html = exportToHTML({ dns: mockDNSResult });

      expect(html).toContain('example.com');
    });

    it('should include CSS styles', () => {
      const html = exportToHTML({ dns: mockDNSResult });

      expect(html).toContain('<style>');
      expect(html).toContain('font-family');
      expect(html).toContain('badge');
    });

    it('should include DNS records table', () => {
      const html = exportToHTML({ dns: mockDNSResult });

      expect(html).toContain('<table>');
      expect(html).toContain('<th>Type</th>');
      expect(html).toContain('<th>Value</th>');
      expect(html).toContain('93.184.216.34');
    });

    it('should include DNSSEC badges', () => {
      const html = exportToHTML({ dns: mockDNSResult });

      expect(html).toContain('badge');
      expect(html).toContain('Validated');
    });

    it('should include email security section', () => {
      const html = exportToHTML({ dns: mockDNSResult });

      expect(html).toContain('Email Security');
      expect(html).toContain('SPF');
      expect(html).toContain('DMARC');
      expect(html).toContain('DKIM');
    });

    it('should include SEO section when available', () => {
      const html = exportToHTML(mockCombinedResult);

      expect(html).toContain('SEO Analysis');
      expect(html).toContain('Robots.txt');
      expect(html).toContain('Sitemap.xml');
    });

    it('should include errors with proper styling', () => {
      const html = exportToHTML({ dns: mockDNSResult });

      expect(html).toContain('Errors');
      expect(html).toContain('error-list');
      expect(html).toContain('Test error');
    });

    it('should include warnings with proper styling', () => {
      const html = exportToHTML({ dns: mockDNSResult });

      expect(html).toContain('Warnings');
      expect(html).toContain('warning-list');
      expect(html).toContain('Test warning');
    });

    it('should properly escape HTML special characters', () => {
      const resultWithHTML = {
        ...mockDNSResult,
        errors: ['Error with <script>alert("XSS")</script>'],
      };

      const html = exportToHTML({ dns: resultWithHTML });

      expect(html).toContain('&lt;script&gt;');
      expect(html).not.toContain('<script>alert');
    });
  });

  describe('exportAnalysis', () => {
    beforeEach(() => {
      // Mock DOM methods
      document.createElement = vi.fn((_tag: string) => {
        return {
          href: '',
          download: '',
          click: vi.fn(),
        } as HTMLAnchorElement;
      });

      document.body.appendChild = vi.fn();
      document.body.removeChild = vi.fn();

      global.URL.createObjectURL = vi.fn(() => 'blob:mock-url');
      global.URL.revokeObjectURL = vi.fn();

      global.Blob = vi.fn((content: BlobPart[], options: BlobPropertyBag) => {
        return { content, options } as unknown as Blob;
      }) as unknown as typeof Blob;
    });

    it('should export to JSON with correct filename', () => {
      exportAnalysis({ dns: mockDNSResult }, 'json');

      expect(document.createElement).toHaveBeenCalledWith('a');
    });

    it('should export to CSV with correct filename', () => {
      exportAnalysis({ dns: mockDNSResult }, 'csv');

      expect(document.createElement).toHaveBeenCalledWith('a');
    });

    it('should export to TXT with correct filename', () => {
      exportAnalysis({ dns: mockDNSResult }, 'txt');

      expect(document.createElement).toHaveBeenCalledWith('a');
    });

    it('should export to HTML with correct filename', () => {
      exportAnalysis({ dns: mockDNSResult }, 'html');

      expect(document.createElement).toHaveBeenCalledWith('a');
    });
  });
});
