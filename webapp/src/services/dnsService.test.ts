import { describe, it, expect, vi, beforeEach } from 'vitest';
import { analyzeDomain } from './dnsService';
import type { GoogleDohResponse } from '../types/dns';

// Mock fetch globally
global.fetch = vi.fn() as typeof fetch;

describe('dnsService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('analyzeDomain', () => {
    it('should analyze domain with A records successfully', async () => {
      const mockAResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: true,
        CD: false,
        Question: [{ name: 'example.com.', type: 1 }],
        Answer: [
          {
            name: 'example.com.',
            type: 1,
            TTL: 3600,
            data: '93.184.216.34',
          },
        ],
      };

      const mockEmptyResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [],
      };

      const mockNSResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [{ name: 'example.com.', type: 2 }],
        Answer: [
          {
            name: 'example.com.',
            type: 2,
            TTL: 3600,
            data: 'ns1.example.com.',
          },
        ],
      };

      vi.mocked(global.fetch).mockImplementation((url: string) => {
        if (url.includes('type=A')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockAResponse),
          });
        }
        if (url.includes('type=NS')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockNSResponse),
          });
        }
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockEmptyResponse),
        });
      });

      const result = await analyzeDomain('example.com');

      expect(result.domain).toBe('example.com');
      expect(result.dnsRecords.A).toHaveLength(1);
      expect(result.dnsRecords.A[0].value).toBe('93.184.216.34');
      expect(result.dnssec.validated).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle NXDOMAIN (domain does not exist)', async () => {
      const mockNxDomainResponse: GoogleDohResponse = {
        Status: 3, // NXDOMAIN
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [{ name: 'nonexistent.invalid.', type: 1 }],
      };

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockNxDomainResponse),
      });

      const result = await analyzeDomain('nonexistent.invalid');

      expect(result.errors).toContain('Domain does not exist (NXDOMAIN)');
      expect(result.dnsRecords.A).toHaveLength(0);
    });

    it('should detect SPF record from TXT records', async () => {
      const mockTxtResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [{ name: 'example.com.', type: 16 }],
        Answer: [
          {
            name: 'example.com.',
            type: 16,
            TTL: 3600,
            data: 'v=spf1 include:_spf.example.com ~all',
          },
        ],
      };

      const mockEmptyResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [],
      };

      vi.mocked(global.fetch).mockImplementation((url: string) => {
        if (url.includes('type=TXT')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockTxtResponse),
          });
        }
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockEmptyResponse),
        });
      });

      const result = await analyzeDomain('example.com');

      expect(result.emailSecurity.spf.found).toBe(true);
      expect(result.emailSecurity.spf.valid).toBe(true);
      expect(result.emailSecurity.spf.record).toContain('v=spf1');
    });

    it('should warn when no SPF record is found', async () => {
      const mockEmptyResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [],
      };

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockEmptyResponse),
      });

      const result = await analyzeDomain('example.com');

      expect(result.warnings).toContain('No TXT records found - SPF/DMARC not configured');
    });

    it('should handle CNAME/A record coexistence correctly', async () => {
      const mockCnameResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [{ name: 'example.com.', type: 5 }],
        Answer: [
          {
            name: 'example.com.',
            type: 5,
            TTL: 3600,
            data: 'target.example.com.',
          },
        ],
      };

      const mockAResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [{ name: 'example.com.', type: 1 }],
        Answer: [
          {
            name: 'example.com.',
            type: 1,
            TTL: 3600,
            data: '93.184.216.34',
          },
        ],
      };

      const mockEmptyResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [],
      };

      vi.mocked(global.fetch).mockImplementation((url: string) => {
        if (url.includes('type=CNAME')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockCnameResponse),
          });
        }
        if (url.includes('type=A')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockAResponse),
          });
        }
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockEmptyResponse),
        });
      });

      const result = await analyzeDomain('example.com');

      // Should remove A records when CNAME exists
      expect(result.dnsRecords.CNAME).toHaveLength(1);
      expect(result.dnsRecords.A).toHaveLength(0);
      expect(result.warnings.some((w) => w.includes('CNAME record'))).toBe(true);
    });

    it('should handle fetch errors gracefully', async () => {
      vi.mocked(global.fetch).mockRejectedValue(new Error('Network error'));

      const result = await analyzeDomain('example.com');

      expect(result.errors).toContain('Network error');
    });

    it('should normalize domain names (remove trailing dot, lowercase)', async () => {
      const mockEmptyResponse: GoogleDohResponse = {
        Status: 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [],
      };

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockEmptyResponse),
      });

      const result = await analyzeDomain('EXAMPLE.COM.');

      expect(result.domain).toBe('example.com');
    });
  });
});
