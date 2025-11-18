import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from './App';
import * as dnsService from './services/dnsService';
import * as seoService from './services/seoService';
import type { DomainAnalysisResult } from './types/dns';
import type { SEOAnalysisResult } from './types/seo';

// Mock matchMedia for DarkModeToggle
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// Mock services
vi.mock('./services/dnsService');
vi.mock('./services/seoService');
vi.mock('./services/exportService', () => ({
  exportAnalysis: vi.fn(),
}));

const mockDNSResult: DomainAnalysisResult = {
  domain: 'example.com',
  timestamp: new Date(),
  dnsRecords: {
    A: [{ type: 'A', name: 'example.com', value: '93.184.216.34', ttl: 3600 }],
    AAAA: [],
    MX: [{ type: 'MX', name: 'example.com', value: '10 mail.example.com', ttl: 3600 }],
    TXT: [],
    NS: [],
    CNAME: [],
    SOA: [],
    CAA: [],
  },
  dnssec: { enabled: true, validated: true },
  emailSecurity: {
    spf: { found: true, record: 'v=spf1 include:_spf.example.com ~all', valid: true },
    dmarc: { found: true, record: 'v=DMARC1; p=quarantine', policy: 'quarantine' },
    dkim: { found: true, selector: 'default' },
  },
  errors: [],
  warnings: [],
};

const mockSEOResult: SEOAnalysisResult = {
  domain: 'example.com',
  robotsTxt: {
    found: true,
    rules: { userAgents: ['*'], disallowed: [], allowed: ['/'], sitemaps: ['https://example.com/sitemap.xml'] },
    errors: [],
    warnings: [],
  },
  sitemap: {
    found: true,
    urls: ['https://example.com/'],
    urlCount: 1,
    errors: [],
    warnings: [],
  },
  favicon: {
    found: true,
    favicons: [{ url: 'https://example.com/favicon.ico', type: 'image/x-icon', size: '16x16' }],
    errors: [],
    warnings: [],
  },
};

describe('App Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render the application with header and input form', () => {
    render(<App />);

    expect(screen.getByText(/Domain Analyzer/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/example.com/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /analyze/i })).toBeInTheDocument();
  });

  it('should perform full analysis workflow and display results', async () => {
    vi.mocked(dnsService.analyzeDomain).mockResolvedValue(mockDNSResult);
    vi.mocked(seoService.analyzeSEO).mockResolvedValue(mockSEOResult);

    render(<App />);

    const input = screen.getByPlaceholderText(/example.com/i);
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'example.com' } });
    fireEvent.click(button);

    // Should show progress bar
    await waitFor(() => {
      expect(screen.getByText(/Analyzing Domain/i)).toBeInTheDocument();
    });

    // Wait for results to appear
    await waitFor(() => {
      expect(screen.getByText(/DNS Records/i)).toBeInTheDocument();
      expect(screen.getByText(/Email Security/i)).toBeInTheDocument();
      expect(screen.getByText(/SEO Analysis/i)).toBeInTheDocument();
    }, { timeout: 3000 });

    // Verify services were called
    expect(dnsService.analyzeDomain).toHaveBeenCalledWith('example.com');
    expect(seoService.analyzeSEO).toHaveBeenCalledWith('example.com');

    // Verify results are displayed
    expect(screen.getByText('93.184.216.34')).toBeInTheDocument();
  });

  it('should display error message when analysis fails', async () => {
    vi.mocked(dnsService.analyzeDomain).mockRejectedValue(new Error('Network error'));

    render(<App />);

    const input = screen.getByPlaceholderText(/example.com/i);
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'example.com' } });
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.getByText(/Network error/i)).toBeInTheDocument();
    });
  });

  it('should show export buttons after successful analysis', async () => {
    vi.mocked(dnsService.analyzeDomain).mockResolvedValue(mockDNSResult);
    vi.mocked(seoService.analyzeSEO).mockResolvedValue(mockSEOResult);

    render(<App />);

    const input = screen.getByPlaceholderText(/example.com/i);
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'example.com' } });
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.getByText(/Export Results/i)).toBeInTheDocument();
      expect(screen.getByText(/JSON/i)).toBeInTheDocument();
      expect(screen.getByText(/CSV/i)).toBeInTheDocument();
      expect(screen.getByText(/TXT/i)).toBeInTheDocument();
      expect(screen.getByText(/HTML/i)).toBeInTheDocument();
    }, { timeout: 3000 });
  });

  it('should handle export button clicks', async () => {
    const { exportAnalysis } = await import('./services/exportService');

    vi.mocked(dnsService.analyzeDomain).mockResolvedValue(mockDNSResult);
    vi.mocked(seoService.analyzeSEO).mockResolvedValue(mockSEOResult);

    render(<App />);

    const input = screen.getByPlaceholderText(/example.com/i);
    const analyzeButton = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'example.com' } });
    fireEvent.click(analyzeButton);

    await waitFor(() => {
      expect(screen.getByText(/Export Results/i)).toBeInTheDocument();
    }, { timeout: 3000 });

    const jsonButton = screen.getByText(/JSON/i);
    fireEvent.click(jsonButton);

    expect(exportAnalysis).toHaveBeenCalledWith(
      expect.objectContaining({ dns: mockDNSResult }),
      'json'
    );
  });

  it('should have skip to main content link', () => {
    render(<App />);

    const skipLink = screen.getByText(/Skip to main content/i);
    expect(skipLink).toBeInTheDocument();
    expect(skipLink).toHaveAttribute('href', '#main-content');
  });

  it('should announce analysis completion to screen readers', async () => {
    vi.mocked(dnsService.analyzeDomain).mockResolvedValue(mockDNSResult);
    vi.mocked(seoService.analyzeSEO).mockResolvedValue(mockSEOResult);

    render(<App />);

    const input = screen.getByPlaceholderText(/example.com/i);
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'example.com' } });
    fireEvent.click(button);

    await waitFor(() => {
      const announcement = screen.getByRole('status');
      expect(announcement).toHaveTextContent(/Analysis complete for example.com/i);
    }, { timeout: 3000 });
  });

  it('should focus results section after analysis completes', async () => {
    vi.mocked(dnsService.analyzeDomain).mockResolvedValue(mockDNSResult);
    vi.mocked(seoService.analyzeSEO).mockResolvedValue(mockSEOResult);

    render(<App />);

    const input = screen.getByPlaceholderText(/example.com/i);
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'example.com' } });
    fireEvent.click(button);

    await waitFor(() => {
      const resultsSection = screen.getByLabelText(/Analysis results/i);
      expect(document.activeElement).toBe(resultsSection);
    }, { timeout: 3000 });
  });

  it('should display progress steps during analysis', async () => {
    vi.mocked(dnsService.analyzeDomain).mockResolvedValue(mockDNSResult);
    vi.mocked(seoService.analyzeSEO).mockResolvedValue(mockSEOResult);

    render(<App />);

    const input = screen.getByPlaceholderText(/example.com/i);
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'example.com' } });
    fireEvent.click(button);

    // Progress bar should be visible
    await waitFor(() => {
      expect(screen.getByText(/Analyzing Domain/i)).toBeInTheDocument();
      expect(screen.getByRole('progressbar')).toBeInTheDocument();
    });
  });

  it('should clear previous results when starting new analysis', async () => {
    vi.mocked(dnsService.analyzeDomain).mockResolvedValue(mockDNSResult);
    vi.mocked(seoService.analyzeSEO).mockResolvedValue(mockSEOResult);

    render(<App />);

    const input = screen.getByPlaceholderText(/example.com/i);
    const button = screen.getByRole('button', { name: /analyze/i });

    // First analysis
    fireEvent.change(input, { target: { value: 'example.com' } });
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.getByText('93.184.216.34')).toBeInTheDocument();
    }, { timeout: 3000 });

    // Second analysis - should clear previous results
    fireEvent.change(input, { target: { value: 'test.com' } });
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.getByText(/Analyzing Domain/i)).toBeInTheDocument();
    });
  });
});
