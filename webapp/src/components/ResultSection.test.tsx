import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ResultSection } from './ResultSection';
import type { DomainAnalysisResult } from '../types/dns';

const mockResult: DomainAnalysisResult = {
  domain: 'example.com',
  timestamp: new Date('2025-01-01T12:00:00Z'),
  dnsRecords: {
    A: [{ type: 'A', name: 'example.com', value: '93.184.216.34', ttl: 3600 }],
    AAAA: [],
    MX: [{ type: 'MX', name: 'example.com', value: '10 mail.example.com', ttl: 3600 }],
    TXT: [
      {
        type: 'TXT',
        name: 'example.com',
        value: 'v=spf1 include:_spf.example.com ~all',
        ttl: 3600,
      },
    ],
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
      record: 'v=spf1 include:_spf.example.com ~all',
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
  errors: [],
  warnings: [],
};

describe('ResultSection', () => {
  it('should render domain name', () => {
    render(<ResultSection result={mockResult} />);
    expect(screen.getByRole('heading', { name: 'example.com' })).toBeInTheDocument();
  });

  it('should display success message when no errors or warnings', () => {
    render(<ResultSection result={mockResult} />);
    expect(screen.getByText(/No critical issues found/i)).toBeInTheDocument();
  });

  it('should display errors', () => {
    const resultWithError = {
      ...mockResult,
      errors: ['Critical error occurred'],
    };
    render(<ResultSection result={resultWithError} />);
    expect(screen.getByText('Critical error occurred')).toBeInTheDocument();
  });

  it('should display warnings', () => {
    const resultWithWarning = {
      ...mockResult,
      warnings: ['Warning: something needs attention'],
    };
    render(<ResultSection result={resultWithWarning} />);
    expect(screen.getByText(/Warning: something needs attention/i)).toBeInTheDocument();
  });

  it('should display DNS records', () => {
    const { container } = render(<ResultSection result={mockResult} />);

    // Check for A record in table cells
    expect(container.textContent).toContain('93.184.216.34');

    // Check for MX record
    expect(container.textContent).toContain('10 mail.example.com');
  });

  it('should display DNSSEC status', () => {
    render(<ResultSection result={mockResult} />);
    expect(screen.getByText(/✓ Validated/i)).toBeInTheDocument();
  });

  it('should display SPF record', () => {
    const { container } = render(<ResultSection result={mockResult} />);
    expect(screen.getByText(/SPF record found/i)).toBeInTheDocument();
    expect(container.textContent).toContain('v=spf1 include:_spf.example.com ~all');
  });

  it('should display DMARC record', () => {
    const { container } = render(<ResultSection result={mockResult} />);
    expect(screen.getByText(/DMARC record found/i)).toBeInTheDocument();
    expect(container.textContent).toContain('v=DMARC1; p=quarantine');
  });

  it('should show "No records found" for empty record types', () => {
    render(<ResultSection result={mockResult} />);

    // AAAA section should show no records (we have none in mock)
    const sections = screen.getAllByText(/No records found/i);
    expect(sections.length).toBeGreaterThan(0);
  });
});
