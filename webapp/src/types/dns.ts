/**
 * DNS record types supported by Google DoH API
 */
export type DNSRecordType = 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CNAME' | 'SOA' | 'CAA';

/**
 * Google DoH API response structure
 */
export interface GoogleDohResponse {
  Status: number; // 0 = NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN
  TC: boolean; // Truncated
  RD: boolean; // Recursion Desired
  RA: boolean; // Recursion Available
  AD: boolean; // Authenticated Data (DNSSEC)
  CD: boolean; // Checking Disabled
  Question: Array<{
    name: string;
    type: number;
  }>;
  Answer?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
  Authority?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
  Comment?: string;
}

/**
 * Parsed DNS record
 */
export interface DNSRecord {
  type: DNSRecordType;
  name: string;
  value: string;
  ttl: number;
}

/**
 * Analysis result for a domain
 */
export interface DomainAnalysisResult {
  domain: string;
  timestamp: Date;

  // DNS Records
  dnsRecords: {
    A: DNSRecord[];
    AAAA: DNSRecord[];
    MX: DNSRecord[];
    TXT: DNSRecord[];
    NS: DNSRecord[];
    CNAME: DNSRecord[];
    SOA: DNSRecord[];
    CAA: DNSRecord[];
  };

  // DNSSEC
  dnssec: {
    enabled: boolean;
    validated: boolean;
  };

  // Email Security
  emailSecurity: {
    spf: {
      found: boolean;
      record?: string;
      valid: boolean;
    };
    dmarc: {
      found: boolean;
      record?: string;
      policy?: string;
    };
    dkim: {
      found: boolean;
      selector?: string;
    };
  };

  // Errors and Warnings
  errors: string[];
  warnings: string[];
}

/**
 * Loading state for analysis sections
 */
export interface AnalysisState {
  isLoading: boolean;
  error: string | null;
  result: DomainAnalysisResult | null;
}
