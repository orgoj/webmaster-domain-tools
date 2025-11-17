import type {
  DNSRecordType,
  GoogleDohResponse,
  DNSRecord,
  DomainAnalysisResult,
} from '../types/dns';

/**
 * Google DoH API endpoint
 */
const GOOGLE_DOH_API = 'https://dns.google/resolve';

/**
 * DNS record type to number mapping
 */
const DNS_TYPE_MAP: Record<DNSRecordType, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  CAA: 257,
};

/**
 * Query Google DoH API for DNS records
 */
async function queryDNS(domain: string, recordType: DNSRecordType): Promise<GoogleDohResponse> {
  const url = `${GOOGLE_DOH_API}?name=${encodeURIComponent(domain)}&type=${recordType}`;

  const response = await fetch(url, {
    headers: {
      Accept: 'application/dns-json',
    },
  });

  if (!response.ok) {
    throw new Error(`DNS query failed: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Parse Google DoH response to DNSRecord array
 */
function parseRecords(response: GoogleDohResponse, type: DNSRecordType): DNSRecord[] {
  if (!response.Answer) {
    return [];
  }

  return response.Answer.filter((answer) => answer.type === DNS_TYPE_MAP[type]).map((answer) => ({
    type,
    name: answer.name,
    value: answer.data,
    ttl: answer.TTL,
  }));
}

/**
 * Normalize domain name (remove trailing dot, lowercase)
 */
function normalizeDomain(domain: string): string {
  return domain.toLowerCase().replace(/\.$/, '');
}

/**
 * Parse SPF record from TXT records
 */
function parseSPF(txtRecords: DNSRecord[]): {
  found: boolean;
  record?: string;
  valid: boolean;
} {
  const spfRecord = txtRecords.find((r) => r.value.startsWith('v=spf1'));

  if (!spfRecord) {
    return { found: false, valid: false };
  }

  // Basic SPF validation
  const valid = /^v=spf1\s+.*/.test(spfRecord.value);

  return {
    found: true,
    record: spfRecord.value,
    valid,
  };
}

/**
 * Parse DMARC record
 */
function parseDMARC(txtRecords: DNSRecord[]): {
  found: boolean;
  record?: string;
  policy?: string;
} {
  const dmarcRecord = txtRecords.find((r) => r.value.startsWith('v=DMARC1'));

  if (!dmarcRecord) {
    return { found: false };
  }

  // Extract policy
  const policyMatch = dmarcRecord.value.match(/p=([^;]+)/);
  const policy = policyMatch ? policyMatch[1] : undefined;

  return {
    found: true,
    record: dmarcRecord.value,
    policy,
  };
}

/**
 * Analyze a domain using Google DoH API
 */
export async function analyzeDomain(domain: string): Promise<DomainAnalysisResult> {
  const normalizedDomain = normalizeDomain(domain);
  const errors: string[] = [];
  const warnings: string[] = [];

  const result: DomainAnalysisResult = {
    domain: normalizedDomain,
    timestamp: new Date(),
    dnsRecords: {
      A: [],
      AAAA: [],
      MX: [],
      TXT: [],
      NS: [],
      CNAME: [],
      SOA: [],
      CAA: [],
    },
    dnssec: {
      enabled: false,
      validated: false,
    },
    emailSecurity: {
      spf: { found: false, valid: false },
      dmarc: { found: false },
      dkim: { found: false },
    },
    errors,
    warnings,
  };

  try {
    // Query all DNS record types in parallel
    const [aRes, aaaaRes, mxRes, txtRes, nsRes, cnameRes, soaRes, caaRes] = await Promise.all([
      queryDNS(normalizedDomain, 'A'),
      queryDNS(normalizedDomain, 'AAAA'),
      queryDNS(normalizedDomain, 'MX'),
      queryDNS(normalizedDomain, 'TXT'),
      queryDNS(normalizedDomain, 'NS'),
      queryDNS(normalizedDomain, 'CNAME'),
      queryDNS(normalizedDomain, 'SOA'),
      queryDNS(normalizedDomain, 'CAA'),
    ]);

    // Check for NXDOMAIN (domain doesn't exist)
    if (aRes.Status === 3) {
      errors.push('Domain does not exist (NXDOMAIN)');
      return result;
    }

    // Parse DNS records
    result.dnsRecords.A = parseRecords(aRes, 'A');
    result.dnsRecords.AAAA = parseRecords(aaaaRes, 'AAAA');
    result.dnsRecords.MX = parseRecords(mxRes, 'MX');
    result.dnsRecords.TXT = parseRecords(txtRes, 'TXT');
    result.dnsRecords.NS = parseRecords(nsRes, 'NS');
    result.dnsRecords.CNAME = parseRecords(cnameRes, 'CNAME');
    result.dnsRecords.SOA = parseRecords(soaRes, 'SOA');
    result.dnsRecords.CAA = parseRecords(caaRes, 'CAA');

    // DNSSEC validation (check AD flag)
    result.dnssec.enabled = aRes.AD || false;
    result.dnssec.validated = aRes.AD || false;

    // DNS CNAME/A record coexistence rule
    if (result.dnsRecords.CNAME.length > 0) {
      if (result.dnsRecords.A.length > 0 || result.dnsRecords.AAAA.length > 0) {
        // Remove A/AAAA as they shouldn't coexist with CNAME
        result.dnsRecords.A = [];
        result.dnsRecords.AAAA = [];
        warnings.push(
          'Domain has CNAME record, ignoring A/AAAA records (DNS rule violation detected)'
        );
      }
    }

    // Email Security Analysis
    if (result.dnsRecords.TXT.length > 0) {
      result.emailSecurity.spf = parseSPF(result.dnsRecords.TXT);

      if (!result.emailSecurity.spf.found) {
        warnings.push('No SPF record found - email authentication not configured');
      } else if (!result.emailSecurity.spf.valid) {
        errors.push('SPF record found but invalid syntax');
      }
    } else {
      warnings.push('No TXT records found - SPF/DMARC not configured');
    }

    // DMARC check (on _dmarc subdomain)
    try {
      const dmarcRes = await queryDNS(`_dmarc.${normalizedDomain}`, 'TXT');
      const dmarcRecords = parseRecords(dmarcRes, 'TXT');
      result.emailSecurity.dmarc = parseDMARC(dmarcRecords);

      if (!result.emailSecurity.dmarc.found) {
        warnings.push('No DMARC record found - email policy not configured');
      } else if (
        result.emailSecurity.dmarc.policy &&
        result.emailSecurity.dmarc.policy === 'none'
      ) {
        warnings.push('DMARC policy is "none" - consider using "quarantine" or "reject"');
      }
    } catch (error) {
      warnings.push('Could not check DMARC record');
    }

    // Check www subdomain CNAME (optional best practice)
    try {
      const wwwRes = await queryDNS(`www.${normalizedDomain}`, 'CNAME');
      const wwwCname = parseRecords(wwwRes, 'CNAME');

      if (wwwCname.length === 0) {
        // Check if www has A records instead
        const wwwARes = await queryDNS(`www.${normalizedDomain}`, 'A');
        const wwwA = parseRecords(wwwARes, 'A');

        if (wwwA.length > 0) {
          warnings.push(
            'www subdomain uses A record instead of CNAME (consider using CNAME for easier management)'
          );
        }
      }
    } catch (error) {
      // Ignore www subdomain errors
    }

    // Warnings for missing critical records
    if (result.dnsRecords.A.length === 0 && result.dnsRecords.CNAME.length === 0) {
      warnings.push('No A or CNAME records found - domain may not be accessible');
    }

    if (result.dnsRecords.NS.length === 0) {
      errors.push('No nameserver (NS) records found');
    }
  } catch (error) {
    errors.push(error instanceof Error ? error.message : 'Unknown error during analysis');
  }

  return result;
}
