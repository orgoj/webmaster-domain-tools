import { useState } from 'react';

interface DomainInputProps {
  onAnalyze: (domain: string) => void;
  isLoading: boolean;
}

/**
 * Validate domain name format
 * Accepts: domain.com, subdomain.domain.com, domain.co.uk
 * Rejects: invalid characters, spaces, protocol prefixes
 */
function isValidDomain(domain: string): boolean {
  // Remove common protocol prefixes if present
  const cleaned = domain.replace(/^https?:\/\//i, '').replace(/^www\./i, '');

  // Domain regex: allows letters, numbers, hyphens, and dots
  // Must start and end with alphanumeric, labels separated by dots
  const domainRegex =
    /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

  // Check basic format
  if (!domainRegex.test(cleaned)) {
    return false;
  }

  // Domain must have at least one dot (TLD required)
  if (!cleaned.includes('.')) {
    return false;
  }

  // Check length constraints
  if (cleaned.length > 253) {
    return false;
  }

  // Each label must be <= 63 characters
  const labels = cleaned.split('.');
  if (labels.some((label) => label.length > 63 || label.length === 0)) {
    return false;
  }

  return true;
}

export function DomainInput({ onAnalyze, isLoading }: DomainInputProps) {
  const [domain, setDomain] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedDomain = domain.trim();

    if (!trimmedDomain) {
      setValidationError('Please enter a domain name');
      return;
    }

    if (!isValidDomain(trimmedDomain)) {
      setValidationError(
        'Invalid domain format. Enter a valid domain like "example.com" (without http://)'
      );
      return;
    }

    // Clear validation error and submit
    setValidationError(null);

    // Remove protocol and www if present for cleaner analysis
    const cleaned = trimmedDomain.replace(/^https?:\/\//i, '').replace(/^www\./i, '');

    onAnalyze(cleaned);
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setDomain(e.target.value);
    // Clear validation error when user starts typing
    if (validationError) {
      setValidationError(null);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="card">
      <h1 className="text-3xl font-bold mb-2 text-gray-900 dark:text-white">Domain Analyzer</h1>
      <p className="text-gray-600 dark:text-gray-300 mb-6">
        Free DNS, email security, and DNSSEC analysis powered by Google DNS-over-HTTPS
      </p>

      <div className="space-y-3">
        <div className="flex gap-4">
          <input
            type="text"
            value={domain}
            onChange={handleInputChange}
            placeholder="example.com"
            className={`flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 transition-colors ${
              validationError
                ? 'border-red-300 dark:border-red-700 focus:ring-red-500'
                : 'border-gray-300 dark:border-gray-600 focus:ring-blue-500'
            } bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500`}
            disabled={isLoading}
            autoFocus
            aria-invalid={validationError ? 'true' : 'false'}
            aria-describedby={validationError ? 'domain-error' : undefined}
          />
          <button type="submit" disabled={isLoading || !domain.trim()} className="btn-primary">
            {isLoading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>

        {validationError && (
          <div
            id="domain-error"
            className="flex items-start gap-2 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg"
            role="alert"
          >
            <span className="text-red-600 dark:text-red-400">✗</span>
            <span className="text-sm text-red-600 dark:text-red-400">{validationError}</span>
          </div>
        )}
      </div>

      <div className="mt-4 text-sm text-gray-500 dark:text-gray-400">
        <p className="mb-2">✓ DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA)</p>
        <p className="mb-2">✓ DNSSEC validation</p>
        <p className="mb-2">✓ Email security (SPF, DMARC, DKIM)</p>
        <p className="mb-2">✓ SEO analysis (robots.txt, sitemap.xml, favicons)</p>
        <p>✓ Export to JSON, CSV, TXT, HTML</p>
      </div>
    </form>
  );
}
