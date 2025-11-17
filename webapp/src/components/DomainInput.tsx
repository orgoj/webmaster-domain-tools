import { useState } from 'react';

interface DomainInputProps {
  onAnalyze: (domain: string) => void;
  isLoading: boolean;
}

export function DomainInput({ onAnalyze, isLoading }: DomainInputProps) {
  const [domain, setDomain] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (domain.trim()) {
      onAnalyze(domain.trim());
    }
  };

  return (
    <form onSubmit={handleSubmit} className="card">
      <h1 className="text-3xl font-bold mb-2">Domain Analyzer</h1>
      <p className="text-gray-600 mb-6">
        Free DNS, email security, and DNSSEC analysis powered by Google DNS-over-HTTPS
      </p>

      <div className="flex gap-4">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          disabled={isLoading}
          autoFocus
        />
        <button type="submit" disabled={isLoading || !domain.trim()} className="btn-primary">
          {isLoading ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>

      <div className="mt-4 text-sm text-gray-500">
        <p className="mb-2">✓ DNS records (A, AAAA, MX, TXT, NS, CNAME)</p>
        <p className="mb-2">✓ DNSSEC validation</p>
        <p className="mb-2">✓ Email security (SPF, DMARC)</p>
        <p>✓ Best practices validation</p>
      </div>
    </form>
  );
}
