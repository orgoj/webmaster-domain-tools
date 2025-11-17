import { useState } from 'react';
import type { DomainAnalysisResult, DNSRecord } from '../types/dns';

interface ResultSectionProps {
  result: DomainAnalysisResult;
}

interface SectionProps {
  title: string;
  icon: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

function CollapsibleSection({ title, icon, defaultOpen = true, children }: SectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 transition-colors"
      >
        <span className="section-title mb-0">
          <span>{icon}</span>
          <span>{title}</span>
        </span>
        <span className="text-gray-500">{isOpen ? '▼' : '▶'}</span>
      </button>
      {isOpen && <div className="p-4">{children}</div>}
    </div>
  );
}

function RecordTable({ records }: { records: DNSRecord[] }) {
  if (records.length === 0) {
    return <p className="text-gray-500 italic">No records found</p>;
  }

  return (
    <table className="record-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Value</th>
          <th>TTL</th>
        </tr>
      </thead>
      <tbody>
        {records.map((record, idx) => (
          <tr key={idx}>
            <td className="text-gray-600">{record.name}</td>
            <td className="font-mono text-sm">{record.value}</td>
            <td className="text-gray-500">{record.ttl}s</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function ResultSection({ result }: ResultSectionProps) {
  return (
    <div className="space-y-4">
      {/* Summary Header */}
      <div className="card">
        <h2 className="text-2xl font-bold mb-2">{result.domain}</h2>
        <p className="text-gray-500 text-sm">
          Analyzed at {result.timestamp.toLocaleString()}
        </p>

        {/* Errors and Warnings */}
        {result.errors.length > 0 && (
          <div className="mt-4 space-y-2">
            {result.errors.map((error, idx) => (
              <div key={idx} className="error-message">
                <span>✗</span>
                <span>{error}</span>
              </div>
            ))}
          </div>
        )}

        {result.warnings.length > 0 && (
          <div className="mt-4 space-y-2">
            {result.warnings.map((warning, idx) => (
              <div key={idx} className="warning-message">
                <span>⚠</span>
                <span>{warning}</span>
              </div>
            ))}
          </div>
        )}

        {result.errors.length === 0 && result.warnings.length === 0 && (
          <div className="mt-4 success-message">
            <span>✓</span>
            <span>No critical issues found</span>
          </div>
        )}
      </div>

      {/* DNS Records */}
      <CollapsibleSection title="DNS Records" icon="🌐">
        <div className="space-y-6">
          <div>
            <h3 className="font-semibold mb-2">A Records (IPv4)</h3>
            <RecordTable records={result.dnsRecords.A} />
          </div>

          <div>
            <h3 className="font-semibold mb-2">AAAA Records (IPv6)</h3>
            <RecordTable records={result.dnsRecords.AAAA} />
          </div>

          <div>
            <h3 className="font-semibold mb-2">CNAME Records</h3>
            <RecordTable records={result.dnsRecords.CNAME} />
          </div>

          <div>
            <h3 className="font-semibold mb-2">MX Records (Mail)</h3>
            <RecordTable records={result.dnsRecords.MX} />
          </div>

          <div>
            <h3 className="font-semibold mb-2">NS Records (Nameservers)</h3>
            <RecordTable records={result.dnsRecords.NS} />
          </div>

          <div>
            <h3 className="font-semibold mb-2">TXT Records</h3>
            <RecordTable records={result.dnsRecords.TXT} />
          </div>

          <div>
            <h3 className="font-semibold mb-2">CAA Records</h3>
            <RecordTable records={result.dnsRecords.CAA} />
          </div>
        </div>
      </CollapsibleSection>

      {/* DNSSEC */}
      <CollapsibleSection title="DNSSEC" icon="🔒">
        <div className="space-y-2">
          <p>
            <strong>Status:</strong>{' '}
            {result.dnssec.validated ? (
              <span className="text-green-600">✓ Validated</span>
            ) : (
              <span className="text-gray-600">Not validated</span>
            )}
          </p>
          {!result.dnssec.validated && (
            <p className="text-sm text-gray-600">
              DNSSEC provides cryptographic authentication of DNS data. Consider enabling it
              for improved security.
            </p>
          )}
        </div>
      </CollapsibleSection>

      {/* Email Security */}
      <CollapsibleSection title="Email Security" icon="📧">
        <div className="space-y-4">
          <div>
            <h3 className="font-semibold mb-2">SPF (Sender Policy Framework)</h3>
            {result.emailSecurity.spf.found ? (
              <div>
                <p className="text-green-600 mb-2">✓ SPF record found</p>
                <pre className="bg-gray-100 p-3 rounded text-sm overflow-x-auto">
                  {result.emailSecurity.spf.record}
                </pre>
                {!result.emailSecurity.spf.valid && (
                  <p className="text-red-600 mt-2">⚠ SPF record syntax invalid</p>
                )}
              </div>
            ) : (
              <p className="text-gray-600">✗ No SPF record found</p>
            )}
          </div>

          <div>
            <h3 className="font-semibold mb-2">DMARC (Domain-based Message Authentication)</h3>
            {result.emailSecurity.dmarc.found ? (
              <div>
                <p className="text-green-600 mb-2">✓ DMARC record found</p>
                <pre className="bg-gray-100 p-3 rounded text-sm overflow-x-auto">
                  {result.emailSecurity.dmarc.record}
                </pre>
                {result.emailSecurity.dmarc.policy && (
                  <p className="mt-2">
                    <strong>Policy:</strong> {result.emailSecurity.dmarc.policy}
                  </p>
                )}
              </div>
            ) : (
              <p className="text-gray-600">✗ No DMARC record found</p>
            )}
          </div>
        </div>
      </CollapsibleSection>
    </div>
  );
}
