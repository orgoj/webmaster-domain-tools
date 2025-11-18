import { useState } from 'react';
import { DomainInput } from './components/DomainInput';
import { ResultSection } from './components/ResultSection';
import { LoadingSpinner } from './components/LoadingSpinner';
import { DarkModeToggle } from './components/DarkModeToggle';
import { GoogleAd } from './components/GoogleAd';
import { analyzeDomain } from './services/dnsService';
import { analyzeSEO } from './services/seoService';
import { exportAnalysis, type ExportFormat } from './services/exportService';
import type { DomainAnalysisResult } from './types/dns';
import type { SEOAnalysisResult } from './types/seo';

function App() {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<DomainAnalysisResult | null>(null);
  const [seoResult, setSeoResult] = useState<SEOAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (domain: string) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    setSeoResult(null);

    try {
      // Run DNS and SEO analysis in parallel
      const [dnsResult, seoAnalysis] = await Promise.all([
        analyzeDomain(domain),
        analyzeSEO(domain),
      ]);

      setResult(dnsResult);
      setSeoResult(seoAnalysis);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  const handleExport = (format: ExportFormat) => {
    if (!result) return;

    exportAnalysis(
      {
        dns: result,
        seo: seoResult || undefined,
      },
      format
    );
  };

  return (
    <div className="min-h-screen py-8 px-4">
      {/* Dark Mode Toggle */}
      <DarkModeToggle />

      {/* Top Ad - Banner */}
      {/* TODO: Replace ad slot "1234567890" with your real AdSense slot ID */}
      <div className="max-w-4xl mx-auto mb-6">
        <GoogleAd adSlot="1234567890" adFormat="horizontal" className="w-full" />
      </div>

      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">
            🌐 Domain Analyzer
          </h1>
          <p className="text-lg text-gray-600 dark:text-gray-300">
            Free DNS, Email Security & SEO Analysis Tool
          </p>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
            Check DNS records, DNSSEC, SPF/DMARC/DKIM, robots.txt, sitemap.xml, and more
          </p>
        </div>

        {/* Input Form */}
        <DomainInput onAnalyze={handleAnalyze} isLoading={isLoading} />

        {/* Loading State */}
        {isLoading && (
          <div className="mt-8 card">
            <LoadingSpinner />
            <p className="text-center text-gray-600 dark:text-gray-300 mt-4">
              Analyzing domain... Running DNS and SEO checks.
            </p>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="mt-8 card">
            <div className="error-message">
              <span>✗</span>
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Results */}
        {result && !isLoading && (
          <div className="mt-8 space-y-6">
            {/* Export Buttons */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">
                📥 Export Results
              </h2>
              <div className="flex flex-wrap gap-3">
                <button
                  onClick={() => handleExport('json')}
                  className="btn-primary text-sm"
                  title="Export as JSON"
                >
                  📄 JSON
                </button>
                <button
                  onClick={() => handleExport('csv')}
                  className="btn-primary text-sm"
                  title="Export as CSV"
                >
                  📊 CSV
                </button>
                <button
                  onClick={() => handleExport('txt')}
                  className="btn-primary text-sm"
                  title="Export as Plain Text"
                >
                  📝 TXT
                </button>
                <button
                  onClick={() => handleExport('html')}
                  className="btn-primary text-sm"
                  title="Export as HTML Report"
                >
                  🌐 HTML
                </button>
              </div>
            </div>

            {/* DNS Results */}
            <ResultSection result={result} />

            {/* SEO Results */}
            {seoResult && (
              <div className="card">
                <h2 className="text-2xl font-bold mb-4 text-gray-900 dark:text-white">
                  🎯 SEO Analysis
                </h2>

                {/* Robots.txt */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-2 text-gray-800 dark:text-gray-200">
                    🤖 robots.txt
                  </h3>
                  {seoResult.robotsTxt.found ? (
                    <div className="space-y-2">
                      <p className="success-message">
                        <span>✓</span>
                        <span>Found robots.txt</span>
                      </p>
                      <div className="text-sm space-y-1 text-gray-700 dark:text-gray-300">
                        <p>
                          <strong>User Agents:</strong>{' '}
                          {seoResult.robotsTxt.rules.userAgents.join(', ') || 'None'}
                        </p>
                        <p>
                          <strong>Disallowed Paths:</strong>{' '}
                          {seoResult.robotsTxt.rules.disallowed.length}
                        </p>
                        <p>
                          <strong>Sitemaps:</strong> {seoResult.robotsTxt.rules.sitemaps.length}
                        </p>
                        {seoResult.robotsTxt.rules.sitemaps.map((sitemap, i) => (
                          <p key={i} className="ml-4 text-xs">
                            • {sitemap}
                          </p>
                        ))}
                      </div>
                      {seoResult.robotsTxt.warnings.map((warning, i) => (
                        <div key={i} className="warning-message">
                          <span>⚠</span>
                          <span>{warning}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="warning-message">
                      <span>⚠</span>
                      <span>No robots.txt found</span>
                    </div>
                  )}
                </div>

                {/* Sitemap */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-2 text-gray-800 dark:text-gray-200">
                    🗺️ Sitemap.xml
                  </h3>
                  {seoResult.sitemap.found ? (
                    <div className="space-y-2">
                      <p className="success-message">
                        <span>✓</span>
                        <span>Found sitemap.xml with {seoResult.sitemap.urlCount} URLs</span>
                      </p>
                      {seoResult.sitemap.warnings.map((warning, i) => (
                        <div key={i} className="warning-message">
                          <span>⚠</span>
                          <span>{warning}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="warning-message">
                      <span>⚠</span>
                      <span>No sitemap.xml found</span>
                    </div>
                  )}
                </div>

                {/* Favicons */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-2 text-gray-800 dark:text-gray-200">
                    🎨 Favicons
                  </h3>
                  {seoResult.favicon.found ? (
                    <div className="space-y-2">
                      <p className="success-message">
                        <span>✓</span>
                        <span>Found {seoResult.favicon.locations.length} favicon(s)</span>
                      </p>
                      <div className="overflow-x-auto">
                        <table className="record-table">
                          <thead>
                            <tr>
                              <th>URL</th>
                              <th>Type</th>
                              <th>Source</th>
                              <th>Size</th>
                            </tr>
                          </thead>
                          <tbody>
                            {seoResult.favicon.locations.map((fav, i) => (
                              <tr key={i}>
                                <td className="text-xs break-all">{fav.url}</td>
                                <td>{fav.type}</td>
                                <td>{fav.source}</td>
                                <td>{fav.size || 'N/A'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ) : (
                    <div className="warning-message">
                      <span>⚠</span>
                      <span>No favicon found</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Mid Ad - Rectangle (after content for AdSense policy compliance) */}
            {/* TODO: Replace ad slot "2345678901" with your real AdSense slot ID */}
            <GoogleAd adSlot="2345678901" adFormat="rectangle" className="w-full" />
          </div>
        )}

        {/* Footer */}
        <footer className="mt-12 space-y-6">
          {/* Bottom Ad - Banner */}
          {/* TODO: Replace ad slot "3456789012" with your real AdSense slot ID */}
          <GoogleAd adSlot="3456789012" adFormat="horizontal" className="w-full" />

          <div className="text-center text-sm text-gray-500 dark:text-gray-400">
            <p>
              Powered by{' '}
              <a
                href="https://developers.google.com/speed/public-dns/docs/doh"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 dark:text-blue-400 hover:underline"
              >
                Google DNS-over-HTTPS
              </a>
            </p>
            <p className="mt-2">
              Free domain analysis tool • No data stored • Privacy-friendly • Open Source
            </p>
            <p className="mt-2 text-xs">
              Features: DNS Records • DNSSEC • SPF/DMARC/DKIM • Robots.txt • Sitemap.xml •
              Favicons • Dark Mode • Export
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
}

export default App;
