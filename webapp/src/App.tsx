import { useState } from 'react';
import { DomainInput } from './components/DomainInput';
import { ResultSection } from './components/ResultSection';
import { LoadingSpinner } from './components/LoadingSpinner';
import { analyzeDomain } from './services/dnsService';
import type { DomainAnalysisResult } from './types/dns';

function App() {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<DomainAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (domain: string) => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const analysisResult = await analyzeDomain(domain);
      setResult(analysisResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen py-8 px-4">
      <div className="max-w-4xl mx-auto">
        <DomainInput onAnalyze={handleAnalyze} isLoading={isLoading} />

        {isLoading && (
          <div className="mt-8 card">
            <LoadingSpinner />
            <p className="text-center text-gray-600 mt-4">
              Analyzing domain... This may take a few seconds.
            </p>
          </div>
        )}

        {error && (
          <div className="mt-8 card">
            <div className="error-message">
              <span>✗</span>
              <span>{error}</span>
            </div>
          </div>
        )}

        {result && !isLoading && (
          <div className="mt-8">
            <ResultSection result={result} />
          </div>
        )}

        {/* Footer */}
        <footer className="mt-12 text-center text-sm text-gray-500">
          <p>
            Powered by{' '}
            <a
              href="https://developers.google.com/speed/public-dns/docs/doh"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:underline"
            >
              Google DNS-over-HTTPS
            </a>
          </p>
          <p className="mt-2">Free domain analysis tool • No data stored • Privacy-friendly</p>
          {/* Placeholder for Google Ads */}
          <div className="mt-6 p-4 bg-gray-100 rounded-lg">
            <p className="text-gray-400">[ Google Ads Placeholder ]</p>
          </div>
        </footer>
      </div>
    </div>
  );
}

export default App;
