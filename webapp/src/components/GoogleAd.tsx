import { useEffect } from 'react';

interface GoogleAdProps {
  adSlot: string;
  adFormat?: 'auto' | 'horizontal' | 'vertical' | 'rectangle';
  fullWidthResponsive?: boolean;
  className?: string;
}

/**
 * Google AdSense ad component
 * Requires VITE_GOOGLE_ADS_CLIENT environment variable
 */
export function GoogleAd({
  adSlot,
  adFormat = 'auto',
  fullWidthResponsive = true,
  className = '',
}: GoogleAdProps) {
  const adClient = import.meta.env.VITE_GOOGLE_ADS_CLIENT;

  useEffect(() => {
    // Only initialize ads if client ID is configured
    if (adClient && window.adsbygoogle) {
      try {
        (window.adsbygoogle = window.adsbygoogle || []).push({});
      } catch (error) {
        console.error('AdSense error:', error);
      }
    }

    // Cleanup function (AdSense doesn't need explicit cleanup, but good practice)
    return () => {
      // AdSense handles cleanup internally
    };
  }, [adClient, adSlot]); // Include adSlot in dependencies

  // Don't render if no client ID configured
  if (!adClient) {
    return (
      <div
        className={`bg-gray-100 dark:bg-gray-800 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-4 text-center ${className}`}
      >
        <p className="text-gray-500 dark:text-gray-400 text-sm">
          Ad placeholder (Configure VITE_GOOGLE_ADS_CLIENT to show ads)
        </p>
      </div>
    );
  }

  return (
    <div className={`ad-container ${className}`}>
      <ins
        className="adsbygoogle"
        style={{ display: 'block' }}
        data-ad-client={adClient}
        data-ad-slot={adSlot}
        data-ad-format={adFormat}
        data-full-width-responsive={fullWidthResponsive}
      />
    </div>
  );
}

// Extend Window interface for TypeScript
declare global {
  interface Window {
    adsbygoogle: Array<Record<string, unknown>>;
  }
}
