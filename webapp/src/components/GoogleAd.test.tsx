import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { GoogleAd } from './GoogleAd';

describe('GoogleAd', () => {
  let originalEnv: ImportMetaEnv;

  beforeEach(() => {
    originalEnv = import.meta.env;
    // Clear adsbygoogle array before each test
    (window as unknown as { adsbygoogle?: unknown[] }).adsbygoogle = [];
  });

  afterEach(() => {
    import.meta.env = originalEnv;
  });

  it('should render ad container with correct data attributes', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = 'ca-pub-123456789';

    const { container } = render(<GoogleAd adSlot="1234567890" adFormat="horizontal" />);

    const adContainer = screen.getByRole('complementary');
    expect(adContainer).toBeInTheDocument();

    const adIns = container.querySelector('.adsbygoogle');
    expect(adIns).toHaveAttribute('data-ad-client', 'ca-pub-123456789');
    expect(adIns).toHaveAttribute('data-ad-slot', '1234567890');
    expect(adIns).toHaveAttribute('data-ad-format', 'horizontal');
  });

  it('should apply custom className', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = 'ca-pub-123456789';

    const { container } = render(
      <GoogleAd adSlot="1234567890" adFormat="horizontal" className="custom-class" />
    );

    const adContainer = container.querySelector('.custom-class');
    expect(adContainer).toBeInTheDocument();
  });

  it('should set full-width responsive attribute', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = 'ca-pub-123456789';

    const { container } = render(<GoogleAd adSlot="1234567890" adFormat="horizontal" />);

    const adIns = container.querySelector('.adsbygoogle');
    expect(adIns).toHaveAttribute('data-full-width-responsive', 'true');
  });

  it('should render placeholder when VITE_GOOGLE_ADS_CLIENT is not configured', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = '';

    render(<GoogleAd adSlot="1234567890" adFormat="horizontal" />);

    expect(screen.getByText(/Ad placeholder/i)).toBeInTheDocument();
    expect(screen.getByText(/Configure VITE_GOOGLE_ADS_CLIENT/i)).toBeInTheDocument();
  });

  it('should push to adsbygoogle array when mounted with valid config', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = 'ca-pub-123456789';
    const adsbygoogle = [];
    (window as unknown as { adsbygoogle: unknown[] }).adsbygoogle = adsbygoogle;

    render(<GoogleAd adSlot="1234567890" adFormat="horizontal" />);

    expect(adsbygoogle.length).toBeGreaterThan(0);
  });

  it('should handle errors gracefully when adsbygoogle push fails', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = 'ca-pub-123456789';
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    (window as unknown as { adsbygoogle: unknown[] }).adsbygoogle = {
      push: () => {
        throw new Error('AdSense error');
      },
    } as unknown as unknown[];

    render(<GoogleAd adSlot="1234567890" adFormat="horizontal" />);

    expect(consoleErrorSpy).toHaveBeenCalledWith(
      'AdSense error:',
      expect.any(Error)
    );

    consoleErrorSpy.mockRestore();
  });

  it('should render rectangle format ad', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = 'ca-pub-123456789';

    const { container } = render(<GoogleAd adSlot="2345678901" adFormat="rectangle" />);

    const adIns = container.querySelector('.adsbygoogle');
    expect(adIns).toHaveAttribute('data-ad-format', 'rectangle');
    expect(adIns).toHaveAttribute('data-ad-slot', '2345678901');
  });

  it('should re-initialize when adSlot changes', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = 'ca-pub-123456789';
    const adsbygoogle: unknown[] = [];
    (window as unknown as { adsbygoogle: unknown[] }).adsbygoogle = adsbygoogle;

    const { rerender } = render(<GoogleAd adSlot="1234567890" adFormat="horizontal" />);

    const initialPushCount = adsbygoogle.length;

    // Change adSlot prop
    rerender(<GoogleAd adSlot="9876543210" adFormat="horizontal" />);

    // Should push again with new adSlot
    expect(adsbygoogle.length).toBeGreaterThan(initialPushCount);
  });

  it('should have accessible role for screen readers', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = 'ca-pub-123456789';

    render(<GoogleAd adSlot="1234567890" adFormat="horizontal" />);

    const adContainer = screen.getByRole('complementary');
    expect(adContainer).toHaveAttribute('role', 'complementary');
    expect(adContainer).toHaveAttribute('aria-label', 'Advertisement');
  });

  it('should display placeholder with centered text and border', () => {
    import.meta.env.VITE_GOOGLE_ADS_CLIENT = '';

    const { container } = render(<GoogleAd adSlot="1234567890" adFormat="horizontal" />);

    const placeholder = container.querySelector('.border-2.border-dashed');
    expect(placeholder).toBeInTheDocument();
    expect(placeholder).toHaveClass('text-center');
  });
});
