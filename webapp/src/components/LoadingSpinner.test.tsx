import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { LoadingSpinner } from './LoadingSpinner';

describe('LoadingSpinner', () => {
  it('should render spinner animation', () => {
    const { container } = render(<LoadingSpinner />);

    // Check for animation spinner class
    const spinner = container.querySelector('.animate-spin');
    expect(spinner).toBeInTheDocument();
  });

  it('should render with proper structure', () => {
    const { container } = render(<LoadingSpinner />);

    // Should have two circular divs (base + animated)
    const circles = container.querySelectorAll('.rounded-full');
    expect(circles).toHaveLength(2);
  });
});
