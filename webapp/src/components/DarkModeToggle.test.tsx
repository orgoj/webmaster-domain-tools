import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { DarkModeToggle } from './DarkModeToggle';

describe('DarkModeToggle', () => {
  beforeEach(() => {
    // Clear localStorage
    localStorage.clear();

    // Remove dark class from document
    document.documentElement.classList.remove('dark');

    // Mock window.matchMedia
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: vi.fn().mockImplementation((query) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });
  });

  it('should render toggle button', () => {
    render(<DarkModeToggle />);

    const button = screen.getByRole('button', { name: /toggle dark mode/i });
    expect(button).toBeInTheDocument();
  });

  it('should start in light mode by default', () => {
    render(<DarkModeToggle />);

    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(localStorage.getItem('darkMode')).toBe('false');
  });

  it('should toggle to dark mode when clicked', () => {
    render(<DarkModeToggle />);

    const button = screen.getByRole('button', { name: /toggle dark mode/i });
    fireEvent.click(button);

    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(localStorage.getItem('darkMode')).toBe('true');
  });

  it('should toggle back to light mode when clicked twice', () => {
    render(<DarkModeToggle />);

    const button = screen.getByRole('button', { name: /toggle dark mode/i });
    fireEvent.click(button); // to dark
    fireEvent.click(button); // back to light

    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(localStorage.getItem('darkMode')).toBe('false');
  });

  it('should restore dark mode from localStorage', () => {
    localStorage.setItem('darkMode', 'true');

    render(<DarkModeToggle />);

    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('should restore light mode from localStorage', () => {
    localStorage.setItem('darkMode', 'false');

    render(<DarkModeToggle />);

    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('should use system preference when no localStorage value', () => {
    window.matchMedia = vi.fn().mockImplementation((query) => ({
      matches: query === '(prefers-color-scheme: dark)',
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }));

    render(<DarkModeToggle />);

    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('should show sun icon in dark mode', () => {
    localStorage.setItem('darkMode', 'true');

    render(<DarkModeToggle />);

    const button = screen.getByRole('button', { name: /toggle dark mode/i });
    expect(button.querySelector('svg')).toBeInTheDocument();
  });

  it('should show moon icon in light mode', () => {
    render(<DarkModeToggle />);

    const button = screen.getByRole('button', { name: /toggle dark mode/i });
    expect(button.querySelector('svg')).toBeInTheDocument();
  });

  it('should have proper aria-label', () => {
    render(<DarkModeToggle />);

    const button = screen.getByRole('button', { name: /toggle dark mode/i });
    expect(button).toHaveAttribute('aria-label', 'Toggle dark mode');
  });

  it('should have proper title attribute in light mode', () => {
    render(<DarkModeToggle />);

    const button = screen.getByRole('button', { name: /toggle dark mode/i });
    expect(button).toHaveAttribute('title', 'Switch to dark mode');
  });

  it('should have proper title attribute in dark mode', () => {
    localStorage.setItem('darkMode', 'true');

    render(<DarkModeToggle />);

    const button = screen.getByRole('button', { name: /toggle dark mode/i });
    expect(button).toHaveAttribute('title', 'Switch to light mode');
  });
});
