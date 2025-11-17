import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { DomainInput } from './DomainInput';

describe('DomainInput', () => {
  it('should render input field and analyze button', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    expect(screen.getByPlaceholderText('example.com')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /analyze/i })).toBeInTheDocument();
  });

  it('should call onAnalyze when form is submitted', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const input = screen.getByPlaceholderText('example.com');
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'example.com' } });
    fireEvent.click(button);

    expect(mockOnAnalyze).toHaveBeenCalledWith('example.com');
  });

  it('should trim whitespace from domain input', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const input = screen.getByPlaceholderText('example.com');
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: '  example.com  ' } });
    fireEvent.click(button);

    expect(mockOnAnalyze).toHaveBeenCalledWith('example.com');
  });

  it('should disable button when isLoading is true', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={true} />);

    const button = screen.getByRole('button', { name: /analyzing/i });
    expect(button).toBeDisabled();
  });

  it('should disable button when input is empty', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const button = screen.getByRole('button', { name: /analyze/i });
    expect(button).toBeDisabled();
  });

  it('should not call onAnalyze with empty domain', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const form = screen.getByRole('button', { name: /analyze/i }).closest('form');
    fireEvent.submit(form!);

    expect(mockOnAnalyze).not.toHaveBeenCalled();
  });

  it('should display feature list', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    expect(screen.getByText(/✓ DNS records \(A, AAAA, MX, TXT, NS, CNAME\)/i)).toBeInTheDocument();
    expect(screen.getByText(/✓ DNSSEC validation/i)).toBeInTheDocument();
    expect(screen.getByText(/✓ Email security \(SPF, DMARC\)/i)).toBeInTheDocument();
  });
});
