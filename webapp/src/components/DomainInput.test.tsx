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

    expect(screen.getByText(/✓ DNS records/i)).toBeInTheDocument();
    expect(screen.getByText(/✓ DNSSEC validation/i)).toBeInTheDocument();
    expect(screen.getByText(/✓ Email security/i)).toBeInTheDocument();
  });

  it('should show validation error for invalid domain', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const input = screen.getByPlaceholderText('example.com');
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'invalid domain!' } });
    fireEvent.click(button);

    expect(screen.getByText(/Invalid domain format/i)).toBeInTheDocument();
    expect(mockOnAnalyze).not.toHaveBeenCalled();
  });

  it('should show validation error for empty input on submit', () => {
    const mockOnAnalyze = vi.fn();
    const { container } = render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const input = screen.getByPlaceholderText('example.com');
    const form = container.querySelector('form')!;

    fireEvent.change(input, { target: { value: '   ' } });
    fireEvent.submit(form);

    expect(screen.getByText(/Please enter a domain name/i)).toBeInTheDocument();
    expect(mockOnAnalyze).not.toHaveBeenCalled();
  });

  it('should accept valid domain with subdomain', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const input = screen.getByPlaceholderText('example.com');
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'subdomain.example.com' } });
    fireEvent.click(button);

    expect(mockOnAnalyze).toHaveBeenCalledWith('subdomain.example.com');
  });

  it('should strip protocol from domain', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const input = screen.getByPlaceholderText('example.com');
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'https://example.com' } });
    fireEvent.click(button);

    expect(mockOnAnalyze).toHaveBeenCalledWith('example.com');
  });

  it('should strip www from domain', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const input = screen.getByPlaceholderText('example.com');
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'www.example.com' } });
    fireEvent.click(button);

    expect(mockOnAnalyze).toHaveBeenCalledWith('example.com');
  });

  it('should clear validation error when user starts typing', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const input = screen.getByPlaceholderText('example.com');
    const button = screen.getByRole('button', { name: /analyze/i });

    // Trigger error
    fireEvent.change(input, { target: { value: 'invalid!' } });
    fireEvent.click(button);
    expect(screen.getByText(/Invalid domain format/i)).toBeInTheDocument();

    // Start typing - error should clear
    fireEvent.change(input, { target: { value: 'example.com' } });
    expect(screen.queryByText(/Invalid domain format/i)).not.toBeInTheDocument();
  });

  it('should reject domain without TLD', () => {
    const mockOnAnalyze = vi.fn();
    render(<DomainInput onAnalyze={mockOnAnalyze} isLoading={false} />);

    const input = screen.getByPlaceholderText('example.com');
    const button = screen.getByRole('button', { name: /analyze/i });

    fireEvent.change(input, { target: { value: 'localhost' } });
    fireEvent.click(button);

    expect(screen.getByText(/Invalid domain format/i)).toBeInTheDocument();
    expect(mockOnAnalyze).not.toHaveBeenCalled();
  });
});
