import { Component, ReactNode, ErrorInfo } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

/**
 * Error Boundary component to catch React rendering errors
 * Prevents white screen of death and shows user-friendly error message
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    // Log error to console for debugging
    console.error('Error caught by boundary:', error, errorInfo);

    // Update state with error details
    this.setState({
      error,
      errorInfo,
    });

    // TODO: Send error to error tracking service (e.g., Sentry)
  }

  handleReset = (): void => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
    // Reload the page to reset application state
    window.location.reload();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
          <div className="max-w-2xl w-full">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
              {/* Error Icon */}
              <div className="flex justify-center mb-6">
                <div className="rounded-full bg-red-100 dark:bg-red-900/20 p-4">
                  <svg
                    className="h-16 w-16 text-red-600 dark:text-red-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                </div>
              </div>

              {/* Error Title */}
              <h1 className="text-3xl font-bold text-center text-gray-900 dark:text-white mb-4">
                Oops! Something went wrong
              </h1>

              {/* Error Description */}
              <p className="text-center text-gray-600 dark:text-gray-300 mb-6">
                We're sorry, but the application encountered an unexpected error. This has been
                logged and we'll look into it.
              </p>

              {/* Error Details (collapsible) */}
              {this.state.error && (
                <details className="mb-6">
                  <summary className="cursor-pointer text-sm font-medium text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white mb-2">
                    Show technical details
                  </summary>
                  <div className="bg-gray-100 dark:bg-gray-900 rounded-lg p-4 mt-2">
                    <p className="text-sm font-mono text-red-600 dark:text-red-400 mb-2">
                      {this.state.error.toString()}
                    </p>
                    {this.state.errorInfo && (
                      <pre className="text-xs text-gray-600 dark:text-gray-400 overflow-auto max-h-64">
                        {this.state.errorInfo.componentStack}
                      </pre>
                    )}
                  </div>
                </details>
              )}

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row gap-3 justify-center">
                <button
                  onClick={this.handleReset}
                  className="btn-primary px-6 py-3 text-base"
                >
                  Reload Application
                </button>
                <a
                  href="/"
                  className="inline-flex items-center justify-center px-6 py-3 text-base font-medium text-gray-700 dark:text-gray-300 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 rounded-lg transition-colors duration-200"
                >
                  Go to Homepage
                </a>
              </div>

              {/* Help Text */}
              <p className="text-center text-sm text-gray-500 dark:text-gray-400 mt-6">
                If this problem persists, please try clearing your browser cache or contact support.
              </p>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
