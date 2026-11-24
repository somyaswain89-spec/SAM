import { Component, type ErrorInfo, type ReactNode } from 'react';

export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('SAM UI boundary error', error.name, info.componentStack); }
  render() {
    if (this.state.failed) return <main className="error-page"><h1>Page could not be displayed</h1><p>Reload this view or contact your SAM administrator.</p><button onClick={() => this.setState({ failed: false })}>Try again</button></main>;
    return this.props.children;
  }
}
