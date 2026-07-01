import { Component } from 'react'

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, info) {
    console.error('[ErrorBoundary]', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'linear-gradient(135deg, #1a1a4e 0%, #3030a0 100%)',
          padding: 20,
        }}>
          <div style={{
            background: 'white', borderRadius: 20,
            padding: '48px 40px', maxWidth: 520, width: '100%',
            textAlign: 'center', boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
          }}>
            <div style={{ fontSize: 64, marginBottom: 16 }}>⚠️</div>
            <h1 style={{ fontSize: 24, fontWeight: 800, color: '#0f172a', marginBottom: 12 }}>
              Something went wrong
            </h1>
            <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.6, marginBottom: 8 }}>
              An unexpected error occurred. Please refresh the page to continue.
            </p>
            {this.state.error && (
              <details style={{ margin: '16px 0', textAlign: 'left' }}>
                <summary style={{ cursor: 'pointer', fontSize: 13, color: '#94a3b8', fontWeight: 600 }}>
                  Technical details
                </summary>
                <pre style={{
                  marginTop: 8, padding: 12, background: '#f8fafc',
                  borderRadius: 8, fontSize: 11, color: '#ef4444',
                  overflow: 'auto', maxHeight: 200, lineHeight: 1.6,
                }}>
                  {this.state.error.toString()}
                </pre>
              </details>
            )}
            <button
              onClick={() => window.location.reload()}
              style={{
                marginTop: 8, padding: '12px 32px',
                background: 'linear-gradient(135deg, #4040c8, #7040d8)',
                color: 'white', border: 'none', borderRadius: 9999,
                fontWeight: 700, fontSize: 14, cursor: 'pointer',
                boxShadow: '0 8px 24px rgba(64,64,200,0.35)',
              }}
            >
              🔄 Reload Page
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
