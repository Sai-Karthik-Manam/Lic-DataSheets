import { Link } from 'react-router-dom'

export default function NotFoundPage() {
  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'linear-gradient(135deg, #1a1a4e 0%, #3030a0 100%)',
      padding: 20,
    }}>
      <div className="animate-fade-in" style={{
        background: 'white',
        borderRadius: 'var(--radius-xl)',
        padding: '56px 40px',
        maxWidth: 480,
        width: '100%',
        textAlign: 'center',
        boxShadow: 'var(--shadow-xl)',
      }}>
        <div style={{
          fontSize: 96,
          fontWeight: 900,
          background: 'var(--grad-primary)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
          lineHeight: 1,
          marginBottom: 16,
        }}>
          404
        </div>

        <div style={{ fontSize: 52, margin: '16px 0' }}>🔍</div>

        <h1 style={{ fontSize: 22, fontWeight: 800, color: 'var(--slate-800)', marginBottom: 12 }}>
          Page Not Found
        </h1>

        <p style={{
          color: 'var(--slate-500)',
          fontSize: 14,
          lineHeight: 1.7,
          marginBottom: 32,
        }}>
          The page you're looking for doesn't exist or has been moved.<br />
          Let's get you back on track!
        </p>

        <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Link to="/" className="btn btn--primary">🏠 Go Home</Link>
          <Link to="/search" className="btn btn--secondary">🔍 Search Files</Link>
        </div>
      </div>
    </div>
  )
}
