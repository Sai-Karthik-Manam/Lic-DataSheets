import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Navigate } from 'react-router-dom'

const FEATURES = [
  { icon: '📤', title: 'Upload Documents', desc: 'Upload Datasheet, Aadhaar, PAN & Bank documents in one go.', cta: 'Get Started →' },
  { icon: '🔍', title: 'Instant Search', desc: 'Find any client and their complete document portfolio in seconds.', cta: 'Start Searching →' },
  { icon: '👥', title: 'Manage Clients', desc: 'Comprehensive client list with document status at a glance.', cta: 'View Clients →' },
  { icon: '📈', title: 'Analytics', desc: 'Monitor document completion rates and activity across the system.', cta: 'View Stats →' },
]

const WHY = [
  { icon: '⚡', label: 'Lightning Fast' },
  { icon: '🔒', label: '100% Secure' },
  { icon: '☁️', label: 'Cloud Backup' },
  { icon: '📱', label: 'Mobile Ready' },
]

export default function LandingPage() {
  const { user } = useAuth()
  if (user) return <Navigate to="/dashboard" replace />

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #1a1a4e 0%, #3030a0 60%, #5252e0 100%)' }}>
      {/* Nav */}
      <nav style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '18px 40px', position: 'sticky', top: 0,
        background: 'rgba(15,15,46,0.5)', backdropFilter: 'blur(10px)',
        borderBottom: '1px solid rgba(255,255,255,0.1)', zIndex: 100,
      }}>
        <span style={{ color: 'white', fontWeight: 800, fontSize: 20 }}>📊 LIC Manager</span>
        <Link to="/login" style={{
          padding: '10px 24px', borderRadius: 'var(--radius-full)',
          background: 'white', color: 'var(--indigo-700)',
          fontWeight: 700, fontSize: 14, textDecoration: 'none',
          transition: 'all 0.2s',
        }}>🔐 Login</Link>
      </nav>

      <div style={{ maxWidth: 1100, margin: '0 auto', padding: '60px 20px 80px' }}>
        {/* Hero */}
        <div style={{ textAlign: 'center', marginBottom: 64 }} className="animate-fade-in">
          <h1 style={{
            fontSize: 'clamp(36px, 6vw, 60px)', fontWeight: 900,
            color: 'white', marginBottom: 16, lineHeight: 1.1,
          }}>
            📊 LIC Document Manager
          </h1>
          <p style={{ fontSize: 20, color: 'rgba(255,255,255,0.85)', marginBottom: 12 }}>
            Secure • Organized • Efficient
          </p>
          <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.65)', maxWidth: 500, margin: '0 auto' }}>
            Professional document management for LIC agents.<br />
            Manage all your client documents in one secure place.
          </p>
          <div style={{ marginTop: 36 }}>
            <Link to="/login" style={{
              display: 'inline-block', padding: '14px 36px',
              background: 'white', color: 'var(--indigo-700)',
              fontWeight: 800, fontSize: 16, borderRadius: 'var(--radius-full)',
              textDecoration: 'none', boxShadow: '0 8px 30px rgba(0,0,0,0.25)',
              transition: 'all 0.2s',
            }}>
              Get Started →
            </Link>
          </div>
        </div>

        {/* Features */}
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 20,
          marginBottom: 56,
        }}>
          {FEATURES.map((f) => (
            <div key={f.title} style={{
              background: 'rgba(255,255,255,0.95)', borderRadius: 'var(--radius-xl)',
              padding: '32px 24px', textAlign: 'center',
              boxShadow: '0 8px 30px rgba(0,0,0,0.2)',
              transition: 'all 0.3s ease', cursor: 'default',
            }}
              onMouseEnter={e => e.currentTarget.style.transform = 'translateY(-8px)'}
              onMouseLeave={e => e.currentTarget.style.transform = 'translateY(0)'}
            >
              <div style={{ fontSize: 48, marginBottom: 14 }}>{f.icon}</div>
              <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--slate-800)', marginBottom: 10 }}>{f.title}</h3>
              <p style={{ fontSize: 13, color: 'var(--slate-500)', lineHeight: 1.6, marginBottom: 16 }}>{f.desc}</p>
              <span style={{
                display: 'inline-block', padding: '8px 18px',
                background: 'var(--grad-primary)', color: 'white',
                borderRadius: 'var(--radius-full)', fontSize: 13, fontWeight: 600,
              }}>{f.cta}</span>
            </div>
          ))}
        </div>

        {/* Why Section */}
        <div style={{
          background: 'rgba(255,255,255,0.95)', borderRadius: 'var(--radius-xl)',
          padding: '40px', textAlign: 'center',
        }}>
          <h2 style={{ fontSize: 22, fontWeight: 800, color: 'var(--slate-800)', marginBottom: 28 }}>
            ✨ Why Choose LIC Manager?
          </h2>
          <div style={{ display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: 32 }}>
            {WHY.map(w => (
              <div key={w.label}>
                <div style={{ fontSize: 40, marginBottom: 8 }}>{w.icon}</div>
                <div style={{ fontWeight: 700, color: 'var(--slate-700)', fontSize: 14 }}>{w.label}</div>
              </div>
            ))}
          </div>
        </div>

        <p style={{ textAlign: 'center', color: 'rgba(255,255,255,0.5)', fontSize: 13, marginTop: 40 }}>
          © 2025 LIC Manager • Secure • Reliable<br />
          <span style={{ marginTop: 6, display: 'block' }}>🔐 Two-Factor Authentication (OTP) Enabled</span>
        </p>
      </div>
    </div>
  )
}
