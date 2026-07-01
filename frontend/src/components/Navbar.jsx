import { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const NAV_LINKS = [
  { to: '/dashboard', label: '📈 Dashboard' },
  { to: '/upload',    label: '📤 Upload' },
  { to: '/search',    label: '🔍 Search' },
  { to: '/clients',   label: '👥 Clients' },
]

export default function Navbar() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)
  const [theme, setTheme] = useState('light')

  useEffect(() => {
    const saved = localStorage.getItem('theme') || 'light'
    setTheme(saved)
    document.documentElement.setAttribute('data-theme', saved)
  }, [])

  const toggleTheme = () => {
    const nextTheme = theme === 'light' ? 'dark' : 'light'
    setTheme(nextTheme)
    document.documentElement.setAttribute('data-theme', nextTheme)
    localStorage.setItem('theme', nextTheme)
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <>
      <nav style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 500,
        height: 'var(--nav-height)',
        background: 'rgba(255,255,255,0.96)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid var(--slate-200)',
        display: 'flex', alignItems: 'center',
        padding: '0 24px',
        gap: 24,
      }}>
        {/* Logo */}
        <Link to="/dashboard" style={{
          fontWeight: 800, fontSize: 18, color: 'var(--indigo-700)',
          textDecoration: 'none', letterSpacing: '-0.3px', whiteSpace: 'nowrap',
        }}>
          📊 LIC Manager
        </Link>

        {/* Desktop Links */}
        <div style={{ display: 'flex', gap: 4, flex: 1 }} className="nav-desktop-links">
          {NAV_LINKS.map(({ to, label }) => (
            <NavLink key={to} to={to} active={location.pathname === to}>{label}</NavLink>
          ))}
          {user?.role === 'admin' && (
            <NavLink to="/admin" active={location.pathname === '/admin'}>⚙️ Admin</NavLink>
          )}
        </div>

        {/* Right Side */}
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginLeft: 'auto' }}>
          <span style={{
            padding: '6px 14px', borderRadius: 'var(--radius-full)',
            background: 'var(--indigo-100)', color: 'var(--indigo-700)',
            fontSize: 13, fontWeight: 700,
          }}>
            👤 {user?.username}
          </span>
          <Link to="/change-password" style={{
            padding: '6px 12px', borderRadius: 'var(--radius-sm)',
            color: 'var(--slate-500)', textDecoration: 'none', fontSize: 13,
            fontWeight: 600, transition: 'all 0.2s',
          }}>🔑</Link>
          <button 
            className={`theme-toggle ${theme === 'dark' ? 'dark' : ''}`} 
            onClick={toggleTheme}
            aria-label="Toggle dark mode"
          />
          <button onClick={handleLogout} className="btn btn--ghost btn--sm">
            🚪 Logout
          </button>

          {/* Hamburger */}
          <button
            className="hamburger"
            onClick={() => setMenuOpen(v => !v)}
            aria-label="Toggle menu"
            style={{
              display: 'none', background: 'none', border: 'none',
              cursor: 'pointer', fontSize: 22, padding: 4,
              color: 'var(--slate-600)',
            }}
          >
            {menuOpen ? '✕' : '☰'}
          </button>
        </div>
      </nav>

      {/* Mobile Drawer */}
      {menuOpen && (
        <div style={{
          position: 'fixed', top: 'var(--nav-height)', left: 0, right: 0,
          background: 'white', borderBottom: '1px solid var(--slate-200)',
          padding: '12px 20px 20px', zIndex: 499, boxShadow: 'var(--shadow-lg)',
          display: 'flex', flexDirection: 'column', gap: 4,
        }}>
          {NAV_LINKS.map(({ to, label }) => (
            <Link key={to} to={to} onClick={() => setMenuOpen(false)} style={{
              padding: '10px 14px', borderRadius: 'var(--radius-sm)',
              color: location.pathname === to ? 'var(--indigo-700)' : 'var(--slate-600)',
              background: location.pathname === to ? 'var(--indigo-50)' : 'transparent',
              textDecoration: 'none', fontWeight: 600, fontSize: 14,
            }}>{label}</Link>
          ))}
          {user?.role === 'admin' && (
            <Link to="/admin" onClick={() => setMenuOpen(false)} style={{
              padding: '10px 14px', borderRadius: 'var(--radius-sm)',
              color: 'var(--slate-600)', textDecoration: 'none', fontWeight: 600, fontSize: 14,
            }}>⚙️ Admin</Link>
          )}
          <hr style={{ border: 'none', borderTop: '1px solid var(--slate-100)', margin: '8px 0' }} />
          <Link to="/change-password" onClick={() => setMenuOpen(false)} style={{
            padding: '10px 14px', borderRadius: 'var(--radius-sm)',
            color: 'var(--slate-600)', textDecoration: 'none', fontWeight: 600, fontSize: 14,
          }}>🔑 Change Password</Link>
          <button onClick={handleLogout} style={{
            padding: '10px 14px', borderRadius: 'var(--radius-sm)',
            color: 'var(--red-800)', background: 'var(--red-100)',
            border: 'none', fontWeight: 600, fontSize: 14, cursor: 'pointer', textAlign: 'left',
          }}>🚪 Logout</button>
        </div>
      )}

      <style>{`
        @media (max-width: 768px) {
          .nav-desktop-links { display: none !important; }
          .hamburger { display: block !important; }
        }
      `}</style>
    </>
  )
}

function NavLink({ to, active, children }) {
  return (
    <Link to={to} className={`nav-link ${active ? 'active' : ''}`}>
      {children}
    </Link>
  )
}
