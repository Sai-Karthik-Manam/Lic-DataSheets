import { useState, useEffect, useRef } from 'react'
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
  const [menuOpen, setMenuOpen] = useState(false)       // mobile drawer
  const [acctOpen, setAcctOpen] = useState(false)       // account dropdown (desktop + mobile)
  const [theme, setTheme] = useState('light')
  const acctRef = useRef(null)

  useEffect(() => {
    const saved = localStorage.getItem('theme') || 'light'
    setTheme(saved)
    document.documentElement.setAttribute('data-theme', saved)
  }, [])

  useEffect(() => {
    const handler = (e) => {
      if (acctRef.current && !acctRef.current.contains(e.target)) setAcctOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
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
      <nav className="navbar-root">
        {/* Logo */}
        <Link to="/dashboard" className="navbar-logo">
          📊 <span className="navbar-logo-text">LIC Manager</span>
        </Link>

        {/* Desktop Links */}
        <div className="nav-desktop-links">
          {NAV_LINKS.map(({ to, label }) => (
            <NavLink key={to} to={to} active={location.pathname === to}>{label}</NavLink>
          ))}
          {user?.role === 'admin' && (
            <NavLink to="/admin" active={location.pathname === '/admin'}>⚙️ Admin</NavLink>
          )}
        </div>

        {/* Right Side: single account menu */}
        <div className="navbar-right">
          <div className="account-menu" ref={acctRef}>
            <button
              className="account-trigger"
              onClick={() => setAcctOpen(v => !v)}
              aria-label="Account menu"
            >
              <span className="account-avatar">{(user?.username || '?')[0].toUpperCase()}</span>
              <span className="account-name">{user?.username}</span>
              <span className="account-caret">{acctOpen ? '▲' : '▼'}</span>
            </button>

            {acctOpen && (
              <div className="account-dropdown">
                <div className="account-dropdown-header">
                  <div className="account-avatar" style={{ width: 36, height: 36, fontSize: 15 }}>
                    {(user?.username || '?')[0].toUpperCase()}
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-primary)' }}>{user?.username}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{user?.role === 'admin' ? 'Administrator' : 'User'}</div>
                  </div>
                </div>
                <div className="account-dropdown-divider" />
                <Link to="/change-password" className="account-dropdown-item" onClick={() => setAcctOpen(false)}>
                  🔑 Change Password
                </Link>
                <button className="account-dropdown-item" onClick={() => { toggleTheme(); }}>
                  {theme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode'}
                </button>
                <div className="account-dropdown-divider" />
                <button className="account-dropdown-item account-dropdown-item--danger" onClick={handleLogout}>
                  🚪 Logout
                </button>
              </div>
            )}
          </div>

          {/* Hamburger (mobile only, controls the nav-link drawer) */}
          <button
            className="hamburger"
            onClick={() => setMenuOpen(v => !v)}
            aria-label="Toggle menu"
          >
            {menuOpen ? '✕' : '☰'}
          </button>
        </div>
      </nav>

      {/* Mobile Drawer (nav links only — account actions live in the dropdown above) */}
      {menuOpen && (
        <div className="mobile-drawer">
          {NAV_LINKS.map(({ to, label }) => (
            <Link
              key={to}
              to={to}
              onClick={() => setMenuOpen(false)}
              className={`mobile-drawer-link ${location.pathname === to ? 'active' : ''}`}
            >
              {label}
            </Link>
          ))}
          {user?.role === 'admin' && (
            <Link
              to="/admin"
              onClick={() => setMenuOpen(false)}
              className={`mobile-drawer-link ${location.pathname === '/admin' ? 'active' : ''}`}
            >
              ⚙️ Admin
            </Link>
          )}
        </div>
      )}
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