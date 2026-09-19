import { useState, useEffect, useRef } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'

const NAV_LINKS = [
  { to: '/dashboard', label: '📈 Dashboard' },
  { to: '/upload',    label: '📤 Upload' },
  { to: '/search',    label: '🔍 Search' },
  { to: '/clients',   label: '👥 Clients' },
]

// Convert ISO timestamp → relative "Xm ago" string
function timeAgo(ts) {
  if (!ts) return ''
  const diff = Date.now() - new Date(ts).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

const ACTION_ICONS = {
  login: '🔑', logout: '🚪', upload: '📤', delete: '🗑',
  view: '👁', download: '⬇️', update: '✏️',
}
function getActionIcon(action = '') {
  const key = Object.keys(ACTION_ICONS).find(k => action.toLowerCase().includes(k))
  return ACTION_ICONS[key] || '📋'
}

export default function Navbar() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)
  const [acctOpen, setAcctOpen] = useState(false)
  const [bellOpen, setBellOpen] = useState(false)
  const [activities, setActivities] = useState([])
  const [actLoading, setActLoading] = useState(false)
  const [actFetched, setActFetched] = useState(false)
  const [theme, setTheme] = useState('light')
  const acctRef = useRef(null)
  const bellRef = useRef(null)

  useEffect(() => {
    const saved = localStorage.getItem('theme') || 'light'
    setTheme(saved)
    document.documentElement.setAttribute('data-theme', saved)
  }, [])

  // Close both dropdowns on outside click
  useEffect(() => {
    const handler = (e) => {
      if (acctRef.current && !acctRef.current.contains(e.target)) setAcctOpen(false)
      if (bellRef.current && !bellRef.current.contains(e.target)) setBellOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const toggleTheme = () => {
    const next = theme === 'light' ? 'dark' : 'light'
    setTheme(next)
    document.documentElement.setAttribute('data-theme', next)
    localStorage.setItem('theme', next)
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const fetchActivity = () => {
    setActLoading(true)
    api.get('/dashboard')
      .then(res => {
        if (res.data.success) {
          setActivities(res.data.stats?.recent_activity || [])
          setActFetched(true)
        }
      })
      .finally(() => setActLoading(false))
  }

  const handleBellClick = () => {
    const next = !bellOpen
    setBellOpen(next)
    setAcctOpen(false)
    // Fetch on first open only; user can manually refresh
    if (next && !actFetched) fetchActivity()
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

        {/* Right Side */}
        <div className="navbar-right">

          {/* ── Bell / Recent Activity — admin only ── */}
          {user?.role === 'admin' && (
            <div ref={bellRef} style={{ position: 'relative' }}>
              <button
                onClick={handleBellClick}
                aria-label="Recent Activity"
                title="Recent Activity"
                style={{
                  background: bellOpen ? 'var(--indigo-50)' : 'none',
                  border: '1px solid ' + (bellOpen ? 'var(--indigo-200)' : 'transparent'),
                  cursor: 'pointer', fontSize: 18,
                  padding: '5px 8px', borderRadius: 8,
                  display: 'flex', alignItems: 'center',
                  color: bellOpen ? 'var(--indigo-600)' : 'var(--slate-500)',
                  transition: 'all 0.15s', position: 'relative',
                }}
                onMouseEnter={e => { if (!bellOpen) e.currentTarget.style.background = 'var(--slate-100)' }}
                onMouseLeave={e => { if (!bellOpen) e.currentTarget.style.background = 'none' }}
              >
                🔔
                {/* Red badge — shown once activities are loaded */}
                {actFetched && activities.length > 0 && (
                  <span style={{
                    position: 'absolute', top: 2, right: 2,
                    background: '#ef4444', color: 'white',
                    borderRadius: '50%', width: 15, height: 15,
                    fontSize: 8, fontWeight: 800,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    {activities.length > 9 ? '9+' : activities.length}
                  </span>
                )}
              </button>

              {bellOpen && (
                <div style={{
                  position: 'absolute', top: 'calc(100% + 8px)', right: 0,
                  width: 340, background: 'white',
                  borderRadius: 'var(--radius-md)',
                  boxShadow: 'var(--shadow-lg)', border: '1px solid var(--slate-200)',
                  zIndex: 300,
                }}>
                  {/* Dropdown header */}
                  <div style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '12px 16px 10px',
                    borderBottom: '1px solid var(--slate-100)',
                  }}>
                    <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--slate-800)' }}>
                      🔔 Recent Activity
                    </span>
                    <button
                      onClick={fetchActivity}
                      style={{
                        background: 'none', border: 'none', cursor: 'pointer',
                        fontSize: 12, color: 'var(--indigo-500)', fontWeight: 600,
                        padding: '2px 6px', borderRadius: 4,
                      }}
                    >
                      ↺ Refresh
                    </button>
                  </div>

                  {/* Dropdown body */}
                  <div style={{ maxHeight: 380, overflowY: 'auto' }}>
                    {actLoading ? (
                      <div style={{ padding: 24, textAlign: 'center', color: 'var(--slate-400)', fontSize: 13 }}>
                        Loading…
                      </div>
                    ) : activities.length === 0 ? (
                      <div style={{ padding: 24, textAlign: 'center', color: 'var(--slate-400)', fontSize: 13 }}>
                        No recent activity found.
                      </div>
                    ) : (
                      activities.map((a, i) => (
                        <div key={i} style={{
                          padding: '10px 16px',
                          borderBottom: i < activities.length - 1 ? '1px solid var(--slate-100)' : 'none',
                          transition: 'background 0.12s',
                        }}
                          onMouseEnter={e => e.currentTarget.style.background = 'var(--slate-50)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'white'}
                        >
                          <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                            <span style={{ fontSize: 16, flexShrink: 0, marginTop: 1 }}>
                              {getActionIcon(a.action)}
                            </span>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--slate-800)', display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                                <span>{a.action}</span>
                                <span style={{ color: 'var(--indigo-500)' }}>@{a.username}</span>
                              </div>
                              {a.details && (
                                <div style={{ fontSize: 12, color: 'var(--slate-500)', marginTop: 2, wordBreak: 'break-word' }}>
                                  {a.details}
                                </div>
                              )}
                              <div style={{ fontSize: 11, color: 'var(--slate-400)', marginTop: 3 }}>
                                🕐 {timeAgo(a.timestamp)}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Account menu */}
          <div className="account-menu" ref={acctRef}>
            <button
              className="account-trigger"
              onClick={() => { setAcctOpen(v => !v); setBellOpen(false) }}
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
                <button className="account-dropdown-item" onClick={() => { toggleTheme() }}>
                  {theme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode'}
                </button>
                <div className="account-dropdown-divider" />
                <button className="account-dropdown-item account-dropdown-item--danger" onClick={handleLogout}>
                  🚪 Logout
                </button>
              </div>
            )}
          </div>

          {/* Hamburger (mobile only) */}
          <button
            className="hamburger"
            onClick={() => setMenuOpen(v => !v)}
            aria-label="Toggle menu"
          >
            {menuOpen ? '✕' : '☰'}
          </button>
        </div>
      </nav>

      {/* Mobile Drawer */}
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