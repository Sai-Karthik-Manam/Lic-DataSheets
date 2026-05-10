import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import Navbar from '../components/Navbar'
import { LoadingOverlay, EmptyState } from '../components/UI'
import api from '../api/client'

const DOC_META = {
  datasheet:    { label: 'Datasheet',    icon: '📄', color: 'var(--indigo-500)' },
  aadhaar:      { label: 'Aadhaar',      icon: '🪪', color: '#8b5cf6' },
  pan:          { label: 'PAN Card',     icon: '💳', color: '#ec4899' },
  bank_account: { label: 'Bank Account', icon: '🏦', color: '#f59e0b' },
}

export default function DashboardPage() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQ, setSearchQ] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [searchOpen, setSearchOpen] = useState(false)
  const searchRef = useRef()
  const navigate = useNavigate()

  useEffect(() => {
    api.get('/dashboard').then(res => {
      if (res.data.success) setData(res.data.stats)
      else setError(res.data.error)
    }).catch(() => setError('Failed to load dashboard')).finally(() => setLoading(false))
  }, [])

  // Quick search
  useEffect(() => {
    if (searchQ.length < 2) { setSearchResults([]); return }
    const t = setTimeout(() => {
      api.get(`/quick-search?q=${encodeURIComponent(searchQ)}`).then(res => {
        setSearchResults(res.data.results || [])
      })
    }, 280)
    return () => clearTimeout(t)
  }, [searchQ])

  // Close search on outside click
  useEffect(() => {
    const h = e => { if (searchRef.current && !searchRef.current.contains(e.target)) setSearchOpen(false) }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])

  const viewClient = async (name) => {
    const res = await api.post('/fetch-data', { name })
    if (res.data.success) navigate('/search', { state: { client: res.data.client } })
  }

  if (loading) return <><Navbar /><div className="page-wrapper"><LoadingOverlay text="Loading dashboard…" /></div></>

  const { total_clients = 0, total_docs = 0, total_users = 0, doc_distribution = [], recent_clients = [], recent_activity = [] } = data || {}
  const completionRate = total_clients > 0 ? ((total_docs / (total_clients * 4)) * 100).toFixed(1) : 0

  const STATS = [
    { icon: '👥', value: total_clients, label: 'Total Clients', color: 'var(--grad-primary)' },
    { icon: '📄', value: total_docs, label: 'Total Documents', color: 'linear-gradient(135deg,#0ea5e9,#0284c7)' },
    { icon: '👤', value: total_users, label: 'Active Users', color: 'linear-gradient(135deg,#22c55e,#16a34a)' },
    { icon: '📊', value: `${completionRate}%`, label: 'Completion Rate', color: 'linear-gradient(135deg,#f59e0b,#d97706)' },
  ]

  return (
    <>
      <Navbar />
      <div className="page-wrapper">
        <div className="page-content" style={{ maxWidth: 1280 }}>
          {/* Header row */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 28, flexWrap: 'wrap', gap: 16 }}>
            <div className="page-header" style={{ marginBottom: 0 }}>
              <h1 className="page-title">📈 Dashboard</h1>
              <p className="page-subtitle">Overview of your LIC document management system</p>
            </div>

            {/* Quick Search */}
            <div ref={searchRef} style={{ position: 'relative', minWidth: 260 }}>
              <input
                className="form-input"
                placeholder="🔍 Quick search clients…"
                value={searchQ}
                onChange={e => { setSearchQ(e.target.value); setSearchOpen(true) }}
                onFocus={() => setSearchOpen(true)}
                style={{ paddingRight: 12 }}
              />
              {searchOpen && searchQ.length >= 2 && (
                <div style={{
                  position: 'absolute', top: 'calc(100% + 6px)', left: 0, right: 0,
                  background: 'white', borderRadius: 'var(--radius-md)',
                  boxShadow: 'var(--shadow-lg)', border: '1px solid var(--slate-200)',
                  zIndex: 100, maxHeight: 320, overflowY: 'auto',
                }}>
                  {searchResults.length === 0
                    ? <p style={{ padding: '20px', textAlign: 'center', color: 'var(--slate-400)', fontSize: 14 }}>No results found</p>
                    : searchResults.map(r => (
                      <div key={r.name} onClick={() => { viewClient(r.name); setSearchOpen(false); setSearchQ('') }}
                        style={{
                          padding: '12px 16px', cursor: 'pointer', borderBottom: '1px solid var(--slate-100)',
                          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                          transition: 'background 0.15s',
                        }}
                        onMouseEnter={e => e.currentTarget.style.background = 'var(--slate-50)'}
                        onMouseLeave={e => e.currentTarget.style.background = 'white'}
                      >
                        <div>
                          <div style={{ fontWeight: 600, color: 'var(--slate-800)', fontSize: 14 }}>{r.name}</div>
                          <div style={{ fontSize: 12, color: 'var(--slate-400)', marginTop: 2 }}>📄 {r.doc_count} docs • 📅 {r.updated_at}</div>
                        </div>
                        <span style={{ color: 'var(--indigo-400)' }}>→</span>
                      </div>
                    ))
                  }
                </div>
              )}
            </div>
          </div>

          {error && <div className="alert alert--error">{error}</div>}

          {/* Stats */}
          <div className="stats-grid">
            {STATS.map(s => (
              <div key={s.label} className="stat-card" style={{ background: s.color, border: 'none', color: 'white' }}>
                <div className="stat-icon" style={{ fontSize: 36 }}>{s.icon}</div>
                <div style={{ fontSize: 34, fontWeight: 800, lineHeight: 1 }}>{s.value}</div>
                <div style={{ fontSize: 13, fontWeight: 600, opacity: 0.9 }}>{s.label}</div>
              </div>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
            {/* Doc Distribution */}
            <div className="card">
              <h2 style={{ fontSize: 17, fontWeight: 700, marginBottom: 20 }}>📊 Document Distribution</h2>
              {doc_distribution.length === 0
                ? <EmptyState icon="📊" title="No data yet" text="Upload some documents to see distribution." />
                : doc_distribution.map(({ type, count }) => {
                    const meta = DOC_META[type] || { label: type, icon: '📄', color: 'var(--indigo-500)' }
                    const pct = total_docs > 0 ? ((count / total_docs) * 100).toFixed(1) : 0
                    return (
                      <div key={type} style={{ marginBottom: 16 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--slate-700)' }}>{meta.icon} {meta.label}</span>
                          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--indigo-700)' }}>{count}</span>
                        </div>
                        <div style={{ background: 'var(--slate-100)', borderRadius: 6, height: 10, overflow: 'hidden' }}>
                          <div style={{
                            height: '100%', width: `${pct}%`, borderRadius: 6,
                            background: meta.color, transition: 'width 0.5s ease',
                          }} />
                        </div>
                      </div>
                    )
                  })
              }
            </div>

            {/* Recent Clients */}
            <div className="card">
              <h2 style={{ fontSize: 17, fontWeight: 700, marginBottom: 20 }}>🆕 Recent Clients</h2>
              {recent_clients.length === 0
                ? <EmptyState icon="👥" title="No clients yet" text="Start by uploading documents!" />
                : recent_clients.map(c => (
                  <div key={c.name} onClick={() => viewClient(c.name)}
                    style={{
                      padding: '12px 14px', borderRadius: 'var(--radius-sm)',
                      marginBottom: 8, cursor: 'pointer', border: '1px solid var(--slate-100)',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'var(--indigo-50)'; e.currentTarget.style.borderColor = 'var(--indigo-200)' }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'white'; e.currentTarget.style.borderColor = 'var(--slate-100)' }}
                  >
                    <div style={{ fontWeight: 700, color: 'var(--indigo-700)', fontSize: 14, marginBottom: 4 }}>{c.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--slate-500)', display: 'flex', gap: 12 }}>
                      <span>📄 {c.doc_count} docs</span>
                      <span>📅 {c.created_at}</span>
                    </div>
                  </div>
                ))
              }
            </div>
          </div>

          {/* Recent Activity */}
          <div className="card" style={{ marginTop: 24 }}>
            <h2 style={{ fontSize: 17, fontWeight: 700, marginBottom: 20 }}>⚡ Recent Activity</h2>
            {recent_activity.length === 0
              ? <EmptyState icon="📋" title="No activity yet" text="Actions will appear here once users start using the system." />
              : recent_activity.map((a, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'flex-start', gap: 14,
                  padding: '12px 0', borderBottom: i < recent_activity.length - 1 ? '1px solid var(--slate-100)' : 'none',
                }}>
                  <div style={{
                    width: 36, height: 36, borderRadius: '50%', flexShrink: 0,
                    background: 'var(--indigo-100)', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', fontWeight: 700, color: 'var(--indigo-700)', fontSize: 13,
                  }}>
                    {(a.username || 'S')[0].toUpperCase()}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--slate-800)' }}>
                      {a.username || 'System'}
                      <span style={{ fontWeight: 400, color: 'var(--slate-500)', marginLeft: 6 }}>
                        {a.action} {a.details ? `– ${a.details}` : ''}
                      </span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--slate-400)', marginTop: 2 }}>🕐 {a.timestamp}</div>
                  </div>
                </div>
              ))
            }
          </div>
        </div>
      </div>

      <style>{`
        @media (max-width: 768px) {
          .stats-grid { grid-template-columns: repeat(2, 1fr) !important; }
          .stats-grid + div { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </>
  )
}
