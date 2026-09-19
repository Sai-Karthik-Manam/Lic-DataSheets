import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import Navbar from '../components/Navbar'
import { LoadingOverlay, EmptyState } from '../components/UI'
import api from '../api/client'
import { DOC_META } from '../constants'

export default function DashboardPage() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQ, setSearchQ] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [searchOpen, setSearchOpen] = useState(false)
  const [missingClients, setMissingClients] = useState([])
  const searchRef = useRef()
  const navigate = useNavigate()

  useEffect(() => {
    api.get('/dashboard').then(res => {
      if (res.data.success) setData(res.data.stats)
      else setError(res.data.error)
    }).catch(() => setError('Failed to load dashboard')).finally(() => setLoading(false))
  }, [])

  // Fetch clients with missing docs (doc_count < 4)
  useEffect(() => {
    api.get('/clients?limit=200').then(res => {
      if (res.data.success) {
        setMissingClients(res.data.clients.filter(c => c.doc_count < 4))
      }
    }).catch(() => {})
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

  const { total_clients = 0, total_docs = 0, total_users = 0, doc_distribution = [] } = data || {}
  const completionRate = total_clients > 0 ? ((total_docs / (total_clients * 4)) * 100).toFixed(1) : 0

  const STATS = [
    { icon: '👥', value: total_clients,       label: 'Total Clients',    color: 'var(--grad-primary)' },
    { icon: '📄', value: total_docs,           label: 'Total Documents',  color: 'linear-gradient(135deg,#0ea5e9,#0284c7)' },
    { icon: '👤', value: total_users,          label: 'Active Users',     color: 'linear-gradient(135deg,#22c55e,#16a34a)' },
    { icon: '📊', value: `${completionRate}%`, label: 'Completion Rate',  color: 'linear-gradient(135deg,#f59e0b,#d97706)' },
  ]

  // Duplicate list for seamless infinite scroll
  const tickerItems = missingClients.length > 0
    ? [...missingClients, ...missingClients]
    : []

  // Speed: ~2s per item, min 8s total
  const scrollDuration = Math.max(8, missingClients.length * 2)

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

            {/* ── Missing Docs Ticker ── */}
            <div className="card" style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, flexShrink: 0 }}>
                <h2 style={{ fontSize: 17, fontWeight: 700, margin: 0 }}>⚠️ Incomplete Documents</h2>
                {missingClients.length > 0 && (
                  <span style={{
                    background: '#fee2e2', color: '#dc2626',
                    borderRadius: 20, fontSize: 11, fontWeight: 700, padding: '2px 8px',
                  }}>
                    {missingClients.length} clients
                  </span>
                )}
              </div>

              {missingClients.length === 0 ? (
                <EmptyState icon="✅" title="All docs complete!" text="Every client has all 4 documents." />
              ) : (
                <div style={{ flex: 1, overflow: 'hidden', position: 'relative', height: 230 }}>

                  {/* Fade overlays */}
                  <div style={{
                    position: 'absolute', top: 0, left: 0, right: 0, height: 36,
                    background: 'linear-gradient(to bottom, white 60%, transparent)',
                    zIndex: 2, pointerEvents: 'none',
                  }} />
                  <div style={{
                    position: 'absolute', bottom: 0, left: 0, right: 0, height: 36,
                    background: 'linear-gradient(to top, white 60%, transparent)',
                    zIndex: 2, pointerEvents: 'none',
                  }} />

                  <style>{`
                    @keyframes ticker-scroll {
                      0%   { transform: translateY(0); }
                      100% { transform: translateY(-50%); }
                    }
                    .ticker-track {
                      animation: ticker-scroll ${scrollDuration}s linear infinite;
                    }
                    .ticker-track:hover {
                      animation-play-state: paused;
                    }
                    .ticker-item:hover {
                      background: #eef2ff !important;
                      border-color: #c7d2fe !important;
                    }
                  `}</style>

                  <div className="ticker-track">
                    {tickerItems.map((c, i) => (
                      <div
                        key={`${c.name}-${i}`}
                        className="ticker-item"
                        onClick={() => viewClient(c.name)}
                        style={{
                          padding: '9px 12px', borderRadius: 8, marginBottom: 6,
                          border: '1px solid var(--slate-100)', cursor: 'pointer',
                          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                          transition: 'all 0.15s', background: 'white',
                        }}
                      >
                        <div style={{ fontWeight: 600, color: 'var(--slate-800)', fontSize: 13 }}>
                          {c.name}
                        </div>
                        <span style={{
                          fontSize: 11, fontWeight: 700, color: '#d97706',
                          background: '#fffbeb', borderRadius: 12, padding: '2px 8px',
                          border: '1px solid #fde68a', whiteSpace: 'nowrap',
                        }}>
                          {c.doc_count}/4 docs
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

          </div>
        </div>
      </div>
    </>
  )
}