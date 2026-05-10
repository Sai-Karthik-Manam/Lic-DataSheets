import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import Navbar from '../components/Navbar'
import { Alert, Modal, LoadingOverlay, EmptyState } from '../components/UI'
import api from '../api/client'

const DOC_TYPES = [
  { key: 'datasheet',    icon: '📊', name: 'Datasheet' },
  { key: 'aadhaar',      icon: '🪪', name: 'Aadhaar' },
  { key: 'pan',          icon: '💳', name: 'PAN Card' },
  { key: 'bank_account', icon: '🏦', name: 'Bank Account' },
]

function EditDocModal({ open, onClose, client, onSaved }) {
  const [docs, setDocs] = useState({})
  const [selectedFiles, setSelectedFiles] = useState({})
  const [loading, setLoading] = useState(false)
  const [fetchingDocs, setFetchingDocs] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    if (open && client) {
      setFetchingDocs(true)
      setSelectedFiles({}); setError(''); setSuccess('')
      api.get(`/client/${client.id}/documents`).then(res => {
        if (res.data.success) setDocs(res.data.documents)
      }).finally(() => setFetchingDocs(false))
    }
  }, [open, client])

  const handleFileSelect = (key, file) => {
    if (!file) return
    if (file.size > 10 * 1024 * 1024) { setError('File too large! Max 10MB.'); return }
    setSelectedFiles(p => ({ ...p, [key]: file }))
  }

  const handleMarkDelete = (key) => setSelectedFiles(p => ({ ...p, [key]: 'DELETE' }))

  const handleSave = async () => {
    if (Object.keys(selectedFiles).length === 0) { setError('Select at least one document to update.'); return }
    setLoading(true); setError('')
    const fd = new FormData()
    Object.entries(selectedFiles).forEach(([key, val]) => {
      if (val === 'DELETE') fd.append(`delete_${key}`, 'true')
      else fd.append(key, val)
    })
    try {
      const res = await api.post(`/client/${client.id}/update-documents`, fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      if (res.data.success) {
        setSuccess('Documents updated!')
        setTimeout(() => { onSaved(); onClose() }, 1200)
      } else setError(res.data.error || 'Update failed')
    } catch (err) { setError(err.response?.data?.error || 'Update failed')
    } finally { setLoading(false) }
  }

  return (
    <Modal open={open} onClose={onClose} title={`✏️ Edit: ${client?.name}`} size="lg"
      footer={<>
        <button className="btn btn--ghost" onClick={onClose} disabled={loading}>Cancel</button>
        <button className="btn btn--primary" onClick={handleSave} disabled={loading}>
          {loading ? <><span className="spinner" /> Saving…</> : 'Save Changes'}
        </button>
      </>}
    >
      {error && <Alert type="error" onClose={() => setError('')}>{error}</Alert>}
      {success && <Alert type="success">{success}</Alert>}

      {fetchingDocs ? <LoadingOverlay text="Loading documents…" /> : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14 }}>
          {DOC_TYPES.map(({ key, icon, name }) => {
            const exists = !!docs[key]
            const sel = selectedFiles[key]
            const isDelete = sel === 'DELETE'
            const hasNew = sel && sel !== 'DELETE'
            return (
              <div key={key} style={{
                padding: 14, borderRadius: 'var(--radius-md)', textAlign: 'center',
                border: `2px solid ${hasNew ? 'var(--amber-400)' : isDelete ? 'var(--red-400)' : exists ? 'var(--green-500)' : 'var(--slate-200)'}`,
                background: hasNew ? '#fef3c7' : isDelete ? 'var(--red-100)' : exists ? 'var(--green-100)' : 'var(--slate-50)',
              }}>
                <div style={{ fontSize: 30, marginBottom: 8 }}>{icon}</div>
                <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6 }}>{name}</div>
                <div className={`badge badge--${hasNew ? 'amber' : isDelete ? 'red' : exists ? 'green' : 'indigo'}`} style={{ marginBottom: 12, fontSize: 11 }}>
                  {hasNew ? '📄 Ready' : isDelete ? '🗑️ To Remove' : exists ? '✅ Exists' : '⚠️ Empty'}
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <label style={{
                    padding: '6px 10px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--grad-primary)', color: 'white',
                    fontSize: 11, fontWeight: 600, cursor: 'pointer', textAlign: 'center',
                  }}>
                    📤 {exists ? 'Replace' : 'Upload'}
                    <input type="file" accept="image/*,application/pdf" style={{ display: 'none' }}
                      onChange={e => handleFileSelect(key, e.target.files[0])} />
                  </label>
                  {exists && !isDelete && (
                    <button className="btn btn--danger btn--sm" onClick={() => handleMarkDelete(key)}>🗑️ Remove</button>
                  )}
                  {isDelete && (
                    <button className="btn btn--ghost btn--sm" onClick={() => setSelectedFiles(p => { const c = {...p}; delete c[key]; return c })}>
                      ↩ Undo
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </Modal>
  )
}

export default function ClientsPage() {
  const [clients, setClients] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [isSearch, setIsSearch] = useState(false)
  const [error, setError] = useState('')
  const [editClient, setEditClient] = useState(null)
  const navigate = useNavigate()

  const fetchClients = async (q = '') => {
    setLoading(true)
    try {
      const res = await api.get(`/clients${q ? `?search=${encodeURIComponent(q)}` : ''}`)
      if (res.data.success) {
        setClients(res.data.clients)
        setIsSearch(res.data.is_search)
      }
    } catch { setError('Failed to load clients') }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchClients() }, [])

  const handleSearch = async e => {
    e.preventDefault()
    fetchClients(search)
  }

  const viewClient = async (name) => {
    const res = await api.post('/fetch-data', { name })
    if (res.data.success) navigate('/search', { state: { client: res.data.client } })
  }

  const handleSync = async () => {
    try {
      const res = await api.post('/manual-sync')
      if (res.data.success) { fetchClients(); alert(`✅ ${res.data.message}`) }
    } catch { alert('Sync failed') }
  }

  return (
    <>
      <Navbar />
      <div className="page-wrapper">
        <div className="page-content">
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, flexWrap: 'wrap', gap: 12 }}>
            <div>
              <h1 className="page-title">👥 All Clients</h1>
              <p className="page-subtitle">{clients.length} client{clients.length !== 1 ? 's' : ''} found</p>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn btn--ghost" onClick={handleSync}>🔄 Sync Drive</button>
              <button className="btn btn--primary" onClick={() => navigate('/upload')}>📤 Upload New</button>
            </div>
          </div>

          {error && <Alert type="error" onClose={() => setError('')}>{error}</Alert>}

          {isSearch && (
            <div className="alert alert--info" style={{ marginBottom: 16 }}>
              🔍 Showing results for: <strong>"{search}"</strong>
              <button onClick={() => { setSearch(''); fetchClients() }} style={{
                background: 'none', border: 'none', cursor: 'pointer', color: 'var(--indigo-600)',
                fontWeight: 600, marginLeft: 10, fontSize: 13,
              }}>Clear ✕</button>
            </div>
          )}

          {/* Search */}
          <form onSubmit={handleSearch} style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
            <input
              className="form-input"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="🔎 Search by client name…"
              style={{ flex: 1 }}
            />
            <button type="submit" className="btn btn--primary">🔍 Search</button>
          </form>

          {/* Table */}
          {loading ? <LoadingOverlay text="Loading clients…" /> : clients.length === 0 ? (
            <EmptyState
              icon="👥"
              title="No Clients Found"
              text={isSearch ? 'Try a different name.' : 'Sync your Google Drive or upload a document to get started.'}
              action={<button className="btn btn--primary" onClick={handleSync}>🔄 Sync Google Drive</button>}
            />
          ) : (
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>👤 Client Name</th>
                    <th>📄 Docs</th>
                    <th>📅 Created</th>
                    <th>🔄 Updated</th>
                    <th>⚡ Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {clients.map((c, i) => (
                    <tr key={c.id}>
                      <td style={{ color: 'var(--slate-400)', fontSize: 13 }}>{i + 1}</td>
                      <td>
                        <span
                          onClick={() => viewClient(c.name)}
                          style={{ fontWeight: 700, color: 'var(--indigo-600)', cursor: 'pointer' }}
                        >{c.name}</span>
                      </td>
                      <td>
                        <span className="badge badge--indigo">{c.doc_count} doc{c.doc_count !== 1 ? 's' : ''}</span>
                      </td>
                      <td style={{ fontSize: 13, color: 'var(--slate-500)' }}>{c.created_at}</td>
                      <td style={{ fontSize: 13, color: 'var(--slate-500)' }}>{c.updated_at}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 8 }}>
                          <button className="btn btn--ghost btn--sm" onClick={() => setEditClient(c)}>✏️ Edit</button>
                          <button className="btn btn--primary btn--sm" onClick={() => viewClient(c.name)}>👁️ View</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {!isSearch && clients.length === 20 && (
            <p style={{ textAlign: 'center', color: 'var(--slate-400)', fontSize: 13, marginTop: 14 }}>
              Showing 20 most recent clients. Use search to find specific clients.
            </p>
          )}
        </div>
      </div>

      <EditDocModal
        open={!!editClient}
        onClose={() => setEditClient(null)}
        client={editClient}
        onSaved={() => fetchClients(search)}
      />
    </>
  )
}
