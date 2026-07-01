import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import Navbar from '../components/Navbar'
import { Modal, EmptyState } from '../components/UI'
import api from '../api/client'
import { DOC_TYPES } from '../constants'
import { useToast } from '../context/ToastContext'

function EditDocModal({ open, onClose, client, onSaved }) {
  const [docs, setDocs] = useState({})
  const [selectedFiles, setSelectedFiles] = useState({})
  const [loading, setLoading] = useState(false)
  const [fetchingDocs, setFetchingDocs] = useState(false)
  const toast = useToast()

  useEffect(() => {
    if (open && client) {
      setFetchingDocs(true)
      setSelectedFiles({})
      api.get(`/client/${client.id}/documents`).then(res => {
        if (res.data.success) setDocs(res.data.documents)
      }).finally(() => setFetchingDocs(false))
    }
  }, [open, client])

  const handleFileSelect = (key, file) => {
    if (!file) return
    if (file.size > 10 * 1024 * 1024) { toast.error('File too large! Max 10MB.'); return }
    setSelectedFiles(p => ({ ...p, [key]: file }))
  }

  const handleMarkDelete = (key) => setSelectedFiles(p => ({ ...p, [key]: 'DELETE' }))

  const handleSave = async () => {
    if (Object.keys(selectedFiles).length === 0) { toast.error('Select at least one document to update.'); return }
    setLoading(true)
    const fd = new FormData()
    Object.entries(selectedFiles).forEach(([key, val]) => {
      if (val === 'DELETE') fd.append(`delete_${key}`, 'true')
      else fd.append(key, val)
    })
    try {
      const res = await api.post(`/client/${client.id}/update-documents`, fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      if (res.data.success) {
        toast.success('Documents updated!')
        setTimeout(() => { onSaved(); onClose() }, 1200)
      } else toast.error(res.data.error || 'Update failed')
    } catch (err) { toast.error(err.response?.data?.error || 'Update failed')
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
      {fetchingDocs ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14 }}>
          {[1,2,3,4].map(i => <div key={i} className="skeleton" style={{ height: 180 }} />)}
        </div>
      ) : (
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

function ClientDetailModal({ open, onClose, client }) {
  const toast = useToast()
  const [downloading, setDownloading] = useState(null)

  if (!client) return null

  const getFileId = (url) => {
    try { return new URL(url).searchParams.get('id') } catch { return null }
  }

  const handleDownload = async (doc) => {
    const fileId = getFileId(doc.url)
    if (!fileId) { toast.error('Cannot get file ID'); return }
    setDownloading(fileId)
    try {
      const res = await api.post('/download-document', { file_id: fileId }, { responseType: 'blob' })
      const blobUrl = window.URL.createObjectURL(new Blob([res.data]))
      const a = document.createElement('a')
      a.href = blobUrl
      a.download = doc.file_name
      a.click()
      window.URL.revokeObjectURL(blobUrl)
      toast.success(`Downloaded: ${doc.file_name}`)
    } catch { toast.error('Download failed') }
    finally { setDownloading(null) }
  }

  return (
    <Modal open={open} onClose={onClose} title={`👤 ${client.name} Details`} size="lg"
      footer={<button className="btn btn--primary" onClick={onClose}>Close</button>}
    >
      <div style={{ display: 'flex', gap: 24, marginBottom: 20, padding: 16, background: 'var(--slate-50)', borderRadius: 'var(--radius-md)' }}>
        <div>
          <div style={{ fontSize: 12, color: 'var(--slate-500)', fontWeight: 600 }}>Total Documents</div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--indigo-700)' }}>{Object.keys(client.documents || {}).length}</div>
        </div>
        <div>
          <div style={{ fontSize: 12, color: 'var(--slate-500)', fontWeight: 600 }}>Created At</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--slate-800)', marginTop: 4 }}>{client.created_at || 'N/A'}</div>
        </div>
        <div>
          <div style={{ fontSize: 12, color: 'var(--slate-500)', fontWeight: 600 }}>Last Updated</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--slate-800)', marginTop: 4 }}>{client.updated_at || 'N/A'}</div>
        </div>
      </div>

      <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 16, color: 'var(--slate-800)' }}>📄 Documents</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 16 }}>
        {DOC_TYPES.map(d => {
          const doc = client.documents?.[d.key]
          const fileId = doc ? getFileId(doc.url) : null
          const viewUrl = fileId ? `https://drive.google.com/file/d/${fileId}/view` : null
          const isDownloading = downloading === fileId
          return (
            <div key={d.key} style={{
              border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)',
              padding: 16, textAlign: 'center', background: doc ? 'white' : 'var(--slate-50)'
            }}>
              <div style={{ fontSize: 32, marginBottom: 8, opacity: doc ? 1 : 0.4 }}>{d.icon}</div>
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4, color: 'var(--slate-700)' }}>{d.name}</div>

              {doc ? (
                <>
                  <div style={{ fontSize: 11, color: 'var(--slate-500)', marginBottom: 12, wordBreak: 'break-all' }}>
                    {doc.file_name} <br/>({(doc.file_size / (1024*1024)).toFixed(2)} MB)
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <button
                      className="btn btn--primary btn--sm btn--full"
                      onClick={() => window.open(viewUrl, '_blank')}
                      disabled={!viewUrl}
                    >
                      👁️ View
                    </button>
                    <button
                      className="btn btn--ghost btn--sm btn--full"
                      onClick={() => handleDownload(doc)}
                      disabled={isDownloading}
                    >
                      {isDownloading ? <><span className="spinner" /> Downloading…</> : '⬇️ Download'}
                    </button>
                  </div>
                </>
              ) : (
                <div style={{ fontSize: 12, color: 'var(--slate-400)', fontStyle: 'italic', marginTop: 12 }}>Not uploaded</div>
              )}
            </div>
          )
        })}
      </div>
    </Modal>
  )
}

export default function ClientsPage() {
  const [clients, setClients] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [isSearch, setIsSearch] = useState(false)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const toast = useToast()
  const [editClient, setEditClient] = useState(null)
  const [viewClientData, setViewClientData] = useState(null)
  const navigate = useNavigate()

  const fetchClients = async (q = search, p = page) => {
    setLoading(true)
    try {
      const qs = new URLSearchParams()
      if (q) qs.append('search', q)
      qs.append('page', p)
      const res = await api.get(`/clients?${qs.toString()}`)
      if (res.data.success) {
        setClients(res.data.clients)
        setIsSearch(res.data.is_search)
        setTotalPages(res.data.pagination?.pages || 1)
        setPage(res.data.pagination?.page || 1)
      }
    } catch { toast.error('Failed to load clients') }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchClients(search, 1) }, [])

  const handleSearch = async e => {
    e.preventDefault()
    fetchClients(search, 1)
  }

  const viewClient = async (name) => {
    setLoading(true)
    try {
      const res = await api.post('/fetch-data', { name })
      if (res.data.success) setViewClientData(res.data.client)
      else toast.error(res.data.error || 'Failed to fetch details')
    } catch { toast.error('Failed to load client details') }
    finally { setLoading(false) }
  }

  const handleSync = async () => {
    try {
      const res = await api.post('/manual-sync')
      if (res.data.success) { fetchClients(search, page); toast.success(`✅ ${res.data.message}`) }
    } catch { toast.error('Sync failed') }
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

          {isSearch && (
            <div className="alert alert--info" style={{ marginBottom: 16 }}>
              🔍 Showing results for: <strong>"{search}"</strong>
              <button onClick={() => { setSearch(''); fetchClients('', 1) }} style={{
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
          {clients.length === 0 && !loading ? (
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
                  {loading ? (
                    Array.from({ length: 5 }).map((_, i) => (
                      <tr key={`skel-${i}`}>
                        <td colSpan="6"><div className="skeleton" style={{ height: 42, width: '100%' }} /></td>
                      </tr>
                    ))
                  ) : clients.map((c, i) => (
                    <tr key={c.id}>
                      <td style={{ color: 'var(--slate-400)', fontSize: 13 }}>{(page - 1) * 20 + i + 1}</td>
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

          {totalPages > 1 && (
            <div className="pagination">
              <button 
                className="page-btn" 
                disabled={page <= 1} 
                onClick={() => fetchClients(search, page - 1)}
              >
                ← Prev
              </button>
              
              {Array.from({ length: totalPages }).map((_, i) => {
                const p = i + 1
                if (p === 1 || p === totalPages || (p >= page - 1 && p <= page + 1)) {
                  return (
                    <button 
                      key={p} 
                      className={`page-btn ${p === page ? 'active' : ''}`}
                      onClick={() => fetchClients(search, p)}
                    >
                      {p}
                    </button>
                  )
                } else if (p === page - 2 || p === page + 2) {
                  return <span key={p} style={{ color: 'var(--slate-400)' }}>...</span>
                }
                return null
              })}

              <button 
                className="page-btn" 
                disabled={page >= totalPages} 
                onClick={() => fetchClients(search, page + 1)}
              >
                Next →
              </button>
            </div>
          )}
        </div>
      </div>

      <EditDocModal
        open={!!editClient}
        onClose={() => setEditClient(null)}
        client={editClient}
        onSaved={() => fetchClients(search, page)}
      />

      <ClientDetailModal
        open={!!viewClientData}
        onClose={() => setViewClientData(null)}
        client={viewClientData}
      />
    </>
  )
}
