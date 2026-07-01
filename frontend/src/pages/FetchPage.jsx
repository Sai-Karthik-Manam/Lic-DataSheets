import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import Navbar from '../components/Navbar'
import { ConfirmModal, LoadingOverlay } from '../components/UI'
import api from '../api/client'
import { DOC_META } from '../constants'
import { useToast } from '../context/ToastContext'

function DocCard({ type, doc, onDelete, onDownload }) {
  const meta = DOC_META[type] || { label: type, icon: '📄' }
  const [imgError, setImgError] = useState(false)

  return (
    <div className="card" style={{ textAlign: 'center', position: 'relative' }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--slate-400)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
        {meta.icon} {meta.label}
      </div>

      {doc ? (
        <>
          {!imgError && doc.image_url ? (
            <img
              src={doc.image_url}
              alt={doc.file_name}
              onError={() => setImgError(true)}
              style={{
                width: '100%', maxHeight: 140, objectFit: 'cover',
                borderRadius: 'var(--radius-sm)', marginBottom: 10,
                border: '1px solid var(--slate-200)', cursor: 'pointer',
              }}
              onClick={() => window.open(doc.image_url, '_blank')}
            />
          ) : (
            <div style={{
              height: 100, background: 'var(--slate-100)', borderRadius: 'var(--radius-sm)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 36, marginBottom: 10,
            }}>📄</div>
          )}

          <div style={{ fontSize: 12, color: 'var(--slate-600)', marginBottom: 12, wordBreak: 'break-all' }}>
            {doc.file_name}<br />
            <span style={{ color: 'var(--slate-400)' }}>{((doc.file_size || 0) / (1024 * 1024)).toFixed(2)} MB</span>
          </div>

          <div style={{ display: 'flex', gap: 6, justifyContent: 'center', flexWrap: 'wrap' }}>
            <button
              className="btn btn--primary btn--sm"
              onClick={() => onDownload(doc.file_id, doc.file_name)}
            >⬇️ Download</button>
            <button
              className="btn btn--danger btn--sm"
              onClick={() => onDelete(doc.file_id, meta.label)}
            >🗑️</button>
          </div>
        </>
      ) : (
        <div style={{
          padding: '28px 16px', color: 'var(--slate-300)', fontSize: 14, fontWeight: 500,
        }}>
          <div style={{ fontSize: 40, marginBottom: 8, opacity: 0.4 }}>{meta.icon}</div>
          Not uploaded
        </div>
      )}
    </div>
  )
}

export default function FetchPage() {
  const location = useLocation()
  const [query, setQuery] = useState('')
  const [client, setClient] = useState(location.state?.client || null)
  const [loading, setLoading] = useState(false)
  const [notFound, setNotFound] = useState(false)
  const toast = useToast()
  const [deleteTarget, setDeleteTarget] = useState(null)      // { file_id, label }
  const [deleteClientOpen, setDeleteClientOpen] = useState(false)
  const [deleteLoading, setDeleteLoading] = useState(false)

  useEffect(() => { if (location.state?.client) setClient(location.state.client) }, [location.state])

  const handleSearch = async e => {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true); setNotFound(false); setClient(null)
    try {
      const res = await api.post('/fetch-data', { name: query })
      if (res.data.success) setClient(res.data.client)
      else if (res.data.not_found) setNotFound(true)
      else toast.error(res.data.error || 'Search failed')
    } catch (err) {
      toast.error(err.response?.data?.error || 'Search failed')
    } finally { setLoading(false) }
  }

  const handleDownload = (fileId, fileName) => {
    // POST to download (triggers file download)
    const form = document.createElement('form')
    form.method = 'POST'
    form.action = '/api/download-document'
    const inp = document.createElement('input')
    inp.type = 'hidden'; inp.name = 'file_id'; inp.value = fileId
    form.appendChild(inp); document.body.appendChild(form); form.submit()
    document.body.removeChild(form)
  }

  const handleDeleteDoc = async () => {
    if (!deleteTarget) return
    setDeleteLoading(true)
    try {
      const res = await api.post('/delete-document', { file_id: deleteTarget.file_id })
      if (res.data.success) {
        toast.success('Document deleted successfully')
        // refresh
        const r2 = await api.post('/fetch-data', { name: client.name })
        if (r2.data.success) setClient(r2.data.client)
      } else {
        toast.error(res.data.error || 'Delete failed')
      }
    } catch (err) {
      toast.error(err.response?.data?.error || 'Delete failed')
    } finally {
      setDeleteLoading(false)
      setDeleteTarget(null)
    }
  }

  const handleDeleteClient = async () => {
    setDeleteLoading(true)
    try {
      const res = await api.post('/delete-client', { name: client.name })
      if (res.data.success) {
        toast.success('Client deleted successfully')
        setClient(null); setDeleteClientOpen(false); setQuery('')
      } else {
        toast.error(res.data.error)
      }
    } catch (err) {
      toast.error(err.response?.data?.error || 'Delete failed')
    } finally {
      setDeleteLoading(false); setDeleteClientOpen(false)
    }
  }

  return (
    <>
      <Navbar />
      <div className="page-wrapper">
        <div className="page-content page-content--narrow">
          <div className="page-header">
            <h1 className="page-title">🔍 Search Client Documents</h1>
            <p className="page-subtitle">Enter a client name to find and manage their documents.</p>
          </div>

          {/* Search Form */}
          <div className="card" style={{ marginBottom: 24 }}>
            <form onSubmit={handleSearch} style={{ display: 'flex', gap: 12 }}>
              <input
                className="form-input"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="🔎 Enter client name to search…"
                required
                style={{ flex: 1 }}
              />
              <button type="submit" className="btn btn--primary" disabled={loading}>
                {loading ? <span className="spinner" /> : '🔍 Search'}
              </button>
            </form>
          </div>

          {loading && <LoadingOverlay text="Searching…" />}

          {notFound && !loading && (
            <div className="card" style={{ textAlign: 'center', padding: '48px 20px' }}>
              <div style={{ fontSize: 52, marginBottom: 12, opacity: 0.4 }}>😕</div>
              <h3 style={{ fontWeight: 700, color: 'var(--slate-700)', marginBottom: 6 }}>No Client Found</h3>
              <p style={{ color: 'var(--slate-400)', fontSize: 14 }}>
                We couldn't find "<strong>{query}</strong>". Check the spelling and try again.
              </p>
            </div>
          )}

          {client && !loading && (
            <>
              {/* Client Info */}
              <div className="card" style={{
                marginBottom: 20, background: 'var(--indigo-50)',
                border: '1px solid var(--indigo-200)',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
                  <div>
                    <h2 style={{ fontSize: 20, fontWeight: 800, color: 'var(--indigo-700)', marginBottom: 10 }}>
                      👤 {client.name}
                    </h2>
                    <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
                      {[
                        { label: 'Documents', val: Object.keys(client.documents).length },
                        { label: 'Created', val: client.created_at?.slice(0, 10) || 'N/A' },
                        { label: 'Updated', val: client.updated_at?.slice(0, 10) || 'N/A' },
                      ].map(i => (
                        <div key={i.label} style={{ textAlign: 'center' }}>
                          <div style={{ fontWeight: 800, fontSize: 18, color: 'var(--indigo-700)' }}>{i.val}</div>
                          <div style={{ fontSize: 11, color: 'var(--slate-500)', fontWeight: 600 }}>{i.label}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                  <button
                    className="btn btn--danger btn--sm"
                    onClick={() => setDeleteClientOpen(true)}
                  >🗑️ Delete Client</button>
                </div>
              </div>

              {/* Documents Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 24 }}>
                {Object.entries(DOC_META).map(([type]) => (
                  <DocCard
                    key={type}
                    type={type}
                    doc={client.documents[type] || null}
                    onDelete={(file_id, label) => setDeleteTarget({ file_id, label })}
                    onDownload={handleDownload}
                  />
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Delete Doc Confirm */}
      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDeleteDoc}
        title="Delete Document"
        message={`Are you sure you want to delete the ${deleteTarget?.label}? This cannot be undone.`}
        confirmLabel="Delete"
        danger
        loading={deleteLoading}
      />

      {/* Delete Client Confirm */}
      <ConfirmModal
        open={deleteClientOpen}
        onClose={() => setDeleteClientOpen(false)}
        onConfirm={handleDeleteClient}
        title="⚠️ Delete Entire Client"
        message={`This will permanently delete ${client?.name} and ALL their documents. This action cannot be undone.`}
        confirmLabel="Delete Client"
        danger
        loading={deleteLoading}
      />
    </>
  )
}
