import { useState, useRef } from 'react'
import Navbar from '../components/Navbar'
import { Alert } from '../components/UI'
import api from '../api/client'

const DOC_TYPES = [
  { key: 'datasheet',    label: '📄 Datasheet',    icon: '📊', required: true },
  { key: 'aadhaar',      label: '🪪 Aadhaar',      icon: '🪪', required: false },
  { key: 'pan',          label: '💳 PAN Card',     icon: '💳', required: false },
  { key: 'bank_account', label: '🏦 Bank Account', icon: '🏦', required: false },
]

function DocCard({ doc, file, onFileChange }) {
  const inputRef = useRef()
  const [preview, setPreview] = useState(null)
  const hasFil = !!file

  const handleChange = (e) => {
    const f = e.target.files[0]
    if (!f) return
    if (f.size > 10 * 1024 * 1024) { alert('File too large! Max 10MB.'); return }
    onFileChange(doc.key, f)
    if (f.type.startsWith('image/')) {
      const reader = new FileReader()
      reader.onload = ev => setPreview(ev.target.result)
      reader.readAsDataURL(f)
    } else {
      setPreview(null)
    }
  }

  const removeFile = () => { onFileChange(doc.key, null); setPreview(null); inputRef.current.value = '' }

  return (
    <div style={{
      border: `2px ${hasFil ? 'solid' : 'dashed'} ${hasFil ? 'var(--green-500)' : doc.required ? 'var(--red-500)' : 'var(--slate-300)'}`,
      borderRadius: 'var(--radius-lg)', padding: 20, background: hasFil ? 'var(--green-100)' : 'white',
      transition: 'all 0.25s', display: 'flex', flexDirection: 'column', gap: 10, alignItems: 'center',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: 38 }}>{doc.icon}</div>
      <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--slate-700)' }}>
        {doc.label}
        {doc.required && <span style={{ color: 'var(--red-500)', marginLeft: 4 }}>*</span>}
      </div>

      {preview && (
        <img src={preview} alt="preview"
          style={{ width: '100%', maxHeight: 80, objectFit: 'cover', borderRadius: 8, border: '1px solid var(--slate-200)' }}
        />
      )}

      {file && (
        <div style={{ fontSize: 12, color: 'var(--slate-600)', fontWeight: 500 }}>
          ✅ {file.name}<br />
          <span style={{ color: 'var(--slate-400)' }}>{(file.size / (1024 * 1024)).toFixed(2)} MB</span>
        </div>
      )}

      <input ref={inputRef} type="file" accept="image/*,application/pdf" onChange={handleChange} style={{ display: 'none' }} />

      {!file
        ? <button type="button" className="btn btn--primary btn--sm" onClick={() => inputRef.current.click()}>📁 Choose File</button>
        : <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" className="btn btn--ghost btn--sm" onClick={() => inputRef.current.click()}>🔄 Replace</button>
            <button type="button" className="btn btn--danger btn--sm" onClick={removeFile}>✕</button>
          </div>
      }
    </div>
  )
}

export default function UploadPage() {
  const [clientName, setClientName] = useState('')
  const [files, setFiles] = useState({})
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [success, setSuccess] = useState(null)
  const [error, setError] = useState('')

  const handleFileChange = (key, file) => {
    setFiles(f => file ? { ...f, [key]: file } : (() => { const c = { ...f }; delete c[key]; return c })())
  }

  const handleSubmit = async e => {
    e.preventDefault()
    if (!files.datasheet) { setError('Datasheet is required.'); return }
    setError(''); setSuccess(null); setLoading(true); setProgress(0)

    const fd = new FormData()
    fd.append('name', clientName)
    DOC_TYPES.forEach(d => { if (files[d.key]) fd.append(d.key, files[d.key]) })

    try {
      const interval = setInterval(() => setProgress(p => Math.min(p + 8, 88)), 350)
      const res = await api.post('/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      clearInterval(interval); setProgress(100)
      if (res.data.success) {
        setSuccess(res.data)
        setClientName('')
        setFiles({})
      } else {
        setError(res.data.error || 'Upload failed')
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Upload error. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <Navbar />
      <div className="page-wrapper">
        <div className="page-content page-content--narrow">
          <div className="page-header">
            <h1 className="page-title">📤 Upload Client Documents</h1>
            <p className="page-subtitle">Upload Datasheet (required), Aadhaar, PAN & Bank documents for a client.</p>
          </div>

          {error && <Alert type="error" onClose={() => setError('')}>{error}</Alert>}

          {success && (
            <div className="alert alert--success">
              ✅ <strong>{success.message}</strong><br />
              Client: <strong>{success.client_name}</strong> · {success.uploaded.length} document(s) uploaded.
              {success.errors?.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  {success.errors.map((e, i) => <div key={i} style={{ color: 'var(--red-800)', fontSize: 13 }}>⚠ {e}</div>)}
                </div>
              )}
            </div>
          )}

          <div className="card">
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label className="form-label">👤 Client Name <span style={{ color: 'var(--red-500)' }}>*</span></label>
                <input
                  className="form-input"
                  type="text"
                  value={clientName}
                  onChange={e => setClientName(e.target.value)}
                  placeholder="Enter client name (e.g. Ramesh Kumar)"
                  required
                  autoFocus
                  disabled={loading}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16, marginBottom: 24 }}>
                {DOC_TYPES.map(d => (
                  <DocCard key={d.key} doc={d} file={files[d.key]} onFileChange={handleFileChange} />
                ))}
              </div>

              {/* Progress Bar */}
              {loading && (
                <div style={{ height: 6, background: 'var(--slate-100)', borderRadius: 3, marginBottom: 16, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', width: `${progress}%`,
                    background: 'var(--grad-primary)', borderRadius: 3, transition: 'width 0.3s ease',
                  }} />
                </div>
              )}

              <div style={{
                padding: '14px 16px', background: '#fefce8', borderRadius: 'var(--radius-sm)',
                borderLeft: '3px solid var(--amber-400)', marginBottom: 20,
                fontSize: 13, color: '#854d0e',
              }}>
                📋 <strong>Rules:</strong> Allowed formats: JPG, PNG, GIF, BMP, WEBP, PDF · Max size: 10MB per file · Datasheet is mandatory.
              </div>

              <button type="submit" className="btn btn--primary btn--lg btn--full" disabled={loading}>
                {loading ? <><span className="spinner" /> Uploading…</> : '✨ Upload Documents'}
              </button>
            </form>
          </div>
        </div>
      </div>
    </>
  )
}
