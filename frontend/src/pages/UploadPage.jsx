import { useState, useRef } from 'react'
import Navbar from '../components/Navbar'
import api from '../api/client'
import { DOC_TYPES } from '../constants'
import { useToast } from '../context/ToastContext'

function DocCard({ doc, file, onFileChange }) {
  const inputRef = useRef()
  const [preview, setPreview] = useState(null)
  const [isDragging, setIsDragging] = useState(false)
  const hasFil = !!file
  const toast = useToast()

  const processFile = (f) => {
    if (!f) return
    if (f.size > 10 * 1024 * 1024) { toast.error('File too large! Max 10MB.'); return }
    onFileChange(doc.key, f)
    if (f.type.startsWith('image/')) {
      const reader = new FileReader()
      reader.onload = ev => setPreview(ev.target.result)
      reader.readAsDataURL(f)
    } else {
      setPreview(null)
    }
  }

  const handleChange = (e) => processFile(e.target.files[0])

  const handleDrop = (e) => {
    e.preventDefault(); e.stopPropagation(); setIsDragging(false)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0])
    }
  }

  const removeFile = (e) => { e.stopPropagation(); onFileChange(doc.key, null); setPreview(null); inputRef.current.value = '' }

  let baseClass = 'drop-zone'
  if (isDragging) baseClass += ' dragging-over'
  if (hasFil) baseClass += ' has-file'
  if (!hasFil && doc.required) baseClass += ' required-empty'

  return (
    <div 
      className={baseClass}
      onClick={() => !hasFil && inputRef.current.click()}
      onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); setIsDragging(true) }}
      onDragLeave={(e) => { e.preventDefault(); e.stopPropagation(); setIsDragging(false) }}
      onDrop={handleDrop}
    >
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

      {!file ? (
        <span style={{ fontSize: 13, color: 'var(--slate-500)', fontWeight: 500, marginTop: 4 }}>
          Drag & drop or <span style={{ color: 'var(--indigo-600)' }}>click to browse</span>
        </span>
      ) : (
        <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
            <button type="button" className="btn btn--ghost btn--sm" onClick={(e) => { e.stopPropagation(); inputRef.current.click() }}>🔄 Replace</button>
            <button type="button" className="btn btn--danger btn--sm" onClick={removeFile}>✕</button>
        </div>
      )}
    </div>
  )
}

export default function UploadPage() {
  const [clientName, setClientName] = useState('')
  const [files, setFiles] = useState({})
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const toast = useToast()

  const handleFileChange = (key, file) => {
    setFiles(f => file ? { ...f, [key]: file } : (() => { const c = { ...f }; delete c[key]; return c })())
  }

  const handleSubmit = async e => {
    e.preventDefault()
    if (!files.datasheet) { toast.error('Datasheet is required.'); return }
    setLoading(true); setProgress(0)

    const fd = new FormData()
    fd.append('name', clientName)
    DOC_TYPES.forEach(d => { if (files[d.key]) fd.append(d.key, files[d.key]) })

    try {
      const interval = setInterval(() => setProgress(p => Math.min(p + 8, 88)), 350)
      const res = await api.post('/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      clearInterval(interval); setProgress(100)
      if (res.data.success) {
        toast.success(res.data.message)
        if (res.data.errors && res.data.errors.length > 0) {
          res.data.errors.forEach(err => toast.warn(err))
        }
        setClientName('')
        setFiles({})
      } else {
        toast.error(res.data.error || 'Upload failed')
      }
    } catch (err) {
      toast.error(err.response?.data?.error || 'Upload error. Please try again.')
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
