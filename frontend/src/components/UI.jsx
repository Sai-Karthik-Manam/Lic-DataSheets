import { useEffect } from 'react'

/* ─── Modal ──────────────────────────────────────────────────────── */
export function Modal({ open, onClose, title, children, footer, size = 'md' }) {
  useEffect(() => {
    if (open) document.body.style.overflow = 'hidden'
    else document.body.style.overflow = ''
    return () => { document.body.style.overflow = '' }
  }, [open])

  if (!open) return null

  const maxWidths = { sm: 420, md: 520, lg: 700, xl: 900 }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-box"
        style={{ maxWidth: maxWidths[size] }}
        onClick={e => e.stopPropagation()}
      >
        <div className="modal-header">
          <h2 className="modal-title">{title}</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  )
}

/* ─── Alert ──────────────────────────────────────────────────────── */
export function Alert({ type = 'info', children, onClose }) {
  if (!children) return null
  return (
    <div className={`alert alert--${type}`} style={{ position: 'relative' }}>
      {children}
      {onClose && (
        <button onClick={onClose} style={{
          position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'inherit', fontSize: 16, opacity: 0.6, padding: '2px 6px',
        }}>✕</button>
      )}
    </div>
  )
}

/* ─── Confirm Dialog ─────────────────────────────────────────────── */
export function ConfirmModal({ open, onClose, onConfirm, title, message, confirmLabel = 'Confirm', danger = false, loading = false }) {
  return (
    <Modal open={open} onClose={onClose} title={title}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose} disabled={loading}>Cancel</button>
          <button
            className={`btn ${danger ? 'btn--danger' : 'btn--primary'}`}
            onClick={onConfirm}
            disabled={loading}
          >
            {loading ? <><span className="spinner" /> Processing…</> : confirmLabel}
          </button>
        </>
      }
    >
      <p style={{ color: 'var(--slate-600)', fontSize: 15, lineHeight: 1.6 }}>{message}</p>
    </Modal>
  )
}

/* ─── Loading Overlay ────────────────────────────────────────────── */
export function LoadingOverlay({ text = 'Loading…' }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center',
      padding: '60px 20px', gap: 16,
    }}>
      <div className="spinner spinner--dark" style={{ width: 32, height: 32, borderWidth: 3 }} />
      <p style={{ color: 'var(--slate-500)', fontSize: 14, fontWeight: 500 }}>{text}</p>
    </div>
  )
}

/* ─── Empty State ────────────────────────────────────────────────── */
export function EmptyState({ icon = '📭', title, text, action }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">{icon}</div>
      <h3 className="empty-title">{title}</h3>
      {text && <p className="empty-text">{text}</p>}
      {action && <div style={{ marginTop: 20 }}>{action}</div>}
    </div>
  )
}
