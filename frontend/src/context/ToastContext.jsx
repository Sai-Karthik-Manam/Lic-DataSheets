import { createContext, useContext, useState, useCallback, useRef } from 'react'

// ─── Toast Context ─────────────────────────────────────────────────────────────

const ToastContext = createContext(null)

let toastIdCounter = 0

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const timers = useRef({})

  const dismiss = useCallback((id) => {
    setToasts(t => t.map(toast => toast.id === id ? { ...toast, exiting: true } : toast))
    setTimeout(() => setToasts(t => t.filter(toast => toast.id !== id)), 350)
    clearTimeout(timers.current[id])
    delete timers.current[id]
  }, [])

  const toast = useCallback(({ message, type = 'info', duration = 4000 }) => {
    const id = ++toastIdCounter
    setToasts(t => [...t, { id, message, type, exiting: false }])
    if (duration > 0) {
      timers.current[id] = setTimeout(() => dismiss(id), duration)
    }
    return id
  }, [dismiss])

  const success = useCallback((msg, opts) => toast({ message: msg, type: 'success', ...opts }), [toast])
  const error   = useCallback((msg, opts) => toast({ message: msg, type: 'error',   duration: 6000, ...opts }), [toast])
  const info    = useCallback((msg, opts) => toast({ message: msg, type: 'info',    ...opts }), [toast])
  const warn    = useCallback((msg, opts) => toast({ message: msg, type: 'warning', ...opts }), [toast])

  return (
    <ToastContext.Provider value={{ toast, success, error, info, warn, dismiss }}>
      {children}
      <ToastContainer toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  )
}

export const useToast = () => {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}

// ─── Toast UI ─────────────────────────────────────────────────────────────────

const TOAST_STYLES = {
  success: { bg: '#f0fdf4', border: '#22c55e', icon: '✅', color: '#166534' },
  error:   { bg: '#fef2f2', border: '#ef4444', icon: '❌', color: '#991b1b' },
  info:    { bg: '#eef2ff', border: '#6366f1', icon: 'ℹ️',  color: '#3730a3' },
  warning: { bg: '#fffbeb', border: '#f59e0b', icon: '⚠️', color: '#92400e' },
}

function ToastItem({ toast, onDismiss }) {
  const style = TOAST_STYLES[toast.type] || TOAST_STYLES.info

  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 12,
      padding: '14px 16px',
      background: style.bg,
      border: `1px solid ${style.border}`,
      borderLeft: `4px solid ${style.border}`,
      borderRadius: 12,
      boxShadow: '0 8px 24px rgba(0,0,0,0.12), 0 2px 8px rgba(0,0,0,0.08)',
      maxWidth: 380,
      minWidth: 260,
      animation: toast.exiting
        ? 'toastOut 0.35s cubic-bezier(0.4,0,1,1) forwards'
        : 'toastIn 0.35s cubic-bezier(0,0,0.2,1)',
      position: 'relative',
      backdropFilter: 'blur(8px)',
    }}>
      <span style={{ fontSize: 18, lineHeight: 1.4, flexShrink: 0 }}>{style.icon}</span>
      <span style={{ flex: 1, fontSize: 14, fontWeight: 500, color: style.color, lineHeight: 1.5 }}>
        {toast.message}
      </span>
      <button
        onClick={() => onDismiss(toast.id)}
        style={{
          background: 'none', border: 'none', cursor: 'pointer',
          color: style.color, opacity: 0.5, fontSize: 16, padding: '0 2px',
          lineHeight: 1, flexShrink: 0, marginTop: 1,
          transition: 'opacity 0.2s',
        }}
        onMouseEnter={e => e.currentTarget.style.opacity = '1'}
        onMouseLeave={e => e.currentTarget.style.opacity = '0.5'}
      >✕</button>
    </div>
  )
}

function ToastContainer({ toasts, onDismiss }) {
  if (toasts.length === 0) return null
  return (
    <>
      <style>{`
        @keyframes toastIn {
          from { opacity: 0; transform: translateX(60px) scale(0.95); }
          to   { opacity: 1; transform: translateX(0)    scale(1); }
        }
        @keyframes toastOut {
          from { opacity: 1; transform: translateX(0) scale(1); max-height: 100px; margin-bottom: 8px; }
          to   { opacity: 0; transform: translateX(60px) scale(0.95); max-height: 0; margin-bottom: 0; }
        }
      `}</style>
      <div style={{
        position: 'fixed', top: 80, right: 20, zIndex: 9999,
        display: 'flex', flexDirection: 'column', gap: 8,
        pointerEvents: 'none',
      }}>
        {toasts.map(t => (
          <div key={t.id} style={{ pointerEvents: 'auto' }}>
            <ToastItem toast={t} onDismiss={onDismiss} />
          </div>
        ))}
      </div>
    </>
  )
}
