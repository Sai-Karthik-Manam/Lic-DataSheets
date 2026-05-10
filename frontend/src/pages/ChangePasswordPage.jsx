import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Navbar from '../components/Navbar'
import { Alert } from '../components/UI'
import api from '../api/client'

export default function ChangePasswordPage() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ current_password: '', new_password: '', confirm_password: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [strength, setStrength] = useState(0)

  const handleChange = e => {
    setForm(f => ({ ...f, [e.target.name]: e.target.value }))
    if (e.target.name === 'new_password') calcStrength(e.target.value)
  }

  const calcStrength = pw => {
    let s = 0
    if (pw.length >= 6) s++
    if (pw.length >= 10) s++
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++
    if (/\d/.test(pw)) s++
    if (/[^a-zA-Z\d]/.test(pw)) s++
    setStrength(s)
  }

  const strengthColor = strength <= 2 ? 'var(--red-500)' : strength <= 3 ? 'var(--amber-400)' : 'var(--green-500)'
  const strengthLabel = ['', 'Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'][strength] || ''

  const handleSubmit = async e => {
    e.preventDefault()
    if (form.new_password !== form.confirm_password) { setError('New passwords do not match'); return }
    if (form.new_password === form.current_password) { setError('New password must be different from current'); return }
    setError(''); setSuccess(''); setLoading(true)
    try {
      const res = await api.post('/change-password', form)
      if (res.data.success) {
        setSuccess('Password changed successfully! Redirecting…')
        setTimeout(() => navigate('/dashboard'), 1500)
      } else setError(res.data.error || 'Failed')
    } catch (err) { setError(err.response?.data?.error || 'Failed to change password') }
    finally { setLoading(false) }
  }

  return (
    <>
      <Navbar />
      <div className="page-wrapper">
        <div className="page-content" style={{ maxWidth: 480, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 28 }}>
            <div style={{ fontSize: 52, marginBottom: 10 }}>🔐</div>
            <h1 className="page-title">Change Password</h1>
            <p className="page-subtitle">Update your account password securely</p>
          </div>

          {error && <Alert type="error" onClose={() => setError('')}>{error}</Alert>}
          {success && <Alert type="success">{success}</Alert>}

          <div className="card">
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label className="form-label">🔑 Current Password</label>
                <input className="form-input" type="password" name="current_password"
                  value={form.current_password} onChange={handleChange} required autoFocus />
              </div>

              <div className="form-group">
                <label className="form-label">🔒 New Password</label>
                <input className="form-input" type="password" name="new_password"
                  value={form.new_password} onChange={handleChange} required minLength={6} />
                {form.new_password && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ height: 4, background: 'var(--slate-100)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${(strength / 5) * 100}%`, background: strengthColor, borderRadius: 2, transition: 'all 0.3s' }} />
                    </div>
                    <p style={{ fontSize: 12, color: strengthColor, fontWeight: 600, marginTop: 4 }}>{strengthLabel}</p>
                  </div>
                )}
              </div>

              <div className="form-group">
                <label className="form-label">🔒 Confirm New Password</label>
                <input className="form-input" type="password" name="confirm_password"
                  value={form.confirm_password} onChange={handleChange} required minLength={6} />
                {form.confirm_password && form.new_password !== form.confirm_password && (
                  <p style={{ fontSize: 12, color: 'var(--red-500)', marginTop: 4, fontWeight: 500 }}>⚠ Passwords do not match</p>
                )}
              </div>

              <div style={{ padding: '12px 14px', background: 'var(--slate-50)', borderRadius: 'var(--radius-sm)', marginBottom: 20, fontSize: 12, color: 'var(--slate-500)', lineHeight: 1.7 }}>
                <strong>Requirements:</strong> Min 6 characters · Mix of uppercase, lowercase & numbers · Must differ from current.
              </div>

              <button type="submit" className="btn btn--primary btn--full btn--lg" disabled={loading}>
                {loading ? <><span className="spinner" /> Changing…</> : '✓ Change Password'}
              </button>
            </form>
          </div>

          <div style={{ textAlign: 'center', marginTop: 20 }}>
            <button className="btn btn--ghost btn--sm" onClick={() => navigate('/dashboard')}>← Back to Dashboard</button>
          </div>
        </div>
      </div>
    </>
  )
}
