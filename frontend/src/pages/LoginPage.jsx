import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import { Alert } from '../components/UI'

export default function LoginPage() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '' })
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }))

  const handleSubmit = async e => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await api.post('/login', form)
      if (res.data.success) {
        navigate('/verify-otp')
      } else {
        setError(res.data.error || 'Login failed')
      }
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'linear-gradient(135deg, #1a1a4e 0%, #3030a0 100%)',
      padding: 20,
    }}>
      <div className="animate-fade-in" style={{
        background: 'white', borderRadius: 'var(--radius-xl)',
        padding: '40px 36px', width: '100%', maxWidth: 440,
        boxShadow: 'var(--shadow-xl)',
      }}>
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{ fontSize: 52, marginBottom: 10 }}>🔐</div>
          <h1 style={{ fontSize: 26, fontWeight: 800, color: 'var(--slate-900)' }}>Welcome Back!</h1>
          <p style={{ fontSize: 14, color: 'var(--slate-500)', marginTop: 4 }}>Login with OTP verification</p>
        </div>

        {error && <Alert type="error" onClose={() => setError('')}>{error}</Alert>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">👤 Username</label>
            <input
              className="form-input"
              type="text"
              name="username"
              value={form.username}
              onChange={handleChange}
              placeholder="Enter your username"
              required
              autoFocus
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label className="form-label">🔑 Password</label>
            <div style={{ display: 'flex', gap: 10 }}>
              <input
                className="form-input"
                type={showPass ? 'text' : 'password'}
                name="password"
                value={form.password}
                onChange={handleChange}
                placeholder="Enter your password"
                required
                autoComplete="current-password"
                style={{ flex: 1 }}
              />
              <button
                type="button"
                className="btn btn--ghost btn--sm"
                style={{ whiteSpace: 'nowrap', minWidth: 64 }}
                onClick={() => setShowPass(v => !v)}
              >
                {showPass ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="btn btn--primary btn--lg btn--full"
            disabled={loading}
            style={{ marginTop: 8 }}
          >
            {loading ? <><span className="spinner" /> Sending OTP…</> : '🚀 Login & Get OTP'}
          </button>
        </form>

        <div style={{
          marginTop: 20, padding: '14px 16px',
          background: 'var(--indigo-50)', borderRadius: 'var(--radius-sm)',
          borderLeft: '3px solid var(--indigo-400)',
        }}>
          <p style={{ fontSize: 13, color: 'var(--indigo-800)', lineHeight: 1.6 }}>
            <strong>🔐 Two-Factor Authentication</strong><br />
            After entering credentials, an OTP will be sent to your registered email. Valid for 5 minutes.
          </p>
        </div>
      </div>
    </div>
  )
}
