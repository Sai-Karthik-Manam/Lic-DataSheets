import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import { useAuth } from '../context/AuthContext'
import { Alert } from '../components/UI'

export default function LoginPage() {
  const navigate = useNavigate()
  const { login } = useAuth()
  const [form, setForm] = useState({ username: '', password: '' })
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [step, setStep] = useState(1) // 1 = credentials, 2 = OTP
  const [otp, setOtp] = useState('')
  const [maskedEmail, setMaskedEmail] = useState('')

  const handleChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }))

  const handleSubmit = async e => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (step === 1) {
        const res = await api.post('/login', form)
        if (res.data.success) {
          if (res.data.require_otp) {
            setStep(2)
            setMaskedEmail(res.data.email)
          } else {
            login(res.data.user)
            navigate('/dashboard')
          }
        } else {
          setError(res.data.error || 'Login failed')
        }
      } else {
        const res = await api.post('/verify-otp', { username: form.username, otp })
        if (res.data.success) {
          login(res.data.user)
          navigate('/dashboard')
        } else {
          setError(res.data.error || 'Invalid OTP')
        }
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
          <p style={{ fontSize: 14, color: 'var(--slate-500)', marginTop: 4 }}>Sign in to your account</p>
        </div>

        {error && <Alert type="error" onClose={() => setError('')}>{error}</Alert>}

        <form onSubmit={handleSubmit}>
          {step === 1 ? (
            <>
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
                {loading ? <><span className="spinner" /> Sending OTP…</> : '🚀 Next (Send OTP)'}
              </button>
            </>
          ) : (
            <>
              <div style={{ marginBottom: 16, fontSize: 14, color: 'var(--slate-600)', textAlign: 'center', lineHeight: 1.5 }}>
                🔒 Enter your personal <strong style={{ color: 'var(--indigo-600)' }}>Security PIN</strong> to complete login.
              </div>

              <div className="form-group">
                <label className="form-label">🔢 Enter 6-Digit OTP</label>
                <input
                  className="form-input"
                  type="text"
                  value={otp}
                  onChange={e => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="Enter OTP"
                  required
                  maxLength={6}
                  autoFocus
                  style={{ textAlign: 'center', letterSpacing: '4px', fontSize: '18px', fontWeight: 'bold' }}
                />
              </div>

              <button
                type="submit"
                className="btn btn--primary btn--lg btn--full"
                disabled={loading || otp.length !== 6}
                style={{ marginTop: 8 }}
              >
                {loading ? <><span className="spinner" /> Verifying…</> : '✓ Verify & Login'}
              </button>

              <button
                type="button"
                className="btn btn--ghost btn--full"
                onClick={() => {
                  setStep(1)
                  setOtp('')
                  setError('')
                }}
                style={{ marginTop: 10 }}
              >
                ← Back to Credentials
              </button>
            </>
          )}
        </form>
      </div>
    </div>
  )
}