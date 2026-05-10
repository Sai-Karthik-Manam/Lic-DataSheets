import { useState, useRef, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import { useAuth } from '../context/AuthContext'
import { Alert } from '../components/UI'

const OTP_LENGTH = 6

export default function VerifyOtpPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [digits, setDigits] = useState(Array(OTP_LENGTH).fill(''))
  const [loading, setLoading] = useState(false)
  const [resending, setResending] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [timer, setTimer] = useState(30)
  const refs = useRef([])

  // Start countdown
  useEffect(() => {
    if (timer <= 0) return
    const id = setTimeout(() => setTimer(t => t - 1), 1000)
    return () => clearTimeout(id)
  }, [timer])

  const updateDigit = (index, val) => {
    const clean = val.replace(/\D/g, '').slice(-1)
    const next = [...digits]
    next[index] = clean
    setDigits(next)
    if (clean && index < OTP_LENGTH - 1) refs.current[index + 1]?.focus()
  }

  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      refs.current[index - 1]?.focus()
    }
  }

  const handlePaste = (e) => {
    e.preventDefault()
    const text = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, OTP_LENGTH)
    if (text.length === OTP_LENGTH) {
      setDigits(text.split(''))
      refs.current[OTP_LENGTH - 1]?.focus()
    }
  }

  const handleSubmit = async e => {
    e.preventDefault()
    const otp = digits.join('')
    if (otp.length !== OTP_LENGTH) { setError('Please enter the complete 6-digit OTP'); return }
    setError('')
    setLoading(true)
    try {
      const res = await api.post('/verify-otp', { otp_code: otp })
      if (res.data.success) {
        login(res.data.user)
        navigate('/dashboard')
      } else {
        setError(res.data.error || 'Invalid OTP')
        setDigits(Array(OTP_LENGTH).fill(''))
        refs.current[0]?.focus()
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Verification failed')
      setDigits(Array(OTP_LENGTH).fill(''))
      refs.current[0]?.focus()
    } finally {
      setLoading(false)
    }
  }

  const handleResend = async () => {
    setResending(true)
    setError('')
    try {
      const res = await api.post('/resend-otp')
      if (res.data.success) {
        setSuccess('OTP resent successfully! Check your email.')
        setTimer(30)
      } else {
        setError(res.data.error || 'Failed to resend OTP')
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to resend OTP')
    } finally {
      setResending(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'linear-gradient(135deg, #1a1a4e 0%, #3030a0 100%)', padding: 20,
    }}>
      <div className="animate-fade-in" style={{
        background: 'white', borderRadius: 'var(--radius-xl)', padding: '40px 36px',
        width: '100%', maxWidth: 420, boxShadow: 'var(--shadow-xl)', textAlign: 'center',
      }}>
        <div style={{ fontSize: 52, marginBottom: 10 }}>🔐</div>
        <h2 style={{ fontSize: 24, fontWeight: 800, color: 'var(--slate-900)', marginBottom: 6 }}>Verify OTP</h2>
        <p style={{ fontSize: 13, color: 'var(--slate-500)', marginBottom: 28 }}>
          Enter the 6-digit code sent to your email
        </p>

        {error && <Alert type="error" onClose={() => setError('')}>{error}</Alert>}
        {success && <Alert type="success" onClose={() => setSuccess('')}>{success}</Alert>}

        <form onSubmit={handleSubmit}>
          {/* OTP Boxes */}
          <div style={{ display: 'flex', gap: 10, justifyContent: 'center', marginBottom: 28 }}>
            {digits.map((d, i) => (
              <input
                key={i}
                ref={el => refs.current[i] = el}
                type="text"
                inputMode="numeric"
                maxLength={1}
                value={d}
                onChange={e => updateDigit(i, e.target.value)}
                onKeyDown={e => handleKeyDown(i, e)}
                onPaste={handlePaste}
                style={{
                  width: 48, height: 56, textAlign: 'center',
                  fontSize: 22, fontWeight: 700, fontFamily: 'var(--font-mono)',
                  border: `2px solid ${d ? 'var(--indigo-400)' : 'var(--slate-200)'}`,
                  borderRadius: 'var(--radius-sm)', background: d ? 'var(--indigo-50)' : 'white',
                  color: 'var(--indigo-700)', outline: 'none', transition: 'all 0.15s',
                }}
              />
            ))}
          </div>

          <button
            type="submit"
            className="btn btn--primary btn--lg btn--full"
            disabled={loading}
          >
            {loading ? <><span className="spinner" /> Verifying…</> : '✓ Verify & Login'}
          </button>
        </form>

        {/* Resend */}
        <div style={{ marginTop: 20 }}>
          <button
            className="btn btn--ghost btn--sm"
            onClick={handleResend}
            disabled={timer > 0 || resending}
            style={{ color: timer > 0 ? 'var(--slate-400)' : 'var(--indigo-600)' }}
          >
            {resending ? <><span className="spinner spinner--dark" /> Sending…</> : '📧 Resend OTP'}
          </button>
          {timer > 0 && (
            <p style={{ fontSize: 12, color: 'var(--slate-400)', marginTop: 6 }}>
              Resend available in {timer}s
            </p>
          )}
        </div>

        <Link to="/login" style={{
          display: 'block', marginTop: 20, fontSize: 13,
          color: 'var(--indigo-600)', textDecoration: 'none', fontWeight: 600,
        }}>
          ← Back to Login
        </Link>
      </div>
    </div>
  )
}
