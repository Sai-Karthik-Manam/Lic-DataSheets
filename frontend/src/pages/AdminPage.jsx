import { useState, useEffect } from 'react'
import Navbar from '../components/Navbar'
import { Alert, Modal, ConfirmModal, LoadingOverlay, EmptyState } from '../components/UI'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'

/* ─── Add User Modal ─────────────────────────────────────────────── */
function AddUserModal({ open, onClose, onAdded }) {
  const [form, setForm] = useState({ username: '', email: '', password: '', role: 'user' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }))

  const handleSubmit = async () => {
    setError('')
    if (!form.username || !form.email || !form.password) { setError('All fields are required'); return }
    if (form.password.length < 6) { setError('Password must be at least 6 characters'); return }
    setLoading(true)
    try {
      const res = await api.post('/admin/user/add', form)
      if (res.data.success) {
        onAdded()
        onClose()
        setForm({ username: '', email: '', password: '', role: 'user' })
      } else setError(res.data.error || 'Failed to add user')
    } catch (err) { setError(err.response?.data?.error || 'Failed to add user') }
    finally { setLoading(false) }
  }

  return (
    <Modal open={open} onClose={onClose} title="➕ Add New User"
      footer={<>
        <button className="btn btn--ghost" onClick={onClose} disabled={loading}>Cancel</button>
        <button className="btn btn--primary" onClick={handleSubmit} disabled={loading}>
          {loading ? <><span className="spinner" /> Creating…</> : '✓ Create User'}
        </button>
      </>}
    >
      {error && <Alert type="error" onClose={() => setError('')}>{error}</Alert>}
      <div className="form-group">
        <label className="form-label">👤 Username</label>
        <input className="form-input" name="username" type="text" value={form.username} onChange={handleChange} required />
      </div>
      <div className="form-group">
        <label className="form-label">📧 Email</label>
        <input className="form-input" name="email" type="email" value={form.email} onChange={handleChange} required />
      </div>
      <div className="form-group">
        <label className="form-label">🔑 Password</label>
        <input className="form-input" name="password" type="password" value={form.password} onChange={handleChange} required minLength={6} />
      </div>
      <div className="form-group">
        <label className="form-label">👑 Role</label>
        <select className="form-select" name="role" value={form.role} onChange={handleChange}>
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </div>
    </Modal>
  )
}

/* ─── Reset Password Modal ───────────────────────────────────────── */
function ResetPasswordModal({ open, onClose, user, onReset }) {
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleReset = async () => {
    if (!password || password.length < 6) { setError('Password must be at least 6 characters'); return }
    setLoading(true); setError('')
    try {
      const res = await api.post(`/admin/user/${user.id}/password`, { new_password: password })
      if (res.data.success) { onReset(res.data.message); onClose(); setPassword('') }
      else setError(res.data.error || 'Failed')
    } catch (err) { setError(err.response?.data?.error || 'Failed') }
    finally { setLoading(false) }
  }

  return (
    <Modal open={open} onClose={onClose} title={`🔑 Reset Password: ${user?.username}`}
      footer={<>
        <button className="btn btn--ghost" onClick={onClose} disabled={loading}>Cancel</button>
        <button className="btn btn--primary" onClick={handleReset} disabled={loading}>
          {loading ? <><span className="spinner" /> Resetting…</> : '✓ Reset Password'}
        </button>
      </>}
    >
      {error && <Alert type="error" onClose={() => setError('')}>{error}</Alert>}
      <div className="form-group">
        <label className="form-label">New Password (min 6 chars)</label>
        <input className="form-input" type="password" value={password}
          onChange={e => setPassword(e.target.value)} required minLength={6} autoFocus />
      </div>
    </Modal>
  )
}

/* ─── Activity Modal ─────────────────────────────────────────────── */
function ActivityModal({ open, onClose, user }) {
  const [activities, setActivities] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (open && user) {
      setLoading(true)
      api.get(`/admin/user/${user.id}/activity`)
        .then(res => { if (res.data.success) setActivities(res.data.activities) })
        .finally(() => setLoading(false))
    }
  }, [open, user])

  return (
    <Modal open={open} onClose={onClose} title={`📊 Activity: ${user?.username}`} size="lg">
      {loading ? <LoadingOverlay text="Loading activity…" /> : activities.length === 0
        ? <EmptyState icon="📋" title="No activity found" text="This user has no recorded activity." />
        : (
          <div style={{ maxHeight: 400, overflowY: 'auto' }}>
            {activities.map((a, i) => (
              <div key={i} style={{
                padding: '12px 0',
                borderBottom: i < activities.length - 1 ? '1px solid var(--slate-100)' : 'none',
              }}>
                <div style={{ fontWeight: 600, color: 'var(--slate-800)', fontSize: 13 }}>{a.action}</div>
                {a.details && <div style={{ color: 'var(--slate-500)', fontSize: 13, marginTop: 2 }}>{a.details}</div>}
                <div style={{ color: 'var(--slate-400)', fontSize: 11, marginTop: 4 }}>
                  🕐 {a.timestamp} · 🌐 {a.ip || '—'}
                </div>
              </div>
            ))}
          </div>
        )
      }
    </Modal>
  )
}

/* ─── Main Admin Page ────────────────────────────────────────────── */
export default function AdminPage() {
  const { user: currentUser } = useAuth()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Modal states
  const [addOpen, setAddOpen] = useState(false)
  const [resetTarget, setResetTarget] = useState(null)
  const [actTarget, setActTarget] = useState(null)
  const [confirmAction, setConfirmAction] = useState(null) // { type, userId, username, payload, label }
  const [actionLoading, setActionLoading] = useState(false)

  const fetchData = async () => {
    setLoading(true)
    try {
      const res = await api.get('/admin/dashboard')
      if (res.data.success) setData(res.data)
      else setError(res.data.error || 'Failed to load')
    } catch { setError('Failed to load admin dashboard') }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchData() }, [])

  /* ─── Confirmed actions (role, unlock, delete) ─── */
  const doConfirmedAction = async () => {
    if (!confirmAction) return
    setActionLoading(true); setError('')
    try {
      const { type, userId, payload } = confirmAction
      let res
      if (type === 'role')   res = await api.post(`/admin/user/${userId}/role`, { role: payload })
      if (type === 'unlock') res = await api.post(`/admin/user/${userId}/unlock`)
      if (type === 'delete') res = await api.post(`/admin/user/${userId}/delete`)
      if (res?.data?.success) { setSuccess(res.data.message); fetchData() }
      else setError(res?.data?.error || 'Action failed')
    } catch (err) { setError(err.response?.data?.error || 'Action failed') }
    finally { setActionLoading(false); setConfirmAction(null) }
  }

  if (loading) return (
    <>
      <Navbar />
      <div className="page-wrapper"><LoadingOverlay text="Loading admin panel…" /></div>
    </>
  )

  const { stats = {}, users = [] } = data || {}

  const STAT_CARDS = [
    { label: 'Total Users',    val: stats.total_users    || 0, color: 'var(--indigo-600)' },
    { label: 'Admin Users',    val: stats.admin_users    || 0, color: 'var(--red-500)' },
    { label: 'Regular Users',  val: stats.regular_users  || 0, color: 'var(--green-500)' },
    { label: 'Total Clients',  val: stats.total_clients  || 0, color: '#0284c7' },
    { label: 'Total Docs',     val: stats.total_documents || 0, color: 'var(--amber-500)' },
  ]

  return (
    <>
      <Navbar />
      <div className="page-wrapper">
        <div className="page-content">
          <div className="page-header">
            <h1 className="page-title">⚙️ Admin Control Panel</h1>
            <p className="page-subtitle">Manage users, roles, and system settings</p>
          </div>

          {error   && <Alert type="error"   onClose={() => setError('')}>{error}</Alert>}
          {success && <Alert type="success" onClose={() => setSuccess('')}>{success}</Alert>}

          {/* Stats */}
          <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', marginBottom: 32 }}>
            {STAT_CARDS.map(s => (
              <div key={s.label} className="stat-card">
                <div style={{ fontSize: 28, fontWeight: 800, color: s.color, lineHeight: 1 }}>{s.val}</div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--slate-500)', marginTop: 4 }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Users table header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--slate-800)' }}>📋 All Users</h2>
            <button className="btn btn--primary" onClick={() => setAddOpen(true)}>➕ Add New User</button>
          </div>

          {users.length === 0 ? (
            <EmptyState icon="👤" title="No users found" text="Add a user to get started." />
          ) : (
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u, i) => {
                    const isSelf = u.id === currentUser?.user_id
                    return (
                      <tr key={u.id}>
                        <td style={{ color: 'var(--slate-400)', fontSize: 13 }}>{i + 1}</td>
                        <td>
                          <strong style={{ color: 'var(--slate-800)' }}>{u.username}</strong>
                          {isSelf && <span className="badge badge--indigo" style={{ marginLeft: 8, fontSize: 10 }}>You</span>}
                        </td>
                        <td style={{ fontSize: 13, color: 'var(--slate-500)' }}>{u.email || '—'}</td>
                        <td>
                          <span className={`badge badge--${u.role === 'admin' ? 'red' : 'green'}`}>
                            {u.role.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ fontSize: 13, color: 'var(--slate-500)', whiteSpace: 'nowrap' }}>{u.created_at}</td>
                        <td>
                          {u.locked_until
                            ? <span className="badge badge--amber">🔒 LOCKED</span>
                            : <span className="badge badge--green">✓ ACTIVE</span>
                          }
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', minWidth: 240 }}>
                            {/* Promote / Demote */}
                            {u.role === 'user' && (
                              <button className="btn btn--primary btn--sm" onClick={() => setConfirmAction({
                                type: 'role', userId: u.id, payload: 'admin',
                                label: `Promote "${u.username}" to Admin?`,
                              })}>⬆ Promote</button>
                            )}
                            {u.role === 'admin' && !isSelf && (
                              <button className="btn btn--ghost btn--sm" onClick={() => setConfirmAction({
                                type: 'role', userId: u.id, payload: 'user',
                                label: `Demote "${u.username}" to User?`,
                              })}>⬇ Demote</button>
                            )}

                            {/* Unlock */}
                            {u.locked_until && (
                              <button
                                className="btn btn--ghost btn--sm"
                                style={{ color: 'var(--green-800)', borderColor: 'var(--green-500)' }}
                                onClick={() => setConfirmAction({
                                  type: 'unlock', userId: u.id,
                                  label: `Unlock account for "${u.username}"?`,
                                })}
                              >🔓 Unlock</button>
                            )}

                            {/* Reset Password */}
                            <button
                              className="btn btn--ghost btn--sm"
                              style={{ color: '#7c3aed', borderColor: '#c4b5fd' }}
                              onClick={() => setResetTarget(u)}
                            >🔑 Reset</button>

                            {/* Activity */}
                            <button
                              className="btn btn--ghost btn--sm"
                              style={{ color: 'var(--blue-800)', borderColor: 'var(--blue-500)' }}
                              onClick={() => setActTarget(u)}
                            >📊 Activity</button>

                            {/* Delete */}
                            {!isSelf && (
                              <button className="btn btn--danger btn--sm" onClick={() => setConfirmAction({
                                type: 'delete', userId: u.id,
                                label: `Permanently delete user "${u.username}"? This cannot be undone.`,
                              })}>🗑 Delete</button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Modals */}
      <AddUserModal
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onAdded={() => { fetchData(); setSuccess('User created successfully!') }}
      />

      <ResetPasswordModal
        open={!!resetTarget}
        onClose={() => setResetTarget(null)}
        user={resetTarget}
        onReset={(msg) => setSuccess(msg)}
      />

      <ActivityModal
        open={!!actTarget}
        onClose={() => setActTarget(null)}
        user={actTarget}
      />

      <ConfirmModal
        open={!!confirmAction}
        onClose={() => setConfirmAction(null)}
        onConfirm={doConfirmedAction}
        title="Confirm Action"
        message={confirmAction?.label || ''}
        danger={confirmAction?.type === 'delete'}
        confirmLabel={confirmAction?.type === 'delete' ? 'Delete' : 'Confirm'}
        loading={actionLoading}
      />
    </>
  )
}
