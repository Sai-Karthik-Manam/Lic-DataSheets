import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { ToastProvider } from './context/ToastContext'
import { ErrorBoundary } from './components/ErrorBoundary'

import LandingPage       from './pages/LandingPage'
import LoginPage         from './pages/LoginPage'
import DashboardPage     from './pages/DashboardPage'
import UploadPage        from './pages/UploadPage'
import FetchPage         from './pages/FetchPage'
import ClientsPage       from './pages/ClientsPage'
import AdminPage         from './pages/AdminPage'
import ChangePassword    from './pages/ChangePasswordPage'
import NotFoundPage      from './pages/NotFoundPage'

function ProtectedRoute({ children, adminOnly = false }) {
  const { user, loading } = useAuth()
  if (loading) return <FullPageSpinner />
  if (!user) return <Navigate to="/login" replace />
  if (adminOnly && user.role !== 'admin') return <Navigate to="/dashboard" replace />
  return children
}

function GuestRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <FullPageSpinner />
  if (user) return <Navigate to="/dashboard" replace />
  return children
}

function FullPageSpinner() {
  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--slate-50)',
    }}>
      <div style={{ textAlign: 'center' }}>
        <div className="spinner spinner--dark" style={{ width: 36, height: 36, borderWidth: 3 }} />
        <p style={{ marginTop: 16, color: 'var(--slate-500)', fontSize: 14, fontWeight: 500 }}>Loading…</p>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <ToastProvider>
          <BrowserRouter>
            <Routes>
              {/* Public */}
              <Route path="/"        element={<LandingPage />} />
              <Route path="/login"   element={<GuestRoute><LoginPage /></GuestRoute>} />

              {/* Protected */}
              <Route path="/dashboard"       element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
              <Route path="/upload"          element={<ProtectedRoute><UploadPage /></ProtectedRoute>} />
              <Route path="/search"          element={<ProtectedRoute><FetchPage /></ProtectedRoute>} />
              <Route path="/clients"         element={<ProtectedRoute><ClientsPage /></ProtectedRoute>} />
              <Route path="/change-password" element={<ProtectedRoute><ChangePassword /></ProtectedRoute>} />
              <Route path="/admin"           element={<ProtectedRoute adminOnly><AdminPage /></ProtectedRoute>} />

              {/* Fallback */}
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </BrowserRouter>
        </ToastProvider>
      </AuthProvider>
    </ErrorBoundary>
  )
}