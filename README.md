
# 📊 LIC Manager — React Edition

A full-stack document management system for LIC agents.
**Flask REST API backend + React (Vite) frontend.**

---

## 🗂 Project Structure

```
lic-react/
├── app.py                  # Flask REST API (all routes under /api/*)
├── requirements.txt
├── procfile
├── .env.example
├── .gitignore
│
└── frontend/               # React + Vite app
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── main.jsx
        ├── App.jsx             # Router + protected routes
        ├── index.css           # Global design system
        ├── api/
        │   └── client.js       # Axios + CSRF interceptor
        ├── context/
        │   └── AuthContext.jsx  # Global auth state
        ├── components/
        │   ├── Navbar.jsx
        │   └── UI.jsx          # Modal, Alert, Spinner, EmptyState
        └── pages/
            ├── LandingPage.jsx
            ├── LoginPage.jsx
            ├── VerifyOtpPage.jsx
            ├── DashboardPage.jsx
            ├── UploadPage.jsx
            ├── FetchPage.jsx
            ├── ClientsPage.jsx
            ├── AdminPage.jsx
            ├── ChangePasswordPage.jsx
            └── NotFoundPage.jsx
```

---

## 🛠 Setup & Installation

### 1. Clone & configure environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

### 2. Backend (Flask API)

```bash
python -m venv env
# Windows:
env\Scripts\activate
# Linux/Mac:
source env/bin/activate

pip install -r requirements.txt
python app.py
# API runs on http://localhost:5000
```

### 3. Frontend (React)

```bash
cd frontend
npm install
npm run dev
# React app runs on http://localhost:5173
# Requests to /api/* are proxied to Flask via vite.config.js
```

### 4. First run

- Visit **http://localhost:5173**
- On first startup, Flask auto-syncs your Google Drive
- Login with existing user credentials; OTP sent via email

---

## 🔑 Key Differences from Flask Template Version

| Feature | Old (Jinja2) | New (React) |
|---|---|---|
| Frontend | Server-rendered HTML | React SPA (Vite) |
| Auth flow | Session + redirect | Session + JSON API |
| CSRF | Form hidden field | `X-CSRFToken` header |
| Navigation | Full page reloads | Client-side routing |
| API | Mixed HTML+JSON | Pure REST JSON API |
| Styling | CSS file | CSS variables design system |

---

## 🚀 Production Deployment

### Build React for production
```bash
cd frontend
npm run build
# Outputs to ../static/dist/
```

### Serve React from Flask (optional)
Add to `app.py`:
```python
from flask import send_from_directory

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react(path):
    if path and os.path.exists(os.path.join('static/dist', path)):
        return send_from_directory('static/dist', path)
    return send_from_directory('static/dist', 'index.html')
```

### Or deploy separately
- **Flask API** → Railway / Render / Heroku
- **React** → Vercel / Netlify
- Set `FRONTEND_URL` in `.env` to your React URL

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/me` | Current user session |
| GET | `/api/csrf-token` | Fetch CSRF token |
| POST | `/api/login` | Login (sends OTP) |
| POST | `/api/verify-otp` | Verify OTP, establish session |
| POST | `/api/resend-otp` | Resend OTP |
| POST | `/api/logout` | Clear session |
| POST | `/api/change-password` | Change password |
| GET | `/api/dashboard` | Dashboard stats |
| POST | `/api/upload` | Upload client documents |
| POST | `/api/fetch-data` | Search client by name |
| GET | `/api/clients` | List clients (with search) |
| GET | `/api/client/:id/documents` | Get client's documents |
| POST | `/api/client/:id/update-documents` | Update/delete documents |
| POST | `/api/download-document` | Download a document |
| POST | `/api/delete-document` | Delete a document |
| POST | `/api/delete-client` | Delete client + all docs |
| GET | `/api/quick-search` | Autocomplete search |
| POST | `/api/manual-sync` | Sync Google Drive |
| GET | `/api/admin/dashboard` | Admin stats + users |
| POST | `/api/admin/user/add` | Add new user |
| POST | `/api/admin/user/:id/role` | Change user role |
| POST | `/api/admin/user/:id/password` | Reset user password |
| POST | `/api/admin/user/:id/unlock` | Unlock locked account |
| POST | `/api/admin/user/:id/delete` | Delete user |
| GET | `/api/admin/user/:id/activity` | User activity log |



**Made with ❤️ for LIC Agents**
