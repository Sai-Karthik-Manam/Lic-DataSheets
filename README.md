# 📊 LIC Agent Datasheet Manager - Multi-Document Edition

A comprehensive Flask web application for managing LIC client documents with Google Drive integration. Upload and organize multiple documents (Datasheet, Aadhaar, PAN, Bank Account) for each client in dedicated folders!

## ✨ Key Features

### 📁 **Multi-Document Management**
- **Datasheet** (Mandatory) - Client insurance details
- **Aadhaar Card** (Optional) - Identity proof
- **PAN Card** (Optional) - Tax identification
- **Bank Account** (Optional) - Banking details
- All documents organized in client-specific folders

### 🎨 **Beautiful Modern UI**
- Stunning gradient designs with purple theme
- Smooth animations and transitions
- Fully responsive (Mobile, Tablet, Desktop)
- Interactive document cards
- Real-time file previews
- Drag & drop support

### 🔍 **Advanced Search & View**
- Search clients by name
- View all documents for a client
- Grid view with thumbnails
- Document metadata display
- Individual document download
- Selective document deletion

### 👥 **Client Management**
- View all clients in a table
- Search and filter clients
- See document count per client
- Track creation and update dates
- Delete entire client with all documents

### 🔒 **Security & Organization**
- Each client gets a dedicated Google Drive folder
- Secure file storage on Google Drive
- Database tracking of all documents
- Unique file IDs prevent duplicates
- Safe deletion with confirmations

## 📸 Screenshots

```
📤 Upload Page → 🔍 Search → 📄 Client View → 👥 All Clients
```

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Google Cloud Account
- Google Drive API enabled

### Step-by-Step Setup

1. **Clone and Setup Environment**
   ```bash
   git clone <your-repo>
   cd lic
   python -m venv env
   env\Scripts\activate  # Windows
   source env/bin/activate  # Linux/Mac
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Google OAuth Setup**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project
   - Enable Google Drive API
   - Create OAuth 2.0 credentials (Desktop app type)
   - Download credentials

4. **Configure Environment**
   ```bash
   copy env.example .env  # Windows
   cp env.example .env    # Linux/Mac
   ```
   
   Edit `.env`:
   ```env
   GOOGLE_CLIENT_ID=your_client_id_here
   GOOGLE_CLIENT_SECRET=your_client_secret_here
   GOOGLE_REFRESH_TOKEN=
   GOOGLE_DRIVE_FOLDER_ID=your_root_folder_id
   FLASK_DEBUG=True
   ```

5. **Database Migration (if upgrading from old version)**
   ```bash
   python migrate_database.py
   ```

6. **First Run - Get Refresh Token**
   ```bash
   python app.py
   ```
   - Browser will open automatically
   - Grant permissions to Google Drive
   - Copy the refresh token from console
   - Add it to `.env` file
   - Restart the app

7. **Access the Application**
   ```
   http://localhost:5000
   ```

## 📁 Project Structure

```
lic/
├── app.py                      # Main Flask application with multi-doc support
├── migrate_database.py         # Database migration script
├── quick_fix.py               # Automated diagnostic tool
├── requirements.txt            # Python dependencies
├── .env                       # Environment variables (don't commit!)
├── .gitignore                 # Git ignore rules
├── database.db                # SQLite database
│
├── templates/
│   ├── upload.html            # Multi-document upload page
│   ├── fetch.html             # Client document viewer
│   ├── clients.html           # All clients list
│   ├── home.html              # Optional landing page
│   └── 404.html               # Custom error page
│
├── static/
│   └── style.css              # Enhanced responsive CSS
│
└── uploads/                   # Temporary file storage
```

## 🗄️ Database Schema

### Clients Table
```sql
- id (PRIMARY KEY)
- name (UNIQUE) - Client name
- folder_id (UNIQUE) - Google Drive folder ID
- created_at - Creation timestamp
- updated_at - Last update timestamp
```

### Documents Table
```sql
- id (PRIMARY KEY)
- client_id (FOREIGN KEY)
- document_type - datasheet, aadhaar, pan, bank_account
- file_id (UNIQUE) - Google Drive file ID
- file_name - Original filename
- url - Direct download URL
- file_size - File size in bytes
- mime_type - File MIME type
- upload_time - Upload timestamp
```

## 🚀 Usage Guide

### Uploading Documents

1. Go to the **Upload Page** (`/`)
2. Enter client name
3. Select files:
   - **Datasheet** - Required
   - **Aadhaar** - Optional
   - **PAN** - Optional
   - **Bank Account** - Optional
4. Click "Upload Documents"
5. All files will be stored in a dedicated folder for that client

### Viewing Client Documents

1. Go to **Fetch Page** (`/fetch`)
2. Enter client name
3. View all uploaded documents
4. Download individual documents
5. Delete specific documents (except datasheet if it's the only one)

### Managing All Clients

1. Go to **All Clients** (`/clients`)
2. Browse all clients in a table
3. Search by name
4. Click "View" to see client documents
5. See statistics (total clients, documents, etc.)

### Deleting Data

**Delete Single Document:**
- Go to client view
- Click delete button on specific document
- Confirm deletion
- Note: Cannot delete datasheet if it's the only document

**Delete Entire Client:**
- Go to client view
- Scroll to "Danger Zone"
- Click "Delete Entire Client"
- Confirm by typing client name
- All documents and folder will be deleted

## 🔧 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Upload page |
| `/upload` | POST | Upload multiple documents |
| `/fetch` | GET | Search page |
| `/fetch_data` | POST | Fetch client documents |
| `/clients` | GET | List all clients |
| `/image/<file_id>` | GET | Serve image proxy |
| `/download_document` | POST | Download specific document |
| `/delete_document` | POST | Delete specific document |
| `/delete_client` | POST | Delete entire client |

## 📝 Document Types

| Type | Icon | Required | Description |
|------|------|----------|-------------|
| Datasheet | 📊 | Yes | Main insurance document |
| Aadhaar | 🪪 | No | Identity proof |
| PAN | 💳 | No | Tax ID card |
| Bank Account | 🏦 | No | Banking details |

## ⚠️ Important Notes

### Security
- Never commit `.env` or `client_secrets.json` to git
- Regenerate OAuth credentials if exposed
- Keep refresh tokens secure
- Use environment variables for all credentials

### Database
- Backup database before migration
- Old table renamed to `datasheets_old` after migration
- Foreign key constraints ensure data integrity
- Cascade delete removes all documents when client is deleted

### Google Drive
- Each client gets a dedicated folder
- Folders created automatically on first upload
- All files are made publicly readable (anyone with link)
- Files stored in your specified root folder
- Folder structure: `Root Folder → Client Name → Documents`

### File Handling
- Maximum file size: 10MB per file
- Allowed formats: JPG, PNG, GIF, BMP, WEBP, PDF
- Files temporarily stored locally during upload
- Automatic cleanup of temporary files
- Images can be previewed before upload

## 🔄 Migration from Old Version

If you're upgrading from the single-document version:

1. **Backup your database**
   ```bash
   copy database.db database_backup.db
   ```

2. **Run migration script**
   ```bash
   python migrate_database.py
   ```

3. **Verify migration**
   - Check console output for success
   - Old data migrated as "datasheet" documents
   - Old table renamed to `datasheets_old`

4. **Update Google Drive folders**
   - Migrated clients will get new folders on next upload
   - Placeholder folder IDs will be replaced

## 🐛 Troubleshooting

### OAuth Errors

**"invalid_grant: Bad Request"**
- Your refresh token is invalid or expired
- Solution: Clear `GOOGLE_REFRESH_TOKEN` in `.env` and restart app

**"invalid_client: Unauthorized"**
- OAuth credentials are incorrect or revoked
- Solution: Generate new credentials in Google Cloud Console

### Database Errors

**"no such table: clients"**
- Database not initialized
- Solution: Run `python migrate_database.py` or restart app

**"UNIQUE constraint failed"**
- Trying to upload duplicate document type for a client
- Solution: Delete existing document first or use different client name

### File Upload Errors

**"File too large"**
- File exceeds 10MB limit
- Solution: Compress or resize the file

**"Invalid file type"**
- File format not supported
- Solution: Convert to JPG, PNG, or PDF

### Google Drive Errors

**"Folder not found"**
- Root folder ID is incorrect
- Solution: Verify `GOOGLE_DRIVE_FOLDER_ID` in `.env`

**"Permission denied"**
- Drive API not enabled or insufficient permissions
- Solution: Enable Drive API in Google Cloud Console

## 💡 Tips & Best Practices

### For Agents
1. **Organize by client name** - Use consistent naming (e.g., "John Doe" not "john doe")
2. **Upload datasheet first** - It's mandatory and helps identify the client
3. **Add documents gradually** - You can upload additional docs later
4. **Use descriptive names** - Easy to search and identify
5. **Regular backups** - Export important data periodically

### For Administrators
1. **Set up backup schedule** - Backup database regularly
2. **Monitor storage** - Check Google Drive storage limits
3. **Clean old files** - Remove outdated client data
4. **Secure credentials** - Never share OAuth tokens
5. **Test migrations** - Always test on backup before production

### Performance Tips
1. **Compress large images** - Faster uploads and less storage
2. **Use PDF for documents** - Better for scanned papers
3. **Clear browser cache** - If images don't load
4. **Stable internet** - Required for Google Drive access

## 🔐 Security Best Practices

### Environment Variables
```env
# ✅ Good - Use environment variables
GOOGLE_CLIENT_ID=your_id_here

# ❌ Bad - Hard-coded in source
client_id = "123456789.apps.googleusercontent.com"
```

### File Permissions
- Keep `.env` file permissions restricted
- Never commit sensitive files to git
- Use `.gitignore` properly
- Rotate credentials periodically

### Database Security
- Regular backups to secure location
- Restrict database file access
- Use parameterized queries (already implemented)
- Monitor access logs

## 📊 Features Comparison

| Feature | Old Version | New Version |
|---------|-------------|-------------|
| Documents per client | 1 (Datasheet) | 4 (Datasheet, Aadhaar, PAN, Bank) |
| Folder structure | Single folder | Client-specific folders |
| Search | By name only | By name + view all |
| Document management | Replace only | Add/Delete individually |
| Client list view | ❌ No | ✅ Yes |
| Statistics | ❌ No | ✅ Yes |
| Responsive design | Basic | Fully responsive |
| Animations | None | Smooth transitions |

## 🎨 Customization

### Change Color Scheme
Edit `static/style.css`:
```css
/* Change primary gradient */
background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
/* To your colors */
background: linear-gradient(135deg, #your-color-1 0%, #your-color-2 100%);
```

### Add New Document Types
1. Update `DOCUMENT_TYPES` in `app.py`
2. Add form fields in `upload.html`
3. Add display sections in `fetch.html`
4. Update database if needed

### Modify File Size Limit
In `app.py`:
```python
MAX_FILE_SIZE = 10 * 1024 * 1024  # Change to your limit
```

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is for internal use. Modify as needed for your requirements.

## 📞 Support

For issues or questions:
1. Check troubleshooting section
2. Review error logs in console
3. Verify configuration in `.env`
4. Check Google Cloud Console settings

## 🎯 Roadmap

Future enhancements:
- [ ] User authentication system
- [ ] Email notifications
- [ ] OCR text extraction
- [ ] Bulk upload via CSV
- [ ] Advanced search filters
- [ ] Document expiry tracking
- [ ] Mobile app
- [ ] API for external integrations

## 📚 Resources

- [Google Drive API Documentation](https://developers.google.com/drive)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [PyDrive2 Documentation](https://docs.iterative.ai/PyDrive2/)

## ⚡ Quick Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run migration
python migrate_database.py

# Check system
python quick_fix.py

# Start application
python app.py

# Access application
http://localhost:5000
```

## 🎉 Changelog

### Version 2.0 (Multi-Document Edition)
- ✨ Added support for multiple document types
- 🗂️ Client-specific folder organization
- 👥 All clients list view
- 📊 Statistics and analytics
- 🎨 Complete UI redesign
- 📱 Fully responsive design
- 🔍 Enhanced search functionality
- 🗑️ Selective document deletion
- 📋 Document metadata tracking

### Version 1.0 (Original)
- 📤 Basic file upload
- 🔍 Simple search
- 💾 SQLite database
- ☁️ Google Drive integration

---

**Made with ❤️ for LIC Agents**

*Simplifying document management, one client at a time!*