<div align="center">
  <table border="1">
    <tr>
      <td align="center" style="padding: 20px;">
        <h3>📢 Domain & Email Migration Notice</h3>
        <p>From <b>May 14 th, 2026</b>, Obscuron will transition to new domains as <code>obscuron.chat</code> will not be renewed:</p>
        <p>🌐 <b>Website:</b> <a href="https://obscuron.faizath.com">obscuron.faizath.com</a> (formerly <i>obscuron.chat</i>)<br>
        ⚙️ <b>API:</b> <a href="https://obscuron-api.faizath.com">obscuron-api.faizath.com</a> (formerly <i>api.obscuron.chat</i>)<br>
        📧 <b>Email:</b> <a href="mailto:contact@obscuron.faizath.com">contact@obscuron.faizath.com</a> (formerly <i>contact@obscuron.chat</i>)<br>
        🛰️ <b>CDN:</b> <a>obscuron-cdn.faizath.com</a> (formerly <i>cdn.obscuron.chat</i>)<br>
        📈 <b>Status Pages:</b> <a href="https://status.faizath.com/status/obscuron">https://status.faizath.com/status/obscuron</a> (formerly <i>status.obscuron.chat</i>)
        </p>
      </td>
    </tr>
  </table>
</div>

# Obscuron Web-Based Encrypted Chat App

## 📦 Installation
1. Clone repository:
```bash
git clone https://github.com/obscuron/nodejs-api.git
cd nodejs-api
```

2. Create `.env` file with required variables:
```bash
MONGODB_URI=mongodb://...
JWT_SECRET=your-secret-key
PORT=3000
DEBUG=true
```

3. Install dependencies:
```bash
npm install
```

4. Build Docker image:
```bash
docker-compose up --build
```

## ⚙️ Usage
Start the application:
```bash
docker-compose up
```

Access endpoints:
- **WebSocket**: Connect to `ws://localhost:3000/room/:id` for chat
- **HTTP API**:
  - `POST /auth` - Authentication/Registration
  - `POST /profile` - Update profile
  - `GET /users` - List all users

## 🗂️ Project Structure
```
├── index.js          # Main server file
├── package.json      # Project metadata
├── Dockerfile        # Docker configuration
├── compose.yml       # Docker Compose setup
└── .env              # Environment variables
```

## 🔐 API Endpoints
### Authentication
```bash
curl -X POST http://localhost:3000/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'
```

### Profile Update
```bash
curl -X POST http://localhost:3000/profile \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"profileName":"New Name"}'
```

## 📌 Notes
- Uses MongoDB for user storage
- Cloudflare R2 for file storage
- JWT for token-based authentication
- WebSocket for real-time chat