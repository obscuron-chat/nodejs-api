# Obscuron Web-Based Encrypted Chat App

## 📦 Installation
1. Clone repository:
```bash
git clone https://github.com/obscuron/nodejs-core.git
cd nodejs-core
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