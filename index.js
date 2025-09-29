require('dotenv').config();

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const url = require('url');

const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({
    origin: [
        'http://localhost:80',
        'http://localhost:8080',
        'http://localhost:4173',
        'http://localhost:5173',
        'http://localhost:5174',
        'https://obscuron.chat',
        'https://api.obscuron.chat'
    ]
}));

const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

// MongoDB
const mongoose = require("mongoose");
const clientOptions = {
  serverApi: { version: "1", strict: true, deprecationErrors: true },
};
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, clientOptions);
    await mongoose.connection.db.admin().command({ ping: 1 });
    console.log("MongoDB connected successfully");
  } catch (err) {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  }
}
connectDB();
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    profileName: { type: String, required: true, default: function() {
                return this.username;
            } },
    imageURL: { type: String, required: true, default: "https://cdn.obscuron.chat/placeholder.png" },
    publicKey: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

// Cloudflare R2
const { R2 } =  require('node-cloudflare-r2');
const path = require("path");
const r2 = new R2({
    accountId: process.env.R2_ACCOUNT_ID,
    accessKeyId: process.env.R2_ACCESS_KEY,
    secretAccessKey: process.env.R2_SECRET_KEY,
});
const bucket = r2.bucket(process.env.R2_BUCKET);
bucket.provideBucketPublicUrl(process.env.R2_PUBLIC_URL);
const uploadPDF = async (file, directory) => {
    const upload = await bucket.uploadFile(file, directory, undefined, 'application/pdf');
    return upload.publicUrls[0];
};


// Websocket
server.on('upgrade', (req, socket, head) => {
    const pathname = url.parse(req.url).pathname;
    const match = pathname.match(/^\/room\/([a-zA-Z0-9_-]+)$/);

    if (!match) {
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
        socket.destroy();
        return;
    }

    const roomId = match[1];

    wss.handleUpgrade(req, socket, head, (ws) => {
        ws.roomId = roomId;
        wss.emit('connection', ws, req);
    });
});

const rooms = {};

wss.on('connection', (ws) => {
    const roomId = ws.roomId;

    rooms[roomId] = rooms[roomId] || new Set();
    rooms[roomId].add(ws);

    console.log(`Client connected to room: ${roomId}`);

    ws.send(`Joined room: ${roomId}`);

    ws.on('message', (message) => {
        console.log(`Message in ${roomId}: ${message}`);

        rooms[roomId].forEach(client => {
        if (client !== ws && client.readyState === WebSocket.OPEN) {
            client.send(`{"room":"${roomId}","message":${message}}`);
        }
        });
    });

    ws.on('close', () => {
        rooms[roomId].delete(ws);
        if (rooms[roomId].size === 0) {
        delete rooms[roomId];
        }
        console.log(`Client disconnected from room: ${roomId}`);
    });
});

// app.get('/', (req, res) => {
//     res.send(`WebSocket server is running. Connect to ${process.env.HOST}:${process.env.PORT}/room/:id`);
// });

const root = __dirname;
app.get('/', (req, res) => 
    res.sendFile(path.join(root, 'index.html'))
);

const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
const signToken = (user, expire=process.env.JWT_DEFAULT_EXPIRE) => {
    return jwt.sign(
        user,
        process.env.JWT_SECRET,
        { 
            expiresIn: expire 
        }
    );
}
const verify = (token) => {
    let verification;
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            verification = {
                status: "error",
                message: process.env.DEBUG ? err.message : "Invalid Token",
                data: {}
            }
        } else {
            verification = {
                status: "success",
                message: "Token Verified",
                data: decoded
            }
        }
    });
    return verification;
};
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            status: "error", 
            message: "Unauthorized: Authentication required",
            data: {}
        });
    }

    const verification = verify(token);
    if (verification.status == "error") {
        return res.status(401).json({
            status: "error", 
            message: process.env.DEBUG ? verification.message : "Invalid Authentication",
            data: {}
        });
    }

    req.user = verification.data;
    next();
};
app.post('/auth', async (req, res) => {
    try {
        const { username, password, publicKey } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({
                status: 'error',
                message: 'Parameter "username" and "password" required',
                data: {}
            });
        }

        const getUser = await User.findOne({ username: username });
    
        if (getUser) {
            if (bcrypt.compareSync(password, getUser.password)) {
                return res.status(200).json({
                    status: 'success',
                    message: "Account login successful",
                    data: {
                        username: username,
                        token: signToken({
                            username: username
                        }),
                        profileName: getUser.profileName
                    }
                });
            } else {
                return res.status(400).json({
                    status: 'error',
                    message: "Account login unsuccessful",
                    data: {}
                });
            }
        } else {
            const newUser = new User({
                username: username,
                password: await bcrypt.hash(password, 10),
                publicKey: publicKey
            });
            await newUser.save();
            
            return res.status(200).json({
                status: 'success',
                message: "Account registration successful",
                data: {
                    username: username,
                    token: signToken({
                        username: username
                    }),
                    profileName: username
                }
            });
        }
    } catch(err) {
        console.error(err);
        return res.status(400).json({
            status: 'error',
            message: process.env.DEBUG ? err.message : "Bad Request",
            data: {}
        });
    }
});

app.post('/profile', verifyToken, async (req, res) => {
    try {
        const { profileName, imageURL } = req.body;

        if (!profileName) {
            return res.status(400).json({
                status: 'error',
                message: 'Parameter "profileName" required',
                data: {}
            });
        }

        const getUser = await User.findOne({ username: req.user.username });
    
        if (!getUser) {
            return res.status(400).json({
                status: 'error',
                message: process.env.DEBUG ? "Email not Found" : "Invalid Credentials",
                data: {}
            });
        }

        getUser.profileName = profileName;
        if (imageURL) {
            getUser.imageURL = imageURL;
        }

        const newUser = await getUser.save();

        return res.status(200).json({
            status: 'success',
            message: "Profile successful",
            data: newUser
        });
    } catch(err) {
        console.error(err);
        return res.status(400).json({
            status: 'error',
            message: process.env.DEBUG ? err.message : "Bad Request",
            data: {}
        });
    }
});

app.get('/users', async (req, res) => {
    try {
        const users = await User.find({}, { __v: 0, _id: 0, password: 0 });
        return res.status(200).json({
            status: 'success',
            message: "GET all users successful",
            data: {
                users: users ? users : []
            }
        });
    } catch(err) {
        console.error(err);
        return res.status(400).json({
            status: 'error',
            message: process.env.DEBUG ? err.message : "Bad Request",
            data: {}
        });
    }
});

server.listen(process.env.PORT, () => {
    console.log(`Server listening on port ${process.env.PORT}`);
});