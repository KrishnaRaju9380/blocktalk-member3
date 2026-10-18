
const express = require("express");
const http = require("http");
const path = require("path");
const { randomUUID } = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  maxHttpBufferSize: 1e6
});

const PORT = process.env.PORT || 3000;
const MAX_MESSAGE_LENGTH = 10_000;

// Store active users by socket ID.
// This is temporary in-memory storage.
const onlineUsers = new Map();

app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (req, res) => {
  res.json({
    status: "running",
    service: "BlockTalk Messaging Server"
  });
});

// Return a snapshot of currently connected users.
function getOnlineUsers() {
  return Array.from(onlineUsers.values()).map((user) => ({
    username: user.username,
    socketId: user.socketId
  }));
}

// Send the current online-user list to everyone.
function broadcastOnlineUsers() {
  io.emit("users:online", getOnlineUsers());
}

// Validate the encrypted message structure.
// The server deliberately does not decrypt messages.
function validateEncryptedMessage(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    return "Invalid message payload.";
  }

  const { sender, recipient, iv, ciphertext } = message;

  if (typeof sender !== "string" || sender.length > 30) {
    return "Invalid sender.";
  }

  if (typeof recipient !== "string" || recipient.length > 30) {
    return "Invalid recipient.";
  }

  if (typeof iv !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(iv)) {
    return "Invalid IV encoding.";
  }

  if (typeof ciphertext !== "string" ||
      ciphertext.length > MAX_MESSAGE_LENGTH * 2 + 100) {
    return "Invalid ciphertext.";
  }

  // A 96-bit IV encoded in Base64 is 16 characters.
  if (iv.length !== 16) {
    return "Invalid IV length.";
  }

  // AES-GCM ciphertext includes the authentication tag.
  if (ciphertext.length < 24) {
    return "Ciphertext is too short.";
  }

  return null;
}

io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);

  // Register a user for this browser session.
  socket.on("user:join", (payload, acknowledge) => {
    if (!payload || typeof payload.username !== "string") {
      if (typeof acknowledge === "function") {
        acknowledge({ success: false, error: "Invalid username." });
      }
      return;
    }

    const username = payload.username.trim();

    if (!/^[A-Za-z0-9_-]{1,30}$/.test(username)) {
      if (typeof acknowledge === "function") {
        acknowledge({
          success: false,
          error: "Use 1–30 letters, numbers, underscores, or hyphens."
        });
      }
      return;
    }

    // One active session per username for this demonstration.
    const existingUser = Array.from(onlineUsers.values()).find(
      (user) => user.username.toLowerCase() === username.toLowerCase()
    );

    if (existingUser && existingUser.socketId !== socket.id) {
      if (typeof acknowledge === "function") {
        acknowledge({
          success: false,
          error: "That username is already online."
        });
      }
      return;
    }

    socket.data.username = username;

    onlineUsers.set(socket.id, {
      username,
      socketId: socket.id
    });

    console.log(`${username} joined.`);

    if (typeof acknowledge === "function") {
      acknowledge({ success: true, username });
    }

    broadcastOnlineUsers();
  });

  // Receive an encrypted message and forward it to its recipient.
  socket.on("message:send", (message, acknowledge) => {
    const sender = onlineUsers.get(socket.id);

    if (!sender) {
      if (typeof acknowledge === "function") {
        acknowledge({ success: false, error: "Join the chat first." });
      }
      return;
    }

    const validationError = validateEncryptedMessage(message);

    if (validationError) {
      if (typeof acknowledge === "function") {
        acknowledge({ success: false, error: validationError });
      }
      return;
    }

    // Never trust the sender name supplied in the message payload.
    if (message.sender !== sender.username) {
      if (typeof acknowledge === "function") {
        acknowledge({ success: false, error: "Sender mismatch." });
      }
      return;
    }

    const recipient = Array.from(onlineUsers.values()).find(
      (user) =>
        user.username.toLowerCase() === message.recipient.toLowerCase()
    );

    if (!recipient) {
      if (typeof acknowledge === "function") {
        acknowledge({
          success: false,
          error: "Recipient is not online."
        });
      }
      return;
    }

    if (recipient.socketId === socket.id) {
      if (typeof acknowledge === "function") {
        acknowledge({
          success: false,
          error: "You cannot send a message to yourself."
        });
      }
      return;
    }

    const forwardedMessage = {
      messageId: randomUUID(),
      sender: sender.username,
      recipient: recipient.username,
      iv: message.iv,
      ciphertext: message.ciphertext,
      timestamp: new Date().toISOString()
    };

    // The server forwards ciphertext and IV only.
    // It never receives the plaintext or AES key.
    io.to(recipient.socketId).emit(
      "message:received",
      forwardedMessage,
      (recipientResponse) => {
        if (recipientResponse && recipientResponse.received === true) {
          socket.emit("message:status", {
            messageId: forwardedMessage.messageId,
            status: "delivered"
          });
        } else {
          socket.emit("message:status", {
            messageId: forwardedMessage.messageId,
            status: "sent"
          });
        }
      }
    );

    if (typeof acknowledge === "function") {
      acknowledge({
        success: true,
        messageId: forwardedMessage.messageId,
        status: "sent"
      });
    }
  });

  // Clean up the user's session when the connection closes.
  socket.on("disconnect", () => {
    const user = onlineUsers.get(socket.id);

    if (user) {
      onlineUsers.delete(socket.id);
      console.log(`${user.username} disconnected.`);
      broadcastOnlineUsers();
    }
  });
});

server.listen(PORT, () => {
  console.log(`BlockTalk server running at http://localhost:${PORT}`);
  console.log("Health check: http://localhost:" + PORT + "/health");
});
