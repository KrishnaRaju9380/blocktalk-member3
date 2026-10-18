
"use strict";

// ================================================
// BlockTalk - Member 3
// Real-Time Messaging and AES-GCM Encryption
// ================================================

const socket = io();

// Demo-only AES-256 key.
// Alice and Bob use the same key locally.
// NEVER use a hardcoded key in a production application.
const DEMO_AES_KEY_HEX =
  "000102030405060708090a0b0c0d0e0f" +
  "101112131415161718191a1b1c1d1e1f";

const MAX_MESSAGE_BYTES = 10000;
const ACK_TIMEOUT_MS = 10000;

// HTML elements
const joinPanel = document.getElementById("joinPanel");
const chatPanel = document.getElementById("chatPanel");
const joinForm = document.getElementById("joinForm");
const usernameInput = document.getElementById("username");
const joinButton = document.getElementById("joinButton");

const connectionDot = document.getElementById("connectionDot");
const connectionStatus = document.getElementById("connectionStatus");

const onlineUsersList = document.getElementById("onlineUsers");
const currentUserLabel = document.getElementById("currentUserLabel");
const chatTitle = document.getElementById("chatTitle");

const messageList = document.getElementById("messageList");
const emptyChat = document.getElementById("emptyChat");
const errorMessage = document.getElementById("errorMessage");

const recipientSelect = document.getElementById("recipient");
const messageForm = document.getElementById("messageForm");
const messageInput = document.getElementById("messageInput");
const sendButton = document.getElementById("sendButton");
const leaveButton = document.getElementById("leaveButton");

// Application state
let currentUsername = "";
let aesKey = null;
let isJoined = false;
let isSending = false;

const messageElements = new Map();
const pendingStatuses = new Map();

// ================================================
// General helpers
// ================================================

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.classList.remove("hidden");
}

function clearError() {
  errorMessage.textContent = "";
  errorMessage.classList.add("hidden");
}

function setConnectionStatus(connected, text) {
  connectionStatus.textContent = text;
  connectionDot.classList.toggle("online", connected);
  connectionDot.classList.toggle("offline", !connected);
}

function updateSendButton() {
  sendButton.disabled =
    !isJoined ||
    !socket.connected ||
    !aesKey ||
    isSending ||
    !recipientSelect.value ||
    !messageInput.value.trim();
}

function bytesToBase64(bytes) {
  let binary = "";

  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

function base64ToBytes(value) {
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(value) ||
      value.length % 4 !== 0) {
    throw new Error("Invalid Base64 data.");
  }

  const binary = atob(value);

  return Uint8Array.from(binary, (character) =>
    character.charCodeAt(0)
  );
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
    throw new Error("Invalid hexadecimal key.");
  }

  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }

  return bytes;
}

// ================================================
// AES-256-GCM key initialization
// ================================================

async function initializeEncryption() {
  if (!window.crypto ||
      !window.crypto.subtle ||
      !window.crypto.getRandomValues) {
    throw new Error(
      "Web Crypto is unavailable. Open BlockTalk through localhost."
    );
  }

  const rawKey = hexToBytes(DEMO_AES_KEY_HEX);

  aesKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    {
      name: "AES-GCM"
    },
    false,
    ["encrypt", "decrypt"]
  );

  // Best-effort cleanup of the temporary byte array.
  rawKey.fill(0);
}

// ================================================
// Encrypt a message in the browser
// ================================================

async function encryptMessage(plaintext) {
  if (!aesKey) {
    throw new Error("Encryption key is not initialized.");
  }

  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);

  if (plaintextBytes.length === 0 ||
      plaintextBytes.length > MAX_MESSAGE_BYTES) {
    throw new Error(
      "Message must contain between 1 and 10000 UTF-8 bytes."
    );
  }

  // AES-GCM uses a unique, random 96-bit IV for each message.
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128
    },
    aesKey,
    plaintextBytes
  );

  return {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer))
  };
}

// ================================================
// Decrypt a message in the browser
// ================================================

async function decryptMessage(ciphertext, encodedIV) {
  if (!aesKey) {
    throw new Error("Encryption key is not initialized.");
  }

  const iv = base64ToBytes(encodedIV);
  const encryptedBytes = base64ToBytes(ciphertext);

  if (iv.length !== 12) {
    throw new Error("The message IV must be 12 bytes.");
  }

  // Web Crypto verifies the AES-GCM authentication tag.
  // Modified or invalid ciphertext will cause decryption to fail.
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128
    },
    aesKey,
    encryptedBytes
  );

  return new TextDecoder("utf-8", {
    fatal: true
  }).decode(decryptedBuffer);
}

// ================================================
// Chat message display
// ================================================

function appendMessage({
  messageId,
  sender,
  text,
  timestamp,
  type,
  status = ""
}) {
  emptyChat.classList.add("hidden");

  const message = document.createElement("article");
  message.className = `message ${type}`;

  const metadata = document.createElement("div");
  metadata.className = "message-meta";

  const senderElement = document.createElement("span");
  senderElement.textContent = sender;

  const timeElement = document.createElement("span");

  const parsedDate = new Date(timestamp);
  timeElement.textContent = Number.isNaN(parsedDate.getTime())
    ? "Time unavailable"
    : parsedDate.toLocaleTimeString();

  metadata.append(senderElement, timeElement);

  const bubble = document.createElement("div");
  bubble.className = "message-bubble";

  // textContent prevents messages from being interpreted as HTML.
  bubble.textContent = text;

  message.append(metadata, bubble);

  let statusElement = null;

  if (type === "sent") {
    statusElement = document.createElement("div");
    statusElement.className = "message-status";
    statusElement.textContent = status || "Sending...";
    message.append(statusElement);
  }

  messageList.appendChild(message);
  messageList.scrollTop = messageList.scrollHeight;

  if (messageId) {
    messageElements.set(messageId, {
      message,
      statusElement
    });
  }

  return { message, statusElement };
}

function updateMessageStatus(messageId, status) {
  const entry = messageElements.get(messageId);

  if (!entry || !entry.statusElement) {
    pendingStatuses.set(messageId, status);
    return;
  }

  const labels = {
    sending: "Sending...",
    sent: "Sent to server",
    delivered: "Delivered",
    failed: "Failed"
  };

  entry.statusElement.textContent = labels[status] || status;
  entry.statusElement.classList.toggle(
    "failed",
    status === "failed"
  );
}

// ================================================
// Online users
// ================================================

function renderOnlineUsers(users) {
  onlineUsersList.replaceChildren();

  const availableRecipients = users.filter(
    (user) => user.username !== currentUsername
  );

  if (users.length === 0) {
    const emptyItem = document.createElement("li");
    emptyItem.className = "empty-users";
    emptyItem.textContent = "No users online";
    onlineUsersList.appendChild(emptyItem);
  } else {
    users.forEach((user) => {
      const item = document.createElement("li");
      item.className = "online-user";

      const avatar = document.createElement("span");
      avatar.className = "user-avatar";
      avatar.textContent = user.username.charAt(0).toUpperCase();

      const details = document.createElement("span");
      details.className = "user-details";

      const name = document.createElement("span");
      name.className = "user-name";
      name.textContent =
        user.username +
        (user.username === currentUsername ? " (You)" : "");

      const presence = document.createElement("span");
      presence.className = "user-presence";

      const dot = document.createElement("span");
      dot.className = "user-presence-dot";

      const presenceText = document.createElement("span");
      presenceText.textContent = "Online";

      presence.append(dot, presenceText);
      details.append(name, presence);
      item.append(avatar, details);
      onlineUsersList.appendChild(item);
    });
  }

  const previousRecipient = recipientSelect.value;
  recipientSelect.replaceChildren();

  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Select recipient";
  recipientSelect.appendChild(placeholder);

  availableRecipients.forEach((user) => {
    const option = document.createElement("option");
    option.value = user.username;
    option.textContent = user.username;
    recipientSelect.appendChild(option);
  });

  if (availableRecipients.some(
    (user) => user.username === previousRecipient
  )) {
    recipientSelect.value = previousRecipient;
  } else if (availableRecipients.length === 1) {
    recipientSelect.value = availableRecipients[0].username;
  }

  recipientSelect.disabled =
    !isJoined || availableRecipients.length === 0;

  if (availableRecipients.length === 0) {
    chatTitle.textContent = "Waiting for another user";
  } else {
    chatTitle.textContent = "Messages";
  }

  updateSendButton();
}

// ================================================
// Socket.IO connection events
// ================================================

socket.on("connect", () => {
  setConnectionStatus(true, "Connected to server");
  joinButton.disabled = false;
  clearError();
});

socket.on("disconnect", () => {
  setConnectionStatus(false, "Disconnected");
  isJoined = false;
  aesKey = null;

  joinPanel.classList.remove("hidden");
  chatPanel.classList.add("hidden");

  joinButton.disabled = false;
  recipientSelect.disabled = true;
  messageInput.disabled = true;
  sendButton.disabled = true;

  currentUsername = "";
  currentUserLabel.textContent = "Not connected";
  clearError();

  showError(
    "Connection lost. Rejoin the chat after reconnecting."
  );
});

socket.on("connect_error", () => {
  setConnectionStatus(false, "Connection failed");
  showError("Unable to connect to BlockTalk. Check the server.");
});

socket.on("users:online", (users) => {
  if (Array.isArray(users)) {
    renderOnlineUsers(users);
  }
});

socket.on("message:status", (data) => {
  if (!data || typeof data.messageId !== "string") {
    return;
  }

  updateMessageStatus(data.messageId, data.status);
});

socket.on("chat:error", (data) => {
  showError(
    data && typeof data.error === "string"
      ? data.error
      : "A chat error occurred."
  );
});

// ================================================
// Join chat
// ================================================

joinForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();

  if (!socket.connected) {
    showError("Wait until the server connection is available.");
    return;
  }

  const username = usernameInput.value.trim();

  if (!/^[A-Za-z0-9_-]{1,30}$/.test(username)) {
    showError(
      "Use 1–30 letters, numbers, underscores, or hyphens."
    );
    return;
  }

  joinButton.disabled = true;

  try {
    // Initialize the AES key before joining.
    await initializeEncryption();

    socket.timeout(ACK_TIMEOUT_MS).emit(
      "user:join",
      { username },
      (error, response) => {
        joinButton.disabled = false;

        if (error) {
          showError("The server did not respond. Try again.");
          return;
        }

        if (!response || !response.success) {
          showError(response?.error || "Unable to join the chat.");
          return;
        }

        currentUsername = response.username;
        isJoined = true;

        currentUserLabel.textContent =
          `Logged in as ${currentUsername}`;

        joinPanel.classList.add("hidden");
        chatPanel.classList.remove("hidden");

        messageInput.disabled = false;
        recipientSelect.disabled = false;

        renderOnlineUsers([]);

        messageInput.focus();
        updateSendButton();
      }
    );
  } catch (error) {
    joinButton.disabled = false;
    aesKey = null;

    console.error("Encryption initialization failed:", error);
    showError(
      "Encryption could not be initialized. Open the app through localhost."
    );
  }
});

// ================================================
// Send an encrypted message
// ================================================

messageForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();

  if (!isJoined || !socket.connected || !aesKey || isSending) {
    showError("Join the chat and wait for the connection.");
    return;
  }

  const plaintext = messageInput.value.trim();
  const recipient = recipientSelect.value;

  if (!recipient) {
    showError("Select an online recipient.");
    return;
  }

  if (!plaintext) {
    return;
  }

  if (new TextEncoder().encode(plaintext).length > MAX_MESSAGE_BYTES) {
    showError("Your message is too large.");
    return;
  }

  isSending = true;
  updateSendButton();

  try {
    // Encrypt before the payload reaches the server.
    const encrypted = await encryptMessage(plaintext);

    const payload = {
      sender: currentUsername,
      recipient,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext
    };

    // Do not include plaintext in the outgoing payload.
    socket.timeout(ACK_TIMEOUT_MS).emit(
      "message:send",
      payload,
      (error, response) => {
        isSending = false;
        updateSendButton();

        if (error) {
          showError("The server did not acknowledge your message.");
          return;
        }

        if (!response || !response.success) {
          showError(response?.error || "Message could not be sent.");
          return;
        }

        messageInput.value = "";

        const messageId = response.messageId;
        const status = pendingStatuses.get(messageId) || "sent";

        pendingStatuses.delete(messageId);

        appendMessage({
          messageId,
          sender: `You → ${recipient}`,
          text: plaintext,
          timestamp: new Date().toISOString(),
          type: "sent",
          status
        });

        updateSendButton();
        messageInput.focus();
      }
    );
  } catch (error) {
    isSending = false;
    updateSendButton();

    console.error("Message encryption failed:", error);
    showError("The message could not be encrypted.");
  }
});

messageInput.addEventListener("input", updateSendButton);
recipientSelect.addEventListener("change", updateSendButton);

// ================================================
// Receive and decrypt a message
// ================================================

socket.on("message:received", async (message, acknowledge) => {
  let received = false;

  try {
    if (!isJoined || !aesKey) {
      throw new Error("Join the chat before receiving messages.");
    }

    if (!message ||
        typeof message.messageId !== "string" ||
        typeof message.sender !== "string" ||
        message.recipient !== currentUsername ||
        typeof message.iv !== "string" ||
        typeof message.ciphertext !== "string") {
      throw new Error("Invalid incoming message.");
    }

    const plaintext = await decryptMessage(
      message.ciphertext,
      message.iv
    );

    appendMessage({
      messageId: null,
      sender: message.sender,
      text: plaintext,
      timestamp: message.timestamp,
      type: "received"
    });

    received = true;
  } catch (error) {
    console.error("Message decryption failed:", error);

    appendMessage({
      messageId: null,
      sender: message?.sender || "Unknown sender",
      text: "Unable to decrypt this message.",
      timestamp: message?.timestamp || new Date().toISOString(),
      type: "received"
    });

    showError(
      "A message could not be decrypted. Check the shared demo key."
    );
  } finally {
    // Acknowledge receipt only after successful decryption.
    // The server uses this acknowledgement for delivery status.
    if (typeof acknowledge === "function") {
      acknowledge({ received });
    }
  }
});

// ================================================
// Leave chat
// ================================================

leaveButton.addEventListener("click", () => {
  // Reloading closes this session and lets the server clean it up.
  window.location.reload();
});

// Initial UI state
setConnectionStatus(false, "Connecting...");
updateSendButton();
