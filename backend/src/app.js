
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

// Security middleware
app.use(helmet());

app.use(cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173"
}));

app.use(express.json({ limit: "10kb" }));

app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: "draft-8",
    legacyHeaders: false
}));

// Health check
app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "Welcome to BlockTalk API",
        status: "running"
    });
});

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        message: "BlockTalk backend is healthy"
    });
});

// Authentication routes
const authRoutes = require("./routes/authRoutes");
app.use("/api/auth", authRoutes);

module.exports = app;
