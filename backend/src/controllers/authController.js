
const bcrypt = require("bcryptjs");
const pool = require("../config/db");

const register = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validate required fields
        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Username, email and password are required"
            });
        }

        const cleanUsername = username.trim();
        const cleanEmail = email.trim().toLowerCase();

        if (cleanUsername.length < 3 || cleanUsername.length > 50) {
            return res.status(400).json({
                success: false,
                message: "Username must be between 3 and 50 characters"
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
            return res.status(400).json({
                success: false,
                message: "Please enter a valid email address"
            });
        }

        if (typeof password !== "string" ||
            password.length < 8 ||
            Buffer.byteLength(password, "utf8") > 72) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 8 characters and at most 72 bytes"
            });
        }

        // Check if the username or email is already registered
        const [existingUsers] = await pool.execute(
            "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1",
            [cleanUsername, cleanEmail]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: "Username or email is already registered"
            });
        }

        // Hash the password before saving
        const passwordHash = await bcrypt.hash(password, 12);

        const [result] = await pool.execute(
            `INSERT INTO users (username, email, password_hash)
             VALUES (?, ?, ?)`,
            [cleanUsername, cleanEmail, passwordHash]
        );

        return res.status(201).json({
            success: true,
            message: "Account created successfully",
            user: {
                id: result.insertId,
                username: cleanUsername,
                email: cleanEmail
            }
        });
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                success: false,
                message: "Username or email is already registered"
            });
        }

        console.error("Registration error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Unable to create account"
        });
    }
};

module.exports = { register };
