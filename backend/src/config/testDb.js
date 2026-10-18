
require("dotenv").config();

const pool = require("./db");

async function testConnection() {
    try {
        const [rows] = await pool.query(
            "SELECT DATABASE() AS databaseName, NOW() AS serverTime"
        );

        console.log("MySQL connected successfully!");
        console.log(rows[0]);
    } catch (error) {
        console.error("MySQL connection failed:", error.message);
    } finally {
        await pool.end();
    }
}

testConnection();
