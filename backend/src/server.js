
require("dotenv").config();

const http = require("http");
const app = require("./app");

const PORT = process.env.PORT || 5000;
const server = http.createServer(app);

server.listen(PORT, () => {
    console.log(`BlockTalk API running on http://localhost:${PORT}`);
});

server.on("error", (error) => {
    console.error("Server startup failed:", error.message);
    process.exitCode = 1;
});
