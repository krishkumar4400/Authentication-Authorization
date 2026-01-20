import http from "http";
import app from "./app.js";
import connectDB from "./config/db.js";
import "dotenv/config";

const port = process.env.PORT || 4000;

const server = http.createServer(app);

const start = async () => {
    await connectDB();
    server.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
    });
};

start();