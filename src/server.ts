import "dotenv/config";
import connectDB from "./config/db.js";
import http from "http";
import app from "./app.js";
import env from "./config/env.js";

const port = env.PORT;

const server = http.createServer(app);

const start = async () => {
  await connectDB();
  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
};

start();
