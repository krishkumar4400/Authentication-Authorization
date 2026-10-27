import mongoose from "mongoose";
import env from "./env.js";

const MONGO_URI = env.MONGO_URI;

if (!MONGO_URI) {
  throw new Error("mongo db connection uri is missing");
}

const connectDB = async (): Promise<void> => {
  try {
    mongoose.connection.on("connected", () =>
      console.log("Database connected successfully"),
    );
    await mongoose.connect(MONGO_URI);
  } catch (error) {
    console.log("mongodb connection error");
    process.exit(1);
  }
};

export default connectDB;
