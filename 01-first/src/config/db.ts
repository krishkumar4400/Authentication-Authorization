import mongoose from "mongoose";

const connectDB = async () => {
    try {
        mongoose.connection.on('connected', () => console.log("Database connected successfully"));
        await mongoose.connect(`${process.env.MONGO_URI}/auth_1`);

    } catch (error) {
        console.log("mongodb connection error");
        process.exit(1);
    }
}

export default connectDB;