import jwt from "jsonwebtoken";
import mongoose from "mongoose";

interface JwtPayload {
    userId: string;
}

const accessSecret = process.env.JWT_ACCESS_SECRET;
const refreshSecret = process.env.JWT_REFRESH_SECRET;

if (!accessSecret || !refreshSecret) {
    throw new Error("JWT secrets are not configured");
}

/**
 * Generate Access Token (short-lived)
 */
export const generateAccessToken = (
    userId: mongoose.Types.ObjectId
): string => {
    const payload: JwtPayload = {
        userId: userId.toString()
    };

    return jwt.sign(payload, accessSecret, {
        expiresIn: "15m"
    });
};

/**
 * Generate Refresh Token (long-lived)
 */
export const generateRefreshToken = (
    userId: mongoose.Types.ObjectId
): string => {
    const payload: JwtPayload = {
        userId: userId.toString()
    };

    return jwt.sign(payload, refreshSecret, {
        expiresIn: "7d"
    });
};
