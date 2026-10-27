import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import env from "../config/env.js";

interface JwtPayload {
  userId: string;
  tokenVersion: number;
  role: string;
}

const accessSecret = env.JWT_ACCESS_SECRET;
const refreshSecret = env.JWT_REFRESH_SECRET;

if (!accessSecret || !refreshSecret) {
  throw new Error("JWT secrets are not configured");
}

/**
 * Generate Access Token (short-lived)
 */
export const generateAccessToken = (
  userId: mongoose.Types.ObjectId,
  tokenVersion: number,
  role: string,
): string => {
  const payload: JwtPayload = {
    userId: userId.toString(),
    tokenVersion,
    role,
  };

  return jwt.sign(payload, accessSecret, {
    expiresIn: "15m",
  });
};

/**
 * Generate Refresh Token (long-lived)
 */
export const generateRefreshToken = (
  userId: mongoose.Types.ObjectId,
  tokenVersion: number,
  role: string,
): string => {
  const payload: JwtPayload = {
    userId: userId.toString(),
    tokenVersion,
    role,
  };

  return jwt.sign(payload, refreshSecret, {
    expiresIn: "7d",
  });
};

export const verifyToken = (token: string): JwtPayload | null => {
  try {
    const decoded = jwt.verify(token, accessSecret);

    if (typeof decoded === "string") {
      return null;
    }

    if (
      typeof decoded.userId !== "string" ||
      typeof decoded.tokenVersion !== "number" ||
      typeof decoded.role !== "string"
    ) {
      return null;
    }

    return {
      userId: decoded.userId,
      tokenVersion: decoded.tokenVersion,
      role: decoded.role,
    };
  } catch (error) {
    console.log(error);
    return null;
  }
};
