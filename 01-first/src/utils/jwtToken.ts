import jwt from "jsonwebtoken";
import mongoose from "mongoose";

interface JwtPayload {
  userId: string;
  tokenVersion: number;
  role: string;
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

/**
 const getJwtSecrets = () => {
  const accessSecret = process.env.JWT_ACCESS_SECRET;
  const refreshSecret = process.env.JWT_REFRESH_SECRET;

  if (!accessSecret || !refreshSecret) {
    throw new Error("JWT secrets are not configured");
  }

  return { accessSecret, refreshSecret };
};

export const generateAccessToken = (
  userId: mongoose.Types.ObjectId,
  tokenVersion: number,
  role: string
): string => {
  const { accessSecret } = getJwtSecrets();

  return jwt.sign(
    { userId: userId.toString(), tokenVersion, role },
    accessSecret,
    { expiresIn: "15m" }
  );
};
 */

export const verifyToken = (token: string) => {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
    userId: string;
    tokenVersion: number;
    role: 'user' | 'admin';
  }
};
