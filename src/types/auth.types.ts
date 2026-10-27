import jwt from "jsonwebtoken";

export interface RegisterBody {
  name: string;
  email: string;
  password: string;
}

export interface LoginBody {
  email: string;
  password: string;
  twoFactorCode: string;
}

export interface JWTPayload {
  userId: string;
}

export interface AccessTokenPayload extends jwt.JwtPayload {
  userId: string;
  tokenVersion: number;
}
