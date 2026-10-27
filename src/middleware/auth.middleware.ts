import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { verifyToken } from "../utils/jwtToken.js";
import User from "../Models/user.model.js";

interface AccessTokenPayload extends jwt.JwtPayload {
  userId: string;
  tokenVersion: number;
}

const isAuth = (req: Request, res: Response, next: NextFunction) => {
  try {
    const accessToken = req.cookies?.accessToken as string | undefined;

    if (!accessToken || typeof accessToken !== "string") {
      return res.status(401).json({
        success: false,
        message: "Not authorized, login again",
      });
    }

    const payload = jwt.verify(
      accessToken,
      process.env.JWT_ACCESS_SECRET!,
    ) as AccessTokenPayload;

    req.user = {
      userId: payload.userId,
      tokenVersion: payload.tokenVersion,
      role: payload.role,
    };

    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    return res.status(401).json({
      success: false,
      message: error,
    });
  }
};

export default isAuth;

export const requireAuth = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Unauthorized login again",
        success: false,
      });
    }

    const token = authHeader.split(" ")[1];
    const payload = verifyToken(token);

    // req.user = {
    //   userId: payload.userId,
    //   tokenVersion: payload.tokenVersion,
    //   role: payload.role,
    // };

    const user = await User.findById(payload.userId);

    if (!user) {
      return res.status(401).json({
        message: "Incorrect user id",
        success: false,
      });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(400).json({
        message: "Token invalidated",
        success: false,
      });
    }

    const authReq = req as any;

    authReq.user = {
      id: user.id,
      role: user.role,
      tokenVersion: user.tokenVersion,
      name: user.name,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
    };

    next();
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
      success: false,
    });
  }
};
