import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

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
                message: "Not authorized, login again"
            });
        }

        const payload = jwt.verify(
            accessToken,
            process.env.JWT_ACCESS_SECRET!
        ) as AccessTokenPayload;

        req.user = {
            userId: payload.userId,
            tokenVersion: payload.tokenVersion
        };

        next();
    } catch (error) {
        console.error("Auth middleware error:", error);
        return res.status(401).json({
            success: false,
            message: error
        });
    }
};

export default isAuth;