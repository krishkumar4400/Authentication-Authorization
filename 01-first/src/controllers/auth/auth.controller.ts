import { Request, Response } from "express";
import User from "../../Models/user.model.js";
import { hashPassword, verifyPassword } from "../../utils/password.js";
import { generateAccessToken, generateRefreshToken } from "../../utils/jwtToken.js";
import { sendMail } from "../../config/nodeMailer.js";
import jwt from "jsonwebtoken";

const nodeEnv = process.env.NODE_ENV;

function getAppUrl() {
    return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

export async function register(req: Request, res: Response) {
    try {
        const { name, email, password } = req.body;

        const normalizedEmail = email.toLowerCase().trim();

        let user = await User.findOne({ email: normalizedEmail });
        if (user) {
            return res.status(409).json({
                message: "User already exists",
                success: false,
            });
        }

        const hashedPassword: string = await hashPassword(password);

        user = await User.create({
            name,
            email: normalizedEmail,
            password: hashedPassword,
            role: "user",
        });

        // email verification
        const accessToken = generateAccessToken(user._id, user.tokenVersion, user.role);

        const refreshToken = generateRefreshToken(user._id, user.tokenVersion, user.role);

        const verifyUrl = `${getAppUrl()}/api/auth/verify-email?token=${accessToken}`;

        await sendMail(
            user.email,
            "Verify your email",
            `<p>Please verify your email by clicking this link:</p>\n
            <p><a href="${verifyUrl}">${verifyUrl}</a></p>
            `,
        );

        res
            .cookie("accessToken", accessToken, {
                httpOnly: true,
                secure: nodeEnv === "production",
                sameSite: nodeEnv === "production" ? "none" : "lax",
                maxAge: 15 * 60 * 1000,
            })
            .cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: nodeEnv === "production",
                sameSite: nodeEnv === "production" ? "none" : "lax",
                maxAge: 7 * 24 * 60 * 60 * 1000,
            })
            .status(200)
            .json({
                message: "User registered successfully",
                success: true,
                user: { accessToken },
            });
    } catch (error) {
        console.error("Register error\n", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
}

export async function login(req: Request, res: Response) {
    try {
        const { email, password } = req.body;

        const normalizedEmail = email.toLowerCase().trim();

        const user = await User.findOne({ email: normalizedEmail });

        if (!user) {
            return res.status(401).json({
                message: "Incorrect email or password",
                success: false,
            });
        }

        if (!user.password) {
            return res.status(500).json({
                message: "User password missing",
                success: false,
            });
        }

        const isValid = await verifyPassword(user.password, password);
        if (!isValid) {
            return res.status(401).json({
                message: "Incorrect email or password",
                success: false,
            });
        }

        const accessToken = generateAccessToken(user._id, user.tokenVersion, user.role);

        const refreshToken = generateRefreshToken(user._id, user.tokenVersion, user.role);

        res
            .cookie("accessToken", accessToken, {
                httpOnly: true,
                secure: nodeEnv === "production",
                sameSite: nodeEnv === "production" ? "none" : "lax",
                maxAge: 15 * 60 * 1000,
            })
            .cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: nodeEnv === "production",
                sameSite: nodeEnv === "production" ? "none" : "lax",
                maxAge: 7 * 24 * 60 * 60 * 1000,
            })
            .status(200)
            .json({
                message: "You are login successfully",
                success: true,
                accessToken,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role,
                    isEmailVerified: user.isEmailVerified,
                    twoFactorEnabled: user.twoFactorEnabled
                }
            });
    } catch (error) {
        console.error("Login error\n", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
}

export async function verifyEmail(req: Request, res: Response) {
    try {
        // const userId = req.userId;
        const { token } = req.query;
        if (!token || typeof token !== "string") {
            return res.status(400).json({
                message: "Verification token is missing",
                success: false,
            });
        }

        const payload = jwt.verify(
            token,
            process.env.JWT_ACCESS_SECRET!,
        ) as jwt.JwtPayload;

        const user = await User.findById(payload.userId);

        if (!user) {
            return res.status(400).json({
                message: "Incorrect user id",
                success: false,
            });
        }

        if (user.isEmailVerified) {
            return res.status(201).json({
                message: "Email is already verified",
                success: false,
            });
        }

        user.isEmailVerified = true;
        await user.save();

        return res.status(200).json({
            message: "Email is verified successfully",
            success: true,
        });
    } catch (error) {
        console.log("Error while verifying email\n", error);
    }
}

export async function refreshToken(req: Request, res: Response) {
    try {
        const refreshToken = req.cookies?.refreshToken as string | undefined;
        if (!refreshToken) {
            return res.status(401).json({
                message: "Refresh token is missing",
                success: false
            });
        }

        const payload = verifyRefreshToken(refreshToken);

        const user = await User.findById(payload.userId);
        if (!user) {
            return res.status(401).json({
                message: "Incorrect user id",
                success: false
            });
        }

        if (user.tokenVersion !== payload.tokenVersion) {
            return res.status(401).json({
                message: "token is expired",
                success: false
            });
        }

        const newAccessToken = generateAccessToken(user._id, user.tokenVersion, user.role);

        const newRefreshToken = generateRefreshToken(user._id, user.tokenVersion, user.role);

        res
            .cookie("refreshToken", newRefreshToken, {
                httpOnly: true,
                secure: nodeEnv === "production",
                sameSite: nodeEnv === "production" ? "none" : "lax",
                maxAge: 7 * 24 * 60 * 60 * 1000,
            })
            .status(200)
            .json({
                message: "token refreshed",
                success: true,
                accessToken: newAccessToken,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role,
                    isEmailVerified: user.isEmailVerified,
                    twoFactorEnabled: user.twoFactorEnabled
                }
            });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            message: "Internal server error",
            success: false
        });
    }
}

//  controller function to verify refresh token if it is valid
export function verifyRefreshToken(token: string) {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
        userId: string, tokenVersion: number, role: string
    }
}

