import { Request, Response } from "express";
import User from "../../Models/user.model.js";
import { hashPassword, verifyPassword } from "../../utils/password.js";
import { generateAccessToken } from "../../utils/jwtToken.js";
import { sendMail } from "../../config/nodeMailer.js";


const nodeEnv = process.env.NODE_ENV

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
                success: false
            });
        }

        const hashedPassword: string = await hashPassword(password);

        user = await User.create({
            name, email: normalizedEmail, password: hashedPassword, role: "user"
        });

        // email verification
        const accessToken = generateAccessToken(user._id);

        const refreshToken = generateAccessToken(user._id);

        const verifyUrl = `${getAppUrl}/auth/verify-email?token=${accessToken}`;

        await sendMail(user.email, "Verify your email", `<p>Please verify your email by clicking this link:</p>\n
            <p><a href="${verifyUrl}">${verifyUrl}</a></p>
            `)

        res
            .cookie("accessToken", accessToken, {
                httpOnly: true,
                secure: nodeEnv === "production",
                sameSite: nodeEnv === "production" ? 'none' : 'lax',
                maxAge: 15 * 60 * 1000
            })
            .cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: nodeEnv === "production",
                sameSite: nodeEnv === "production" ? 'none' : 'lax',
                maxAge: 7 * 24 * 60 * 60 * 1000
            })
            .status(200)
            .json({
                message: "User registered successfully",
                success: true
            });



    } catch (error) {
        console.error("Register error\n", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error"
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
                success: false
            });
        }

        if (!user.password) {
            return res.status(500).json({
                message: "User password missing",
                success: false
            });
        }

        const isValid = await verifyPassword(user.password, password);
        if (!isValid) {
            return res.status(401).json({
                message: "Incorrect email or password",
                success: false
            });
        }

        const accessToken = generateAccessToken(user._id);

        const refreshToken = generateAccessToken(user._id);

        res
            .cookie("accessToken", accessToken, {
                httpOnly: true,
                secure: nodeEnv === "production",
                sameSite: nodeEnv === "production" ? 'none' : 'lax',
                maxAge: 15 * 60 * 1000
            })
            .cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: nodeEnv === "production",
                sameSite: nodeEnv === "production" ? 'none' : 'lax',
                maxAge: 7 * 24 * 60 * 60 * 1000
            })
            .status(200)
            .json({
                message: "You are login successfully",
                success: true
            });

    } catch (error) {
        console.error("Login error\n", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
}


export async function verifyEmail (req:Request, res:Response) {
    try {
        // const userId = req.userId;

        

    } catch (error) {
        console.log("Error while verifying email\n", error);
    }
}