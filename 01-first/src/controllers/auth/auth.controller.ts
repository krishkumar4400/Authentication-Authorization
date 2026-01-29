import { raw, Request, Response } from "express";
import User from "../../Models/user.model.js";
import { hashPassword, verifyPassword } from "../../utils/password.js";
import {
  generateAccessToken,
  generateRefreshToken,
} from "../../utils/jwtToken.js";
import { sendMail } from "../../config/nodeMailer.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { GoogleAuth, OAuth2Client } from "google-auth-library";
import { OTP, verify } from 'otplib';

const nodeEnv = process.env.NODE_ENV;

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

async function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !clientSecret) {
    throw new Error("Google client id or secret is missing");
  }

  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri,
  });
}

// user register controller function
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
    const accessToken = generateAccessToken(
      user._id,
      user.tokenVersion,
      user.role,
    );

    const refreshToken = generateRefreshToken(
      user._id,
      user.tokenVersion,
      user.role,
    );

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

// user login controller function
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

    // 2FA authentication
    const { twoFactorCode } = req.body;
    if (user.twoFactorEnabled) {
      if (!twoFactorCode || typeof twoFactorCode !== "string") {
        return res.status(400).json({
          message: "Two factor code is required",
          success: false,
        });
      }

      if (!user.twoFactorSecret) {
        return res.status(400).json({
          message: "Two factor misconfigured for this account",
          success: false,
        });
      }

      // verify the code using otplib
      const otp = new OTP();

      const isValid = otp.verify({
        token: twoFactorCode,
        secret: user.twoFactorSecret
      });

      if (!isValid) {
        return res.status(400).json({
          message: "Invalid two factor code",
          success: false
        });
      }

    }

    const accessToken = generateAccessToken(
      user._id,
      user.tokenVersion,
      user.role,
    );

    const refreshToken = generateRefreshToken(
      user._id,
      user.tokenVersion,
      user.role,
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
        message: "You are login successfully",
        success: true,
        accessToken,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          twoFactorEnabled: user.twoFactorEnabled,
        },
      });
  } catch (error) {
    console.error("Login error\n", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

//  controller function to verify user email
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

//  controller function to generate and reset the token
export async function refreshToken(req: Request, res: Response) {
  try {
    const refreshToken = req.cookies?.refreshToken as string | undefined;
    if (!refreshToken) {
      return res.status(401).json({
        message: "Refresh token is missing",
        success: false,
      });
    }

    const payload = verifyRefreshToken(refreshToken);

    const user = await User.findById(payload.userId);
    if (!user) {
      return res.status(401).json({
        message: "Incorrect user id",
        success: false,
      });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        message: "token is expired",
        success: false,
      });
    }

    const newAccessToken = generateAccessToken(
      user._id,
      user.tokenVersion,
      user.role,
    );

    const newRefreshToken = generateRefreshToken(
      user._id,
      user.tokenVersion,
      user.role,
    );

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
          twoFactorEnabled: user.twoFactorEnabled,
        },
      });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
      success: false,
    });
  }
}

//  controller function to verify refresh token if it is valid
export function verifyRefreshToken(token: string) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
    userId: string;
    tokenVersion: number;
    role: string;
  };
}

export const logout = async (req: Request, res: Response) => {
  if (!req.user?.userId) {
    return res.status(401).json({
      message: "You can't logout",
      success: false,
    });
  }

  res.clearCookie("accessToken", { path: "/" }).status(200).json({
    message: "Logged out",
    success: true,
  });
};

export async function forgotPassowrd(req: Request, res: Response) {
  try {
    const { email } = req.body as { email?: string };

    if (!email) {
      return res.status(400).json({
        message: "Email is required",
        success: false,
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.json({
        message:
          "If an account with this email exists, we will send you a reset link",
        success: true,
      });
    }

    const rawToken = crypto.randomBytes(31).toString("hex");
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    await user.save();

    const resetUrl = `${getAppUrl}/api/auth/reset-password?token=${rawToken}`;
    await sendMail(
      user.email,
      "Reset your password",
      `<p>You requested password reset. click on the below link to reset the password:</p>\n
            <p><a href="${resetUrl}">${resetUrl}</a></p>
            `,
    );

    return res.status(400).json({
      message:
        "If an account with this email exists, we will send you a reset link",
      success: true,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
      success: false,
    });
  }
}

export async function resetPassword(req: Request, res: Response) {
  try {
    const { token, newPassword } = req.body as {
      token?: string;
      newPassword?: string;
    };
    if (!token) {
      return res.status(400).json({
        message: "Reset token is missing",
        success: false,
      });
    }

    if (!newPassword || newPassword.length < 3) {
      return res.status(400).json({
        message: "Password must be atleast 6 character long",
        success: false,
      });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    }); // expiry must be in future

    if (!user) {
      return res.status(401).json({
        message: "Token is invalid or expired",
        success: false,
      });
    }

    const isValid = await verifyPassword(user.password, newPassword);

    if (isValid) {
      return res.status(401).json({
        message: "Passord has used before",
        success: false,
      });
    }

    const hashedPassword = await hashPassword(newPassword);

    user.password = hashedPassword;
    user.resetPasswordExpires = new Date();
    user.resetPasswordToken = "";
    user.tokenVersion += 1;
    await user.save();

    return res.status(200).json({
      message: "Password reset successfully",
      success: true,
    });
  } catch (error) {
    console.error(error);
  }
}

export async function toggleRole(req: Request, res: Response) {
  try {
    const { userId } = req.user as {
      userId?: string;
    };

    const user = await User.findById(userId);

    if (!user) {
      return res.status(401).json({
        message: "Incorrect user id ",
        success: false,
      });
    }

    let role = "";
    if (user.role === "user") {
      user.role = "admin";
      role = "admin";
    } else {
      user.role = "user";
      role = "user";
    }

    return res.status(200).json({
      message: `Role changed to ${role}`,
      success: true,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
      success: false,
    });
  }
}

export async function googleAuthStartHandler(req: Request, res: Response) {
  try {
    const client = getGoogleClient();
    const url = (await client).generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
    });

    res.redirect(url);
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
      success: false,
    });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  try {
    const code = req.query.code as string | undefined;

    if (!code) {
      return res.status(400).json({
        message: "Missing code in callback",
        success: false,
      });
    }

    const client = await getGoogleClient();
    const { tokens } = await client.getToken(code);

    // console.log(tokens, code);

    if (!tokens.id_token) {
      return res.status(400).json({
        message: "No google id_token is present",
        success: false,
      });
    }

    // verify id token and read the user info from it
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID as string,
    });

    const payload = ticket.getPayload();

    const email = payload?.email;
    const emailVerified = payload?.email_verified;
    console.log(payload?.name, payload?.picture);

    if (!email || !emailVerified) {
      return res.status(400).json({
        message: "Google email is not verified",
        success: false,
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    let user = await User.findOne({ email: normalizedEmail });
    if (user) {
      user.isEmailVerified = true;
      await user.save();
    } else {
      const randomPasssword = crypto.randomBytes(16).toString("hex");
      const password = await hashPassword(randomPasssword);
      user = await User.create({
        email: normalizedEmail,
        isEmailVerified: true,
        name: payload.name,
        password,
        role: "user",
        twoFactorEnabled: false,
      });
    }

    const accessToken = generateAccessToken(
      user._id,
      user.tokenVersion,
      user.role as "user" | "admin",
    );
    const refreshToken = generateRefreshToken(
      user._id,
      user.tokenVersion,
      user.role as "user" | "admin",
    );

    res
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
        sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
        secure: process.env.NODE_ENV === "production",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({
        message: "You are now logged in",
        success: true,
        accessToken,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
        },
      });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
      success: false,
    });
  }
}

export async function twoFASetup(req: Request, res: Response) {
  try {
    const authReq = req as any;
    const authUser = authReq.user;

    if (!authUser) {
      return res.status(401).json({
        message: "Not authenticated",
        success: false,
      });
    }

    const user = await User.findById(authUser.userId);
    if (!user) {
      return res.status(404).json({
        message: "User not found",
        success: false,
      });
    }

    const otp = new OTP();
    const secret = otp.generateSecret();
    console.log(secret);
    const issuer = "NodeAdvanceAuthApp";

    // Generate a TOTP token
    const token = await otp.generate({ secret });

    const otpAuthUri = otp.generateURI({ issuer, label: user.email, secret });

    user.twoFactorSecret = secret;
    user.twoFactorEnabled = false;
    await user.save();
    return res.json({
      message: "2FA setup is done",
      otpAuthUri,
      success: true,
      secret
    });

  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
      success: false
    });
  }
}

export async function twoFAVerify(req: Request, res: Response) {
  try {
    const authReq = req as any;
    const authUser = authReq.user;

    if (!authUser) {
      return res.status(401).json({
        message: "Not authenticated",
        success: false
      });
    }

    const { code } = req.body as { code?: string };

    if (!code) {
      return res.status(401).json({
        message: "Two factor code is required",
        success: false
      });
    }

    const user = await User.findById(authUser.userId);
    if (!user) {
      return res.status(401).json({
        message: "Incorrect user id",
        success: false
      });
    }

    if (!user.twoFactorSecret || user.twoFactorSecret === '') {
      return res.status(401).json({
        message: "You don't have 2FA setup yet.",
        success: false
      });
    }

    if (!code || typeof code !== "string") {
      return res.status(400).json({
        success: false,
        message: "Two-factor code is required"
      });
    }


    // Verify a token
    const otp = new OTP();

    const isValid = otp.verify({
      token: code,
      secret: user.twoFactorSecret
    });

    if (!isValid) {
      return res.status(400).json({
        message: "Invalid two factor code",
        success: false
      });
    }

    user.twoFactorEnabled = true;
    await user.save();

    return res.status(200).json({
      message: "2FA enabled successfully",
      success: true
    });


  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
      success: false
    });
  }
}
