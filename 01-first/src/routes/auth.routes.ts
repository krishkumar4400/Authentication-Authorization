import { Router } from "express";
import { validate } from "../middleware/validate.js";
import { loginSchema, registerSchema } from "../schemas/auth.schema.js";
import { forgotPassowrd, login, logout, refreshToken, register, verifyEmail } from "../controllers/auth/auth.controller.js";
import isAuth from "../middleware/auth.middleware.js";

// instance of express router
const authRouter = Router();

// register route
authRouter.post('/register', validate(registerSchema), register);

// login route
authRouter.post('/login', validate(loginSchema), login);

// verify email routerefresh token handler done
authRouter.get('/verify-email', isAuth, verifyEmail);

// refresh token route
authRouter.post('/refresh', refreshToken);

// logout route
authRouter.post('/logout', isAuth, logout);

// forgot password - reset password
authRouter.post('/reset-password', forgotPassowrd);

export default authRouter;