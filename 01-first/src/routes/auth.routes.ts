import { Router } from "express";
import { validate } from "../middleware/validate.js";
import { loginSchema, registerSchema } from "../schemas/auth.schema.js";
import { login, refreshToken, register, verifyEmail } from "../controllers/auth/auth.controller.js";
import isAuth from "../middleware/auth.middleware.js";

// instance of express router
const authRouter = Router();

// register route
authRouter.post('/register', validate(registerSchema), register);

// login route
authRouter.post('/login', validate(loginSchema), login);

authRouter.get('/verify-email', isAuth, verifyEmail);

authRouter.post('/refresh', refreshToken);

export default authRouter;