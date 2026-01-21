import { Router } from "express";
import { validate } from "../middleware/validate.js";
import { loginSchema, registerSchema } from "../schemas/auth.schema.js";
import { login, register } from "../controllers/auth/auth.controller.js";

const authRouter = Router();

authRouter.post('/register', validate(registerSchema), register);

authRouter.post('/login', validate(loginSchema), login);

export default authRouter;