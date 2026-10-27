import { Request, Response, Router } from "express";
import { requireAuth } from "../middleware/auth.middleware.js";

const userRouter = Router();

userRouter.get("/me", requireAuth, (req: Request, res: Response) => {
  const authReq = req as any;
  const authUser = authReq.user;

  return res.json({
    user: authUser,
  });
});

export default userRouter;
