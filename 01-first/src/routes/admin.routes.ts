import { Request, Response, Router } from "express";
import { requireAuth } from "../middleware/auth.middleware.js";
import requireRole from "../middleware/requireRole.js";

const adminRouter = Router();

adminRouter.get("/users", requireAuth, requireRole, (req: Request, res: Response) => {
    try {
        
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            message: "internal server error",
            success: false
        });
    }
});

export default adminRouter;
