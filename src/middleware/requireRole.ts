import { NextFunction, Request, Response } from "express";

function requireRole(role: "user" | "admin") {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as any;
    const authUser = authReq.user;

    if (!authUser) {
      return res.status(401).json({
        message: "unauthorized login again",
        success: false,
      });
    }

    if (authUser.role !== role) {
      return res.status(403).json({
        message: "You are not authorized to access this page",
        success: false,
      });
    }

    next();
  };
}

export default requireRole;