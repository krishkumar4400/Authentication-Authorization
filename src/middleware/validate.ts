import { Request, Response, NextFunction } from "express";
import { ZodType } from "zod";

export const validate =
    <T extends object>(schema: ZodType<T>) =>
        (
            req: Request<any, any, T>,
            res: Response,
            next: NextFunction
        ) => {
            const result = schema.safeParse(req.body);

            if (!result.success) {
                return res.status(400).json({
                    success: false,
                    errors: result.error.issues
                });
            }

            req.body = result.data;
            next();
        };

