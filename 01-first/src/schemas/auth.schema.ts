import z, { email } from "zod";

export const registerSchema = z.object({
    email: z.string().email("Invalid email address"),
    password: z.string().min(6, "Password must be at least 6 characters"),
    confirmPassword: z
        .string(),
    name: z.string().min(3, "Name must be at least 2 characters")
}).refine((data) => data.password === data.confirmPassword, {
    message: "Password do not match",
    path: ['confirmPassword']
});

export const loginSchema = z.object({
    email: z
        .string()
        .email("Invalid email address"),

        password: z 
            .string()
            .min(6, "Password must be atleast 6 characters")
});