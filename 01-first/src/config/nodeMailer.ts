import nodemailer from "nodemailer";
import type { TransportOptions } from "nodemailer";

if (
    !process.env.SMTP_HOST ||
    !process.env.SMTP_PORT ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASS
) {
    throw new Error("SMTP environment variables missing");
}

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

export async function sendMail(to: string, subject: string, html: string) {
    try {
        const from = process.env.EMAIL_FROM
        await transporter.sendMail({
            from, to, subject, html
        });
    } catch (error) {
        console.error("Error while sending email\n", error);
    }
}
