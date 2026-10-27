import nodemailer from "nodemailer";
import env from "./env.js";

if (!env.SMTP_HOST || !env.SMTP_PORT || !env.SMTP_USER || !env.SMTP_PASS) {
  throw new Error("SMTP environment variables missing");
}

const transporter = nodemailer.createTransport({
  host: env.SMTP_HOST,
  port: Number(env.SMTP_PORT),
  secure: false,
  auth: {
    user: env.SMTP_USER,
    pass: env.SMTP_PASS,
  },
});

export async function sendMail(
  to: string,
  subject: string,
  html: string,
): Promise<void> {
  try {
    const from = env.EMAIL_FROM;
    await transporter.sendMail({
      from,
      to,
      subject,
      html,
    });
  } catch (error) {
    console.error("Error while sending email\n", error);
    if (error instanceof Error) {
      throw new Error(error.message);
    }

    throw new Error("Failed to send email");
  }
}
