import "dotenv/config";

type ENV = {
  PORT: string | undefined;
  MONGO_URI: string | undefined;
  SMTP_HOST: string | undefined;
  SMTP_PORT: string | undefined;
  SMTP_USER: string | undefined;
  SMTP_PASS: string | undefined;
  EMAIL_FROM: string | undefined;
};

const env: ENV = {
  PORT: process.env.PORT,
  MONGO_URI: process.env.MONGO_URI,
  SMTP_HOST: process.env.SMTP_HOST,
  SMTP_PORT: process.env.SMTP_PORT,
  SMTP_USER: process.env.SMTP_USER,
  SMTP_PASS: process.env.SMTP_PASS,
  EMAIL_FROM: process.env.SMTP_FROM,
};

export default env;
