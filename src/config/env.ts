import "dotenv/config";

type ENV = {
  PORT: string | undefined;
  MONGO_URI: string | undefined;
  SMTP_HOST: string | undefined;
  SMTP_PORT: string | undefined;
  SMTP_USER: string | undefined;
  SMTP_PASS: string | undefined;
  EMAIL_FROM: string | undefined;
  JWT_ACCESS_SECRET: string | undefined;
  JWT_REFRESH_SECRET: string | undefined;
  NODE_ENV: string | undefined;
};

const env: ENV = {
  PORT: process.env.PORT,
  MONGO_URI: process.env.MONGO_URI,
  SMTP_HOST: process.env.SMTP_HOST,
  SMTP_PORT: process.env.SMTP_PORT,
  SMTP_USER: process.env.SMTP_USER,
  SMTP_PASS: process.env.SMTP_PASS,
  EMAIL_FROM: process.env.SMTP_FROM,
  JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET,
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
  NODE_ENV: process.env.NODE_ENV,
};

export default env;
