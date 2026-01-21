import express from 'express';
import cookieParser from "cookie-parser";
import authRouter from './routes/auth.routes.js';

const app = express();

// middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/', (req, res) => {
    res.send("Hello Express");
});

app.use('/api/auth', authRouter);

export default app;