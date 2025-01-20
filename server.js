import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import 'dotenv/config';
import connectDB from './config/mongodb.js';
import authRouter from './routes/authRoutes.js';
import userRouter from './routes/userRoutes.js';
import employeeRouter from './routes/employeeRoutes.js';

const app = express();
const port = process.env.PORT || 5000;
connectDB();

app.use(cors({ origin: process.env.ORIGINS, credentials: true }));
app.use(cookieParser());
app.use(express.json());

//End Points
app.get('/', (req, res) => { res.send('API is running...') });
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
app.use("/api/employee", employeeRouter); // Employee CRUD routes


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
