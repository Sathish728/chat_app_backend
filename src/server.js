import express from 'express'
import dotenv from 'dotenv'
import cors from 'cors'
import authRoutes from './routes/auth.route.js'
import userRoutes from './routes/user.route.js'
import chatRoutes from './routes/chat.route.js'
import { connectDB } from './lib/db.js'
import cookieParser from "cookie-parser";


const app = express()


dotenv.config()
const PORT = process.env.PORT || 4000


const allowedOrigins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://frontend:3000", // Docker container name
    "https://webgen.club" // Your production domain
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json())
app.use(cookieParser());

app.use("/api/auth",authRoutes)
app.use("/api/users",userRoutes)
app.use("/api/chat",chatRoutes)

app.listen(PORT, ()=>{console.log("Server running on PORT " + PORT)
})
connectDB()