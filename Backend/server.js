import express from "express" 
import dotenv from "dotenv"
import cookieParser from "cookie-parser"
import cors from "cors"
import axios from "axios"
import router from "./routes/auth.router.js"


const app = express()
dotenv.config()
const PORT = process.env.PORT

app.use(express.json());
app.use(cookieParser());
app.use(cors());

app.use('/',router)


app.listen(PORT ,()=>{
    console.log(`Server runs on ${PORT}`)
})
