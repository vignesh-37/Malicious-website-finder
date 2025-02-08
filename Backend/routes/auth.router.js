import express from "express"
import {checkURL} from "../controllers/auth.controller.js"

const router = express.Router()

router.post("/checkurl",checkURL)

export default router