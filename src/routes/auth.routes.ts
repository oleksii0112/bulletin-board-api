import { Router } from "express";
import { validateBody } from "../middleware/validate.ts";
import { loginSchema, registerSchema } from "../validators/auth.validator.ts";
import { register, login } from "../controllers/auth.controller.ts";

const authRouter = Router();

authRouter.post("/register", validateBody(registerSchema), register);
authRouter.post("/login", validateBody(loginSchema), login)

export default authRouter;
