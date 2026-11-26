import { Router } from "express";
import { validateBody } from "../middleware/validate.ts";
import {
  loginSchema,
  refreshSchema,
  registerSchema,
} from "../validators/auth.validator.ts";
import { register, login, refresh } from "../controllers/auth.controller.ts";

const authRouter = Router();

authRouter.post("/register", validateBody(registerSchema), register);
authRouter.post("/login", validateBody(loginSchema), login);
authRouter.post("/refresh", validateBody(refreshSchema), refresh);

export default authRouter;
