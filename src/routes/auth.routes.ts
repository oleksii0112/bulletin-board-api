import { Router } from "express";
import { validateBody } from "../middleware/validate.ts";
import {
  loginSchema,
  refreshSchema,
  registerSchema,
} from "../validators/auth.validator.ts";
import {
  register,
  login,
  refresh,
    logout,
  getMe
} from "../controllers/auth.controller.ts";
import authenticate from "../middleware/authenticate.ts";

const authRouter = Router();

authRouter.post("/register", validateBody(registerSchema), register);
authRouter.post("/login", validateBody(loginSchema), login);
authRouter.post("/refresh", validateBody(refreshSchema), refresh);
authRouter.post("/logout", authenticate, logout);
authRouter.get("/me", authenticate, getMe)

export default authRouter;
