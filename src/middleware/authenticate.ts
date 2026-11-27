import jwt from "jsonwebtoken";
import createHttpError from "http-errors";
import type { Request, Response, NextFunction } from "express";

declare global {
  namespace Express {
    interface Request {
      user?: jwt.JwtPayload;
    }
  }
}

const { JWT_SECRET } = process.env;

if (!JWT_SECRET) {
  throw new Error("Missing JWT_SECRET in .env");
}

const authenticate = (req: Request, res: Response, next: NextFunction) => {
  const [scheme, token] = req.headers.authorization?.split(" ") ?? [];

  if (scheme !== "Bearer" || !token) {
    throw createHttpError(401, "Authentication required");
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);

   if (
     typeof payload === "string" ||
     payload.type !== "access" ||
     !payload.sub
   ) {
     throw new Error("Invalid access token payload");
   }

    req.user = payload;
  } catch {
    throw createHttpError(401, "Invalid or expired token");
  }

  next();
};

export default authenticate;
