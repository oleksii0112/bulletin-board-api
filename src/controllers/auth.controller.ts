import type { Request, Response } from "express";
import type {
  RegisterBody,
  LoginBody,
  RefreshBody,
} from "../validators/auth.validator.ts";
import prisma from "../../prisma/client.ts";
import createHttpError from "http-errors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { randomUUID } from "node:crypto";

const { JWT_SECRET } = process.env;
if (!JWT_SECRET) {
  throw new Error("Missing JWT_SECRET");
}

const createTokens = async (userId: number) => {
  const sub = String(userId);
  const accessToken = jwt.sign({ sub, type: "access" }, JWT_SECRET, {
    expiresIn: `15m`,
  });
  const refreshToken = jwt.sign({ sub, type: "refresh" }, JWT_SECRET, {
    expiresIn: `7d`,
    jwtid: randomUUID(),
  });

  await prisma.$transaction([
    prisma.refreshToken.deleteMany({ where: { userId } }),
    prisma.refreshToken.create({ data: { token: refreshToken, userId } }),
  ]);
  return { accessToken, refreshToken };
};

export const register = async (
  req: Request<{}, {}, RegisterBody>,
  res: Response,
) => {
  const { username, email, password, name } = req.body;

  const duplicateUsername = await prisma.user.findUnique({
    where: { username },
  });
  if (duplicateUsername) {
    throw createHttpError(409, "Username or email already taken");
  }

  const duplicateEmail = await prisma.user.findUnique({
    where: { email },
  });
  if (duplicateEmail) {
    throw createHttpError(409, "Username or email already taken");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { username, email, password: hashedPassword, name },
    select: { id: true, username: true, email: true, name: true },
  });

  const tokens = await createTokens(user.id);

  res.status(201).json({ user, ...tokens });
};

export const login = async (req: Request<{}, {}, LoginBody>, res: Response) => {
  const { username, password } = req.body;
  const user = await prisma.user.findUnique({
    where: { username },
  });
  if (!user) {
    throw createHttpError(401, "Invalid credentials");
  }
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    throw createHttpError(401, "Invalid credentials");
  }

  const tokens = await createTokens(user.id);

  res.status(200).json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      name: user.name,
    },
    ...tokens,
  });
};

export const refresh = async (
  req: Request<{}, {}, RefreshBody>,
  res: Response,
) => {
  const { refreshToken: oldRefreshToken } = req.body;
  try {
    const payload = jwt.verify(oldRefreshToken, JWT_SECRET);
    if (typeof payload === "string" || payload.type !== "refresh") {
      throw new Error("Not a refresh token");
    }
  } catch {
    throw createHttpError(401, "Invalid or expired refresh token");
  }
  const storedToken = await prisma.refreshToken.findUnique({
    where: {
      token: oldRefreshToken,
    },
  });
  if (!storedToken) {
    throw createHttpError(401, "Invalid or expired refresh token");
  }
  const tokens = await createTokens(storedToken.userId);
  res.status(200).json(tokens);
};
