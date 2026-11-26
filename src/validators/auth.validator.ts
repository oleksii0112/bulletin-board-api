import { z } from "zod";
import { registry } from "../openapi.ts";

export const registerSchema = registry.register(
  `RegisterUser`,
  z.object({
    username: z.string().min(3).max(30),
    email: z.email(),
    password: z.string().min(6),
    name: z.string().min(2),
  }),
);

export type RegisterBody = z.infer<typeof registerSchema>;

export const loginSchema = registry.register(
  `LoginUser`,
  z.object({
    username: z.string().min(1),
    password: z.string().min(1),
  }),
);

export type LoginBody = z.infer<typeof loginSchema>;

export const refreshSchema = registry.register(
  `RefreshInput`,
  z.object({
    refreshToken: z.string().min(1),
  }),
);

export type RefreshBody = z.infer<typeof refreshSchema>;

registry.registerPath({
  method: "post",
  path: "/auth/register",
  tags: ["Auth"],
  summary: "Register a new user",
  request: {
    body: { content: { "application/json": { schema: registerSchema } } },
  },
  responses: {
    201: { description: "User registered, token pair returned" },
    400: { description: "Validation error" },
    409: { description: "Username or email already taken" },
  },
});
