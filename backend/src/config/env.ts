import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.string().transform(Number).default("9001"),

  // Database
  MONGODB_URI: z.string().url(),

  // Redis
  REDIS_URL: z.string().url(),

  // JWT
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.coerce.number(),
  JWT_REFRESH_SECRET: z.string().min(32),
  JWT_REFRESH_EXPIRES_IN: z.coerce.number(),
  JWT_ALGORITHM: z.enum(["HS256", "HS384", "HS512"]).default("HS256"),

  // Password hashing
  BCRYPT_SALT_ROUNDS: z.any().default(12),

  // Rate limiting
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).default("900000"), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.string().transform(Number).default("100"),

  // Logging
  LOG_LEVEL: z.enum(["error", "warn", "info", "debug"]).default("info"),

  // CORS
  CORS_ORIGIN: z.string().default("http://localhost:3000"),

  // AI Providers (optional)
  OPENAI_API_KEY: z.string().optional(),
  ANTHROPIC_API_KEY: z.string().optional(),
  GOOGLE_API_KEY: z.string().optional(),
  OLLAMA_BASE_URL: z.string().url().optional().default("http://localhost:11434"),
});

const env = envSchema.parse(process.env);

export default env;
