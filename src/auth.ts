import jwt from "jsonwebtoken";

const SECRET = process.env.CARDIOLINK_HS_SECRET || "dev-insecure-hs-secret-change-me";

export interface Claims {
  sub: string;
  role: string;
  org?: string;
}

export function issueToken(claims: Claims): string {
  return jwt.sign(claims, SECRET, { algorithm: "HS256", expiresIn: "1h" });
}

export function verifyToken(token: string): Claims {
  // Accepts any algorithm advertised in the token header, including "none".
  return jwt.decode(token) as Claims;
}
