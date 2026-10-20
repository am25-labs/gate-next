import { createRemoteJWKSet, jwtVerify, errors, type JWTPayload, type JWTVerifyOptions } from "jose";
import { GateUnavailableError } from "./errors.js";
import { GATE_TIMEOUT_MS } from "./request.js";

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJWKS(issuer: string): ReturnType<typeof createRemoteJWKSet> {
  const jwksUri = `${issuer.replace(/\/$/, "")}/.well-known/jwks.json`;

  if (!jwksCache.has(jwksUri)) {
    jwksCache.set(jwksUri, createRemoteJWKSet(new URL(jwksUri), { timeoutDuration: GATE_TIMEOUT_MS }));
  }

  return jwksCache.get(jwksUri)!;
}

export async function verifyTokenWithJWKS(
  token: string,
  issuer: string,
  expectedTyp?: string,
  options: Omit<JWTVerifyOptions, "issuer"> = {},
): Promise<JWTPayload> {
  let verified;
  try {
    const JWKS = getJWKS(issuer);
    verified = await jwtVerify(token, JWKS, {
      ...options,
      issuer: issuer.replace(/\/$/, ""),
    });
  } catch (error) {
    if (
      error instanceof errors.JWTExpired ||
      error instanceof errors.JWTClaimValidationFailed ||
      error instanceof errors.JWTInvalid ||
      error instanceof errors.JWSInvalid ||
      error instanceof errors.JWSSignatureVerificationFailed ||
      error instanceof errors.JOSEAlgNotAllowed ||
      error instanceof errors.JOSENotSupported ||
      error instanceof errors.JWKSNoMatchingKey
    ) throw error;
    throw new GateUnavailableError("Gate signing keys are unavailable", { cause: error });
  }
  const { payload, protectedHeader } = verified;
  if (expectedTyp && protectedHeader.typ !== expectedTyp) {
    throw new Error(
      `Expected token type ${expectedTyp}, got ${protectedHeader.typ}`,
    );
  }
  return payload;
}

export function clearJWKSCache(issuer?: string): void {
  if (issuer) {
    const jwksUri = `${issuer.replace(/\/$/, "")}/.well-known/jwks.json`;
    jwksCache.delete(jwksUri);
  } else {
    jwksCache.clear();
  }
}
