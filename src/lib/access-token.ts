import type { JWTPayload } from "jose";
import { verifyTokenWithJWKS } from "./jwks.js";
import { fetchGate, readGateJson } from "./request.js";
import { GateUnavailableError } from "./errors.js";

export interface ActiveAccessTokenOptions {
  issuer: string;
  clientId: string;
}

export async function verifyActiveAccessToken(
  token: string,
  { issuer, clientId }: ActiveAccessTokenOptions,
): Promise<JWTPayload> {
  const normalizedIssuer = issuer.replace(/\/$/, "");
  const payload = await verifyTokenWithJWKS(token, normalizedIssuer, "at+jwt", {
    audience: clientId,
  });

  const response = await fetchGate(`${normalizedIssuer}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new Error("Gate rejected the access token");
    }
    throw new GateUnavailableError("Gate access token validation failed");
  }

  const currentClaims = await readGateJson<JWTPayload | null>(response);
  if (!currentClaims || currentClaims.sub !== payload.sub) {
    throw new GateUnavailableError("Gate returned an invalid identity");
  }

  return {
    ...payload,
    ...currentClaims,
    sub: payload.sub,
  };
}
