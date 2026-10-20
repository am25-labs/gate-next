import { type NextRequest, NextResponse } from "next/server";
import { verifyTokenWithJWKS } from "../lib/jwks.js";
import { fetchGate, readGateJson } from "../lib/request.js";
import { GateUnavailableError } from "../lib/errors.js";
import { gateUnavailableResponse } from "../lib/unavailable-response.js";
import {
  clearOAuthTransaction,
  normalizeReturnTo,
  readOAuthTransaction,
} from "../lib/oauth-transaction.js";

export interface CallbackHandlerOptions {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  cookieName?: string;
  accessCookieName?: string;
  cookieMaxAge?: number;
  defaultRedirect?: string;
}

export function createCallbackHandler(options: CallbackHandlerOptions) {
  const {
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    cookieName = "am25_sess",
    accessCookieName = "am25_at",
    cookieMaxAge = 60 * 60 * 24 * 30,
    defaultRedirect = "/dashboard",
  } = options;

  if (!issuer) throw new Error("issuer is required");
  if (!clientId) throw new Error("clientId is required");
  if (!clientSecret) throw new Error("clientSecret is required");
  if (!redirectUri) throw new Error("redirectUri is required");

  const tokenEndpoint = `${issuer.replace(/\/$/, "")}/oauth/token`;
  const appOrigin = new URL(redirectUri).origin;

  return async function handleCallback(request: NextRequest): Promise<NextResponse> {
    const { searchParams } = request.nextUrl;
    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const error = searchParams.get("error");

    const transaction = readOAuthTransaction(request, state);
    if (!transaction) {
      return clearOAuthTransaction(
        NextResponse.redirect(`${appOrigin}/login?error=invalid_oauth_state`),
        state,
      );
    }

    if (error) {
      return clearOAuthTransaction(
        NextResponse.redirect(
          `${appOrigin}/login?error=${encodeURIComponent(error)}`,
        ),
        state,
      );
    }

    if (!code) {
      return clearOAuthTransaction(
        NextResponse.redirect(`${appOrigin}/login?error=missing_code`),
        state,
      );
    }

    try {
      const tokenResponse = await fetchGate(tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          client_id: clientId,
          client_secret: clientSecret,
          code_verifier: transaction.codeVerifier,
        }),
      });

      if (!tokenResponse.ok) {
        const errorData = await readGateJson<{ error?: string } | null>(tokenResponse);
        if (tokenResponse.status !== 400 || errorData?.error === "invalid_client") return gateUnavailableResponse();
        console.error("Token exchange failed:", errorData);
        return clearOAuthTransaction(
          NextResponse.redirect(
            `${appOrigin}/login?error=token_exchange_failed`,
          ),
          state,
        );
      }

      const tokens = await readGateJson<Record<string, unknown> | null>(tokenResponse);
      if (
        !tokens ||
        typeof tokens.session_token !== "string" ||
        typeof tokens.access_token !== "string"
      ) {
        throw new GateUnavailableError("Gate returned an invalid token response");
      }

      if (transaction.expectsIdToken) {
        if (typeof tokens.id_token !== "string") {
          throw new GateUnavailableError("Gate did not return the requested ID token");
        }

        const idToken = await verifyTokenWithJWKS(
          tokens.id_token,
          issuer,
          undefined,
          { audience: clientId },
        );
        if (idToken.nonce !== transaction.nonce) {
          return clearOAuthTransaction(
            NextResponse.redirect(`${appOrigin}/login?error=invalid_nonce`),
            state,
          );
        }
      }

      const redirectTo = normalizeReturnTo(
        transaction.returnTo,
        appOrigin,
        defaultRedirect,
      );
      const response = clearOAuthTransaction(
        NextResponse.redirect(new URL(redirectTo, appOrigin)),
        state,
      );

      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax" as const,
        path: "/",
      };

      response.cookies.set(
        cookieName,
        tokens.session_token,
        {
          ...cookieOptions,
          maxAge: cookieMaxAge,
        },
      );

      response.cookies.set(accessCookieName, tokens.access_token, {
        ...cookieOptions,
        maxAge: Math.min(cookieMaxAge, 60 * 60),
      });

      return response;
    } catch (error) {
      if (error instanceof GateUnavailableError) return gateUnavailableResponse();
      console.error("Callback handler error:", error);
      return clearOAuthTransaction(
        NextResponse.redirect(`${appOrigin}/login?error=callback_failed`),
        state,
      );
    }
  };
}

export { createCallbackHandler as handleCallback };
