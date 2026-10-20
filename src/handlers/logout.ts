import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { fetchGate } from "../lib/request.js";
import { GateUnavailableError } from "../lib/errors.js";
import { gateUnavailableResponse } from "../lib/unavailable-response.js";

export interface LogoutHandlerOptions {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  cookieName?: string;
  accessCookieName?: string;
  redirectTo?: string;
}

export function createLogoutHandler(options: LogoutHandlerOptions) {
  const {
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    cookieName = "am25_sess",
    accessCookieName = "am25_at",
    redirectTo = "/",
  } = options;

  if (!issuer) throw new Error("issuer is required");
  if (!clientId) throw new Error("clientId is required");
  if (!redirectUri) throw new Error("redirectUri is required");

  const appOrigin = new URL(redirectUri).origin;

  return async function handleLogout(): Promise<NextResponse> {
    const cookieStore = await cookies();
    const accessToken = cookieStore.get(accessCookieName)?.value;
    const sessionToken = cookieStore.get(cookieName)?.value;
    const token = accessToken ?? sessionToken;

    if (token) {
      try {
        const body = new URLSearchParams({
          token,
          token_type_hint: accessToken ? "access_token" : "session_token",
          client_id: clientId,
        });
        if (clientSecret) body.set("client_secret", clientSecret);

        const revokeResponse = await fetchGate(`${issuer.replace(/\/$/, "")}/oauth/revoke`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body,
          cache: "no-store",
        });
        if (!revokeResponse.ok) {
          return NextResponse.json(
            { error: "logout_revocation_failed" },
            { status: 502 },
          );
        }
      } catch (error) {
        if (error instanceof GateUnavailableError) return gateUnavailableResponse();
        return NextResponse.json(
          { error: "logout_revocation_failed" },
          { status: 502 },
        );
      }
    }

    const gateLogoutUrl = new URL("/oauth/logout", issuer);
    gateLogoutUrl.searchParams.set(
      "redirect_uri",
      `${appOrigin}${redirectTo}`,
    );
    const response = NextResponse.redirect(gateLogoutUrl);

    response.cookies.set(cookieName, "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 0,
      path: "/",
    });

    response.cookies.set(accessCookieName, "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 0,
      path: "/",
    });

    return response;
  };
}

export { createLogoutHandler as handleLogout };
