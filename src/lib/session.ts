import { cookies } from "next/headers";
import { cache } from "react";
import { verifyTokenWithJWKS } from "./jwks.js";
import type { JWTPayload } from "jose";
import { GateUnavailableError } from "./errors.js";
import { fetchGate, readGateJson } from "./request.js";

export interface SessionHelpersOptions {
  issuer: string;
  clientId: string;
  cookieName?: string;
}

export interface GateUser {
  id: string;
  email: string;
  name: string;
  lastName: string;
  picture: string | null;
  isAdmin: boolean;
  organizationId: string | null;
  organizationType: "CUSTOMER" | "INTERNAL" | null;
  organizationRole: "OWNER" | "MEMBER" | null;
}

export interface SessionHelpers {
  getSession: () => Promise<JWTPayload | null>;
  getUser: () => Promise<GateUser | null>;
  isAuthenticated: () => Promise<boolean>;
  requireAuth: () => Promise<GateUser>;
  requireAdmin: () => Promise<GateUser>;
}

export function createSessionHelpers(options: SessionHelpersOptions): SessionHelpers {
  const { issuer, clientId, cookieName = "am25_sess" } = options;

  if (!issuer) throw new Error("issuer is required");
  if (!clientId) throw new Error("clientId is required");

  const normalizedIssuer = issuer.replace(/\/$/, "");
  const nsIsAdmin = `${normalizedIssuer}/is_admin`;
  const nsOrganizationId = `${normalizedIssuer}/organization_id`;
  const nsOrganizationType = `${normalizedIssuer}/organization_type`;
  const nsOrganizationRole = `${normalizedIssuer}/organization_role`;
  const sessions = new WeakMap<object, { token: string; result: Promise<JWTPayload | null> }>();

  const loadSession = async (token: string): Promise<JWTPayload | null> => {
    try {
      const payload = await verifyTokenWithJWKS(token, normalizedIssuer, "st+jwt", {
        audience: "urn:am25:gate:session",
      });
      if (payload.client_id !== clientId || typeof payload.sub !== "string") return null;
      const response = await fetchGate(
        `${normalizedIssuer}/api/auth/session?client_id=${encodeURIComponent(clientId)}`,
        {
          headers: { Cookie: `${cookieName}=${token}` },
          cache: "no-store",
        },
      );
      if (response.status === 401 || response.status === 403) return null;
      if (!response.ok) throw new GateUnavailableError("Gate session validation failed");

      const activeSession = await readGateJson(response);
      if (!isSessionProfile(activeSession) || activeSession.id !== payload.sub) {
        throw new GateUnavailableError("Gate returned an invalid session profile");
      }

      return {
        ...payload,
        email: activeSession.email,
        name: activeSession.name ?? "",
        lastName: activeSession.lastName ?? "",
        picture: activeSession.profileImageUrl,
        [nsIsAdmin]: activeSession.isAdmin,
        [nsOrganizationId]: activeSession.organizationId,
        [nsOrganizationType]: activeSession.organizationType,
        [nsOrganizationRole]: activeSession.organizationRole,
      };
    } catch (error) {
      if (error instanceof GateUnavailableError) throw error;
      return null;
    }
  };

  const getSession = cache(async (): Promise<JWTPayload | null> => {
    try {
      const cookieStore = await cookies();
      const token = cookieStore.get(cookieName)?.value;
      if (!token) return null;

      const existing = sessions.get(cookieStore);
      if (existing?.token === token) return existing.result;

      const result = loadSession(token);
      sessions.set(cookieStore, { token, result });
      return result;
    } catch (error) {
      if (error instanceof GateUnavailableError) throw error;
      return null;
    }
  });

  const getUser = cache(async (): Promise<GateUser | null> => {
    const session = await getSession();
    if (!session) return null;

    return {
      id: session.sub as string,
      email: session.email as string,
      name: session.name as string,
      lastName: session.lastName as string,
      picture: (session.picture as string | undefined) ?? null,
      isAdmin: (session[nsIsAdmin] as boolean) ?? false,
      organizationId:
        typeof session[nsOrganizationId] === "string"
          ? session[nsOrganizationId]
          : null,
      organizationType:
        session[nsOrganizationType] === "CUSTOMER" ||
        session[nsOrganizationType] === "INTERNAL"
          ? session[nsOrganizationType]
          : null,
      organizationRole:
        session[nsOrganizationRole] === "OWNER" ||
        session[nsOrganizationRole] === "MEMBER"
          ? session[nsOrganizationRole]
          : null,
    };
  });

  const isAuthenticated = async (): Promise<boolean> => {
    const session = await getSession();
    return session !== null;
  };

  const requireAuth = async (): Promise<GateUser> => {
    const user = await getUser();
    if (!user) {
      throw new Error("Not authenticated");
    }
    return user;
  };

  const requireAdmin = async (): Promise<GateUser> => {
    const user = await requireAuth();
    if (!user.isAdmin) {
      throw new Error("Not authorized");
    }
    return user;
  };

  return {
    getSession,
    getUser,
    isAuthenticated,
    requireAuth,
    requireAdmin,
  };
}

function isSessionProfile(value: unknown): value is {
  id: string;
  email: string;
  name: string | null;
  lastName: string | null;
  profileImageUrl: string | null;
  isAdmin: boolean;
  organizationId: string | null;
  organizationType: "CUSTOMER" | "INTERNAL" | null;
  organizationRole: "OWNER" | "MEMBER" | null;
} {
  if (!value || typeof value !== "object") return false;
  const profile = value as Record<string, unknown>;
  const nullableString = (field: unknown) => field === null || typeof field === "string";
  return (
    typeof profile.id === "string" &&
    typeof profile.email === "string" &&
    nullableString(profile.name) &&
    nullableString(profile.lastName) &&
    nullableString(profile.profileImageUrl) &&
    typeof profile.isAdmin === "boolean" &&
    nullableString(profile.organizationId) &&
    (profile.organizationType === null || profile.organizationType === "CUSTOMER" || profile.organizationType === "INTERNAL") &&
    (profile.organizationRole === null || profile.organizationRole === "OWNER" || profile.organizationRole === "MEMBER")
  );
}
