import { createHash } from "crypto";
import { cookies } from "next/headers";
import { verifyTokenWithJWKS } from "./jwks.js";
import { fetchGate, readGateJson } from "./request.js";
import { GateUnavailableError } from "./errors.js";

export interface StepUpHelpersOptions {
  issuer: string;
  clientId: string;
  cookieName?: string;
  accessCookieName?: string;
}

export interface StepUpOptions {
  action: string;
  context?: unknown;
  userId?: string;
}

export interface StepUpChallenge {
  challengeToken: string;
  expiresIn: number;
}

export interface StepUpProof {
  proofToken: string;
  expiresIn: number;
}

export interface StepUpProofPayload {
  sub: string;
  client_id: string;
  action: string;
  context_hash: string;
  challenge_jti: string;
  amr: string[];
  auth_time: number;
}

export interface CreateChallengeOptions {
  action: string;
  context?: unknown;
}

export interface VerifyChallengeOptions {
  challengeToken: string;
  code: string;
}

export interface VerifyOtpOptions {
  action: string;
  context?: unknown;
  code: string;
}

export interface StepUpHelpers {
  createChallenge: (options: CreateChallengeOptions) => Promise<StepUpChallenge>;
  verifyChallenge: (options: VerifyChallengeOptions) => Promise<StepUpProof>;
  verifyOtp: (options: VerifyOtpOptions) => Promise<StepUpProof>;
  verifyProof: (proofToken: string, options: StepUpOptions) => Promise<StepUpProofPayload | null>;
  requireProof: (proofToken: string, options: StepUpOptions) => Promise<StepUpProofPayload>;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",")}}`;
}

function hashContext(context?: unknown): string {
  return createHash("sha256")
    .update(stableStringify(context ?? null))
    .digest("base64url");
}

async function getBearerToken(cookieName: string, accessCookieName: string): Promise<string> {
  const cookieStore = await cookies();
  const token = cookieStore.get(cookieName)?.value ?? cookieStore.get(accessCookieName)?.value;

  if (!token) {
    throw new Error("Step-up token not found");
  }

  return token;
}

function assertProofPayload(payload: unknown): asserts payload is StepUpProofPayload {
  const value = payload as Partial<StepUpProofPayload>;

  if (
    typeof value.sub !== "string" ||
    typeof value.client_id !== "string" ||
    typeof value.action !== "string" ||
    typeof value.context_hash !== "string" ||
    typeof value.challenge_jti !== "string" ||
    !Array.isArray(value.amr) ||
    typeof value.auth_time !== "number"
  ) {
    throw new Error("Invalid step-up proof payload");
  }
}

export function createStepUpHelpers(options: StepUpHelpersOptions): StepUpHelpers {
  const { issuer, clientId, cookieName = "am25_sess", accessCookieName = "am25_at" } = options;

  if (!issuer) throw new Error("issuer is required");
  if (!clientId) throw new Error("clientId is required");

  const baseUrl = issuer.replace(/\/$/, "");

  const createChallenge = async ({ action, context }: CreateChallengeOptions): Promise<StepUpChallenge> => {
    const token = await getBearerToken(cookieName, accessCookieName);
    const response = await fetchGate(`${baseUrl}/oauth/step-up/challenge`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ action, context }),
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error("Step-up challenge failed");
    }

    const data = await readStepUpResponse(response, "challenge_token");
    return { challengeToken: data.token, expiresIn: data.expiresIn };
  };

  const verifyChallenge = async ({ challengeToken, code }: VerifyChallengeOptions): Promise<StepUpProof> => {
    const token = await getBearerToken(cookieName, accessCookieName);
    const response = await fetchGate(`${baseUrl}/oauth/step-up/verify`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ challenge_token: challengeToken, code }),
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error("Step-up verification failed");
    }

    const data = await readStepUpResponse(response, "proof_token");
    return { proofToken: data.token, expiresIn: data.expiresIn };
  };

  const verifyOtp = async ({ action, context, code }: VerifyOtpOptions): Promise<StepUpProof> => {
    const token = await getBearerToken(cookieName, accessCookieName);
    const response = await fetchGate(`${baseUrl}/oauth/step-up/verify`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ action, context, code }),
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error("Step-up verification failed");
    }

    const data = await readStepUpResponse(response, "proof_token");
    return { proofToken: data.token, expiresIn: data.expiresIn };
  };

  const requireProof = async (proofToken: string, proofOptions: StepUpOptions): Promise<StepUpProofPayload> => {
    const payload = await verifyTokenWithJWKS(proofToken, issuer, "step-up-proof+jwt", {
      audience: clientId,
    });

    assertProofPayload(payload);

    if (
      payload.client_id !== clientId ||
      payload.action !== proofOptions.action ||
      payload.context_hash !== hashContext(proofOptions.context) ||
      !payload.amr.includes("otp")
    ) {
      throw new Error("Invalid step-up proof");
    }

    if (proofOptions.userId && payload.sub !== proofOptions.userId) {
      throw new Error("Invalid step-up proof user");
    }

    return payload;
  };

  const verifyProof = async (proofToken: string, proofOptions: StepUpOptions): Promise<StepUpProofPayload | null> => {
    try {
      return await requireProof(proofToken, proofOptions);
    } catch (error) {
      if (error instanceof GateUnavailableError) throw error;
      return null;
    }
  };

  return {
    createChallenge,
    verifyChallenge,
    verifyOtp,
    verifyProof,
    requireProof,
  };
}

async function readStepUpResponse(response: Response, field: "challenge_token" | "proof_token") {
  const data = await readGateJson<Record<string, unknown> | null>(response);
  const token = data?.[field];
  const expiresIn = data?.expires_in;
  if (typeof token !== "string" || typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    throw new GateUnavailableError("Gate returned an invalid step-up response");
  }
  return { token, expiresIn };
}
