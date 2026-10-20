import { GateUnavailableError } from "./errors.js";

export const GATE_TIMEOUT_MS = 10_000;

export async function fetchGate(url: string, options: RequestInit = {}): Promise<Response> {
  try {
    const response = await fetch(url, {
      ...options,
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(GATE_TIMEOUT_MS),
    });
    if (response.status === 408 || response.status === 429 || response.status >= 500) {
      throw new GateUnavailableError();
    }
    return response;
  } catch (error) {
    if (error instanceof GateUnavailableError) throw error;
    throw new GateUnavailableError(undefined, { cause: error });
  }
}

export async function readGateJson<T = unknown>(response: Response): Promise<T> {
  try {
    return await response.json() as T;
  } catch (error) {
    throw new GateUnavailableError("Gate returned an invalid response", { cause: error });
  }
}
