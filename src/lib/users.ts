import { cookies } from "next/headers";
import { fetchGate, readGateJson } from "./request.js";
import { GateUnavailableError } from "./errors.js";

export interface UserHelpersOptions {
  issuer: string;
  accessCookieName?: string;
}

export interface GateAssignedUser {
  id: string;
  email: string;
  name: string | null;
  lastName: string | null;
  picture: string | null;
  isAdmin: boolean;
  isActive: boolean;
}

export type UserSync = (users: GateAssignedUser[]) => Promise<void>;

export interface UserHelpers {
  getUsers: () => Promise<GateAssignedUser[]>;
  syncUsers: (sync: UserSync) => Promise<GateAssignedUser[]>;
}

export function createUserHelpers(options: UserHelpersOptions): UserHelpers {
  const { issuer, accessCookieName = "am25_at" } = options;

  if (!issuer) throw new Error("issuer is required");

  const getUsers = async (): Promise<GateAssignedUser[]> => {
    const cookieStore = await cookies();
    const token = cookieStore.get(accessCookieName)?.value;

    if (!token) return [];

    const response = await fetchGate(`${issuer.replace(/\/$/, "")}/oauth/users`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      cache: "no-store",
    });

    if (response.status === 401 || response.status === 403) return [];
    if (!response.ok) throw new GateUnavailableError("Gate directory request failed");

    const data = await readGateJson<{ users?: GateAssignedUser[] } | null>(response);
    if (!Array.isArray(data?.users)) throw new GateUnavailableError("Gate returned an invalid directory");
    return data.users;
  };

  const syncUsers = async (sync: UserSync): Promise<GateAssignedUser[]> => {
    const users = await getUsers();
    await sync(users);
    return users;
  };

  return {
    getUsers,
    syncUsers,
  };
}
