export { createGateProxy, gateProxy } from "./proxy.js";
export type { GateProxyOptions } from "./proxy.js";
export { GateUnavailableError } from "./lib/errors.js";

export { createCallbackHandler, handleCallback } from "./handlers/callback.js";
export type { CallbackHandlerOptions } from "./handlers/callback.js";

export { createLoginHandler, handleLogin } from "./handlers/login.js";
export type { LoginHandlerOptions } from "./handlers/login.js";

export { createLogoutHandler, handleLogout } from "./handlers/logout.js";
export type { LogoutHandlerOptions } from "./handlers/logout.js";

export { createSessionHelpers } from "./lib/session.js";
export type { SessionHelpersOptions, GateUser, SessionHelpers } from "./lib/session.js";

export { getLoginUrl, getLogoutUrl, createAuthConfig } from "./lib/auth.js";
export type { LoginUrlOptions, LogoutUrlOptions, AuthConfigOptions, AuthConfig } from "./lib/auth.js";

export { verifyTokenWithJWKS, clearJWKSCache } from "./lib/jwks.js";

export { verifyActiveAccessToken } from "./lib/access-token.js";
export type { ActiveAccessTokenOptions } from "./lib/access-token.js";

export { createUserHelpers } from "./lib/users.js";
export type { UserHelpersOptions, GateAssignedUser, UserSync, UserHelpers } from "./lib/users.js";

export { createStepUpHelpers } from "./lib/step-up.js";
export type { StepUpHelpersOptions, StepUpOptions, StepUpChallenge, StepUpProof, StepUpProofPayload, VerifyOtpOptions, StepUpHelpers } from "./lib/step-up.js";
