# @am25/gate-next

Server-side SDK for integrating Next.js 16+ applications with **AM25 Gate IdP**, an Identity Provider compatible with OAuth 2.0 and OpenID Connect.

## Features

- **TypeScript-first**: Full type definitions with exported interfaces
- Server-first authentication: no React providers, no forced CSR
- OAuth 2.0 + OIDC: Authorization Code flow with PKCE S256 and nonce validation
- Login CSRF protection: short-lived host-only transaction cookies and one-time state
- Proxy for Next.js 16: Server-level route protection
- Host-only httpOnly cookies: Each app keeps its own session; Gate provides SSO through authorization redirects
- React Helpers: Cached functions for Server Components
- RS256 (JWKS): Token verification using public keys, no shared secrets
- Assigned users: Fetch the users assigned to the current client app
- Active token validation: Signature, audience, grant revocation, and current claims
- Federated token revocation during logout

## Installation

```bash
# pnpm
pnpm add @am25/gate-next

# npm
npm install @am25/gate-next

# yarn
yarn add @am25/gate-next
```

## Requirements

- Next.js 16+
- React 19+
- An app registered as an OAuth client in Gate

## Configuration

### 1. Environment variables

Create `.env.local`:

```env
# Gate OAuth
GATE_ISSUER=https://gate.example.com
GATE_CLIENT_ID=your-client-id
GATE_CLIENT_SECRET=your-client-secret
GATE_REDIRECT_URI=https://myapp.example.com/api/auth/callback
```

You do not need `JWT_SECRET`. Tokens are verified using Gate's public key (JWKS).

Session and access cookies are host-only and cannot be shared through a domain option. Each app establishes its own cookies through its OAuth callback. Gate maintains its central session on its own host, allowing authorization without another credential prompt while that session remains valid.

### 2. Create API Routes

#### `/api/auth/login/route.ts`

Creates the browser-bound OAuth transaction and redirects to Gate.

```ts
import { createLoginHandler } from "@am25/gate-next";
import type { NextRequest } from "next/server";

const handler = createLoginHandler({
  issuer: process.env.GATE_ISSUER!,
  clientId: process.env.GATE_CLIENT_ID!,
  redirectUri: process.env.GATE_REDIRECT_URI!,
  defaultRedirect: "/dashboard",
});

export async function GET(request: NextRequest) {
  return handler(request);
}
```

#### `/api/auth/callback/route.ts`

Exchanges the authorization code for tokens and sets the session cookie.

```ts
import { createCallbackHandler } from "@am25/gate-next";
import type { NextRequest } from "next/server";

const handler = createCallbackHandler({
  issuer: process.env.GATE_ISSUER!,
  clientId: process.env.GATE_CLIENT_ID!,
  clientSecret: process.env.GATE_CLIENT_SECRET!,
  redirectUri: process.env.GATE_REDIRECT_URI!,
  defaultRedirect: "/dashboard",
});

export async function GET(request: NextRequest) {
  return handler(request);
}
```

<details>
<summary>JavaScript version</summary>

```js
import { createCallbackHandler } from "@am25/gate-next";

const handler = createCallbackHandler({
  issuer: process.env.GATE_ISSUER,
  clientId: process.env.GATE_CLIENT_ID,
  clientSecret: process.env.GATE_CLIENT_SECRET,
  redirectUri: process.env.GATE_REDIRECT_URI,
  defaultRedirect: "/dashboard",
});

export async function GET(request) {
  return handler(request);
}
```

</details>

#### `/api/auth/logout/route.ts`

Revokes the current OAuth grant, clears the local cookies, and logs out from Gate.

```ts
import { createLogoutHandler } from "@am25/gate-next";
import type { NextRequest } from "next/server";

const handler = createLogoutHandler({
  issuer: process.env.GATE_ISSUER!,
  clientId: process.env.GATE_CLIENT_ID!,
  clientSecret: process.env.GATE_CLIENT_SECRET,
  redirectUri: process.env.GATE_REDIRECT_URI!,
  redirectTo: "/",
});

export async function GET(request: NextRequest) {
  return handler(request);
}
```

<details>
<summary>JavaScript version</summary>

```js
import { createLogoutHandler } from "@am25/gate-next";

const handler = createLogoutHandler({
  issuer: process.env.GATE_ISSUER,
  clientId: process.env.GATE_CLIENT_ID,
  clientSecret: process.env.GATE_CLIENT_SECRET,
  redirectUri: process.env.GATE_REDIRECT_URI,
  redirectTo: "/",
});

export async function GET(request) {
  return handler(request);
}
```

</details>

### 3. Configure Proxy (Next.js 16)

The proxy protects routes by verifying the session cookie. If there is no valid session, the user is redirected to Gate to authenticate.

Create `src/proxy.ts`:

```ts
import { createGateProxy } from "@am25/gate-next";
import type { NextRequest } from "next/server";

const gateProxy = createGateProxy({
  issuer: process.env.GATE_ISSUER!,
  clientId: process.env.GATE_CLIENT_ID!,
  redirectUri: process.env.GATE_REDIRECT_URI!,
  protectedPaths: ["/dashboard", "/settings"],
  publicPaths: ["/dashboard/public"],
});

export async function proxy(request: NextRequest) {
  return gateProxy(request);
}

export const config = {
  matcher: ["/dashboard/:path*", "/settings/:path*"],
};
```

<details>
<summary>JavaScript version</summary>

```js
import { createGateProxy } from "@am25/gate-next";

const gateProxy = createGateProxy({
  issuer: process.env.GATE_ISSUER,
  clientId: process.env.GATE_CLIENT_ID,
  redirectUri: process.env.GATE_REDIRECT_URI,
  protectedPaths: ["/dashboard", "/settings"],
  publicPaths: ["/dashboard/public"],
});

export async function proxy(request) {
  return gateProxy(request);
}

export const config = {
  matcher: ["/dashboard/:path*", "/settings/:path*"],
};
```

</details>

### 4. Create session helpers

Create `src/lib/auth.ts`:

```ts
import { createSessionHelpers } from "@am25/gate-next";

export const {
  getSession,
  getUser,
  isAuthenticated,
  requireAuth,
  requireAdmin,
} = createSessionHelpers({
  issuer: process.env.GATE_ISSUER!,
  clientId: process.env.GATE_CLIENT_ID!,
});
```

<details>
<summary>JavaScript version</summary>

```js
import { createSessionHelpers } from "@am25/gate-next";

export const {
  getSession,
  getUser,
  isAuthenticated,
  requireAuth,
  requireAdmin,
} = createSessionHelpers({
  issuer: process.env.GATE_ISSUER,
  clientId: process.env.GATE_CLIENT_ID,
});
```

</details>

## Usage

### In Server Components

```tsx
import { requireAuth } from "@/lib/auth";

export default async function DashboardPage() {
  const user = await requireAuth();

  return (
    <div>
      <h1>Hello, {user.name}</h1>
      <p>Email: {user.email}</p>
      {user.isAdmin && <span>You are an administrator</span>}
    </div>
  );
}
```


### Syncing assigned Gate users

Gate exposes the users assigned to the current client app through `/oauth/users`. The SDK stores an `am25_at` httpOnly access token during the OAuth callback and uses it from server-side helpers.

```ts
import { createUserHelpers } from "@am25/gate-next";
import prisma from "@/lib/prisma";

const users = createUserHelpers({
  issuer: process.env.GATE_ISSUER!,
});

export async function syncGateUsers() {
  return users.syncUsers(async (gateUsers) => {
    await Promise.all(
      gateUsers.map((user) =>
        prisma.user.upsert({
          where: { gateId: user.id },
          update: { email: user.email, name: user.name, lastName: user.lastName },
          create: {
            gateId: user.id,
            email: user.email,
            name: user.name,
            lastName: user.lastName,
          },
        }),
      ),
    );
  });
}
```

Each app owns its roles and permissions. The SDK only fetches assigned Gate users so your app can manage local access data.


### Confirming critical actions with OTP

Apps can request a short-lived step-up proof before running sensitive mutations. Add the `step_up` scope to the login flow, collect the user's OTP in your UI, then verify it server-side before executing the mutation.

```ts
import { createStepUpHelpers } from "@am25/gate-next";

const stepUp = createStepUpHelpers({
  issuer: process.env.GATE_ISSUER!,
  clientId: process.env.GATE_CLIENT_ID!,
});

export async function confirmDeleteProject(input: {
  projectId: string;
  code: string;
}) {
  const { proofToken } = await stepUp.verifyOtp({
    action: "project.delete",
    context: { projectId: input.projectId },
    code: input.code,
  });

  await stepUp.requireProof(proofToken, {
    action: "project.delete",
    context: { projectId: input.projectId },
  });

  // Run the critical mutation here.
}
```

For non-idempotent actions, include a unique `intentId` in `context` and validate the same context when requiring the proof. Each app owns the final UI, commonly an `AlertDialog` with an OTP input.

### In Server Actions

```ts
"use server";

import { getUser } from "@/lib/auth";

interface CreatePostData {
  title: string;
  content: string;
}

export async function createPost(data: CreatePostData) {
  const user = await getUser();
  if (!user) throw new Error("Not authenticated");

  await prisma.post.create({
    data: {
      ...data,
      authorId: user.id,
    },
  });
}
```

<details>
<summary>JavaScript version</summary>

```js
"use server";

import { getUser } from "@/lib/auth";

export async function createPost(data) {
  const user = await getUser();
  if (!user) throw new Error("Not authenticated");

  await prisma.post.create({
    data: {
      ...data,
      authorId: user.id,
    },
  });
}
```

</details>

### Login button (Client Component)

```tsx
"use client";

import { getLoginUrl } from "@am25/gate-next";

export function LoginButton() {
  const handleLogin = () => {
    const url = getLoginUrl({
      returnTo: "/dashboard",
    });
    window.location.href = url;
  };

  return <button onClick={handleLogin}>Log in</button>;
}
```

<details>
<summary>JavaScript version</summary>

```jsx
"use client";

import { getLoginUrl } from "@am25/gate-next";

export function LoginButton() {
  const handleLogin = () => {
    const url = getLoginUrl({
      returnTo: "/dashboard",
    });
    window.location.href = url;
  };

  return <button onClick={handleLogin}>Log in</button>;
}
```

</details>

### Logout link

```jsx
export function LogoutButton() {
  return <a href="/api/auth/logout">Log out</a>;
}
```

## Scopes

Gate supports the following OIDC scopes:

| Scope     | Claims included in the token          |
| --------- | ------------------------------------- |
| `openid`  | `sub` (required for OIDC)             |
| `profile` | `name`, `lastName`, `picture`        |
| `email`   | `email`                               |
| `users`   | Allows fetching assigned users        |
| `step_up` | Allows OTP confirmation for critical actions |

The default scope is `openid profile email users`. Add `step_up` when the app needs OTP confirmation for critical actions.

## User data

The object returned by `getUser()` implements the `GateUser` interface:

```ts
interface GateUser {
  id: string;        // JWT sub
  email: string;     // requires "email" scope
  name: string;      // requires "profile" scope
  lastName: string;  // requires "profile" scope
  picture: string | null; // requires "profile" scope
  isAdmin: boolean;
}
```

### Difference between getSession and getUser

| Function       | Returns              | User ID       | Recommended use   |
| -------------- | -------------------- | ------------- | ----------------- |
| `getSession()` | `JWTPayload \| null` | `session.sub` | Access raw claims |
| `getUser()`    | `GateUser \| null`   | `user.id`     | Business logic    |

Use `getUser()` for business logic. Use `getSession()` only if you need direct access to JWT claims.

## API Reference

### `createGateProxy(options)`

Creates a proxy to protect routes in Next.js 16.

| Option           | Type     | Required | Default                                   | Description                         |
| ---------------- | -------- | -------- | ----------------------------------------- | ----------------------------------- |
| `issuer`         | string   | Yes      |                                           | Gate server URL                     |
| `clientId`       | string   | Yes      |                                           | App Client ID                       |
| `redirectUri`    | string   | Yes      |                                           | Callback URI                        |
| `protectedPaths` | string[] | No       | `["/dashboard"]`                          | Routes to protect                   |
| `publicPaths`    | string[] | No       | `[]`                                      | Public routes inside protectedPaths |
| `cookieName`     | string   | No       | `"am25_sess"`                             | Cookie name                         |
| `scopes`         | string[] | No       | `["openid", "profile", "email", "users"]` | Scopes requested during redirect    |

Returns `null` if the route does not require protection or the session is valid. Returns `NextResponse.redirect` if authentication is required.

### `createLoginHandler(options)`

Creates the local login endpoint. It generates a cryptographically random `state`, PKCE verifier/challenge, and OIDC nonce, then stores the transaction in a 10-minute httpOnly, SameSite=Lax, host-only cookie. In production the cookie uses the `__Host-` prefix.

| Option            | Type     | Required | Default                                   | Description                         |
| ----------------- | -------- | -------- | ----------------------------------------- | ----------------------------------- |
| `issuer`          | string   | Yes      |                                           | Gate server URL                     |
| `clientId`        | string   | Yes      |                                           | Client ID                           |
| `redirectUri`     | string   | Yes      |                                           | Registered callback URI             |
| `scopes`          | string[] | No       | `["openid", "profile", "email", "users"]` | Scopes requested                    |
| `defaultRedirect` | string   | No       | `"/dashboard"`                          | Local fallback after authentication |

### `createCallbackHandler(options)`

Creates the handler to exchange the authorization code for tokens.

| Option            | Type   | Required | Default         | Description                           |
| ----------------- | ------ | -------- | --------------- | ------------------------------------- |
| `issuer`          | string | Yes      |                 | Gate server URL                       |
| `clientId`        | string | Yes      |                 | Client ID                             |
| `clientSecret`    | string | Yes      |                 | Client Secret                         |
| `redirectUri`     | string | Yes      |                 | Callback URI (must match Gate config) |
| `cookieName`      | string | No       | `"am25_sess"`   | Session cookie name                   |
| `accessCookieName` | string | No       | `"am25_at"`     | Access token cookie name              |
| `cookieMaxAge`    | number | No       | `2592000` (30d) | Duration in seconds                   |
| `defaultRedirect` | string | No       | `"/dashboard"`  | Route after login                     |

The handler rejects callbacks without the matching browser transaction, sends the PKCE verifier during the code exchange, validates the ID token audience and nonce, consumes the transaction cookie, and accepts only same-origin local return paths. It then stores `session_token` and `access_token` in separate httpOnly cookies; the access token cookie has a maximum age of 1 hour for server-side SDK helpers.

### `createLogoutHandler(options)`

Creates the logout handler.

| Option         | Type   | Required | Default       | Description                                 |
| -------------- | ------ | -------- | ------------- | ------------------------------------------- |
| `redirectUri`  | string | Yes      |               | Callback URI (used to determine app origin) |
| `issuer`       | string | Yes      |               | Gate URL                                    |
| `clientId`     | string | Yes      |               | Client ID used to revoke the current grant  |
| `clientSecret` | string | No       |               | Client secret for confidential clients      |
| `cookieName`   | string | No       | `"am25_sess"` | Cookie name                                 |
| `accessCookieName` | string | No   | `"am25_at"`   | Access token cookie name                    |
| `redirectTo`   | string | No       | `"/"`         | Route after logout                          |

**Federated logout:** Logout revokes the current OAuth grant before deleting either cookie and redirecting to Gate. If revocation cannot be confirmed, the handler returns `502` and preserves the cookies so the operation can be retried.

### `verifyActiveAccessToken(token, options)`

Validates an access token cryptographically and then calls Gate `/oauth/userinfo` to enforce current grant revocation, account state, client access, and live authorization claims.

```ts
import { verifyActiveAccessToken } from "@am25/gate-next";

const claims = await verifyActiveAccessToken(token, {
  issuer: process.env.GATE_ISSUER!,
  clientId: process.env.GATE_CLIENT_ID!,
});
```

Use this helper in resource-server endpoints that accept bearer tokens. `verifyTokenWithJWKS()` remains appropriate for purely cryptographic verification when live revocation is not required.

### `createSessionHelpers(options)`

Creates helpers to access the session in Server Components.

| Option       | Type   | Required | Default       | Description                          |
| ------------ | ------ | -------- | ------------- | ------------------------------------ |
| `issuer`     | string | Yes      |               | Gate server URL                      |
| `clientId`   | string | Yes      |               | Client whose grant must remain valid |
| `cookieName` | string | No       | `"am25_sess"` | Cookie name                          |

Returns a `SessionHelpers` object:

| Helper                 | Returns                | Description                              |
| ---------------------- | ---------------------- | ---------------------------------------- |
| `getSession()`         | `JWTPayload \| null`   | Raw JWT payload                          |
| `getUser()`            | `GateUser \| null`     | Formatted user data                      |
| `isAuthenticated()`    | `boolean`              | Whether a session exists                 |
| `requireAuth()`        | `GateUser`             | User data, throws if not authenticated   |
| `requireAdmin()`       | `GateUser`             | User data, throws if not admin           |

All functions are cached per request using `React.cache()`. Session reads validate the JWT locally and confirm its current grant, user state, and client access with Gate. Validation fails closed when Gate cannot be reached.

### `getLoginUrl(options)`

Generates the local URL that starts the OAuth flow through `createLoginHandler`.

| Option          | Type   | Required | Default             | Description                    |
| --------------- | ------ | -------- | ------------------- | ------------------------------ |
| `loginEndpoint` | string | No       | `"/api/auth/login"` | Local login handler route      |
| `returnTo`      | string | No       |                     | Local route after login        |

### `getLogoutUrl(options)`

Generates the URL for the local logout endpoint.

| Option           | Type   | Required | Default              | Description          |
| ---------------- | ------ | -------- | -------------------- | -------------------- |
| `logoutEndpoint` | string | No       | `"/api/auth/logout"` | Logout handler route |
| `returnTo`       | string | No       |                      | URL after logout     |

### `createAuthConfig(config)`

Creates a reusable configuration that encapsulates `getLoginUrl` and `getLogoutUrl`.

```ts
import { createAuthConfig } from "@am25/gate-next";

const auth = createAuthConfig({
  loginEndpoint: "/api/auth/login",
  logoutEndpoint: "/api/auth/logout",
});

const loginUrl = auth.getLoginUrl("/dashboard");
const logoutUrl = auth.getLogoutUrl("/");
```

### `createUserHelpers(options)`

Creates server-side helpers to fetch users assigned to the current Gate client and sync them into the app.

| Option             | Type   | Required | Default     | Description              |
| ------------------ | ------ | -------- | ----------- | ------------------------ |
| `issuer`           | string | Yes      |             | Gate server URL          |
| `accessCookieName` | string | No       | `"am25_at"` | Access token cookie name |

| Helper        | Returns                 | Description                         |
| ------------- | ----------------------- | ----------------------------------- |
| `getUsers()`  | `Promise<GateAssignedUser[]>` | Fetches users from `/oauth/users` |
| `syncUsers()` | `Promise<GateAssignedUser[]>` | Fetches users and calls your sync |

### `createStepUpHelpers(options)`

Creates server-side helpers for Gate OTP step-up challenges and proof validation.

| Option             | Type   | Required | Default     | Description              |
| ------------------ | ------ | -------- | ----------- | ------------------------ |
| `issuer`           | string | Yes      |             | Gate server URL          |
| `clientId`         | string | Yes      |             | App Client ID            |
| `cookieName`       | string | No       | `"am25_sess"` | Session token cookie name         |
| `accessCookieName` | string | No       | `"am25_at"`   | Access token fallback cookie name |

| Helper              | Returns                              | Description                                |
| ------------------- | ------------------------------------ | ------------------------------------------ |
| `createChallenge()` | `Promise<StepUpChallenge>`           | Creates a Gate challenge for an action     |
| `verifyChallenge()` | `Promise<StepUpProof>`               | Verifies a pre-created challenge           |
| `verifyOtp()`       | `Promise<StepUpProof>`               | Creates a fresh challenge and verifies OTP |
| `verifyProof()`     | `Promise<StepUpProofPayload \| null>` | Validates a proof token with JWKS          |
| `requireProof()`    | `Promise<StepUpProofPayload>`        | Validates a proof token or throws          |

The app must request the `step_up` scope during login before using these helpers.

### `verifyTokenWithJWKS(token, issuer, expectedTyp)`

Verifies a JWT using Gate’s public key (JWKS). Used internally by the SDK but available for manual verification.

| Parameter     | Type   | Required | Description                                        |
| ------------- | ------ | -------- | -------------------------------------------------- |
| `token`       | string | Yes      | JWT to verify                                      |
| `issuer`      | string | Yes      | Gate server URL                                    |
| `expectedTyp` | string | No       | Expected header type (e.g. `"st+jwt"`, `"at+jwt"`) |

### `clearJWKSCache(issuer)`

Clears the JWKS public key cache. Useful if Gate rotates its keys.

| Parameter | Type   | Required | Description                              |
| --------- | ------ | -------- | ---------------------------------------- |
| `issuer`  | string | No       | Issuer URL. If omitted, clears all cache |

## Exported types

All option interfaces and return types are exported for use in your own code:

```ts
import type {
  GateUser,
  SessionHelpers,
  SessionHelpersOptions,
  GateProxyOptions,
  LoginHandlerOptions,
  CallbackHandlerOptions,
  LogoutHandlerOptions,
  LoginUrlOptions,
  LogoutUrlOptions,
  AuthConfig,
  AuthConfigOptions,
} from "@am25/gate-next";
```

## Authentication flow

```
User            App (login/proxy)      Gate (IdP)           App (callback)
  |                  |                      |                      |
  | GET /dashboard   |                      |                      |
  | ---------------> |                      |                      |
  |                  |                      |                      |
  |                  | Create state, PKCE, nonce                    |
  |                  | Set transaction cookie                      |
  |                  | Redirect to Gate     |                      |
  | <--------------- |                      |                      |
  |                  |                      |                      |
  | Login on Gate                           |                      |
  | --------------------------------------->|                      |
  |                  |                      |                      |
  | Redirect with authorization code       |                      |
  | <---------------------------------------|                      |
  |                  |                      |                      |
  | GET /api/auth/callback?code=xxx&state=xxx                     |
  | -------------------------------------------------------------->|
  |                  |                      |                      |
  |                  |                      | POST /oauth/token    |
  |                  |                      | + code_verifier      |
  |                  |                      |<---------------------|
  |                  |                      |                      |
  |                  |                      | Returns tokens       |
  |                  |                      |--------------------->|
  |                  |                      |                      |
  | Validate state + nonce; consume transaction cookie             |
  | Set-Cookie: am25_sess (httpOnly, RS256)                       |
  | <--------------------------------------------------------------|
  |                  |                      |                      |
  | Redirect to /dashboard                                         |
  | ---------------> |                      |                      |
  |                  |                      |                      |
  |                  | Verify token (JWKS) |                      |
  |                  | -------------------> |                      |
  |                  |                      |                      |
  |                  | Public key (cache)  |                      |
  |                  | <------------------- |                      |
  |                  |                      |                      |
  | Page OK          |                      |                      |
  | <--------------- |                      |                      |
```

## Token verification (RS256)

The SDK verifies tokens using Gate’s public key obtained from the JWKS endpoint:

```
GET {issuer}/.well-known/jwks.json
```

- Only Gate has the private key (used to sign tokens)
- Apps only need the public key (used to verify tokens)
- The public key is automatically cached in memory

## Domain cookies

Apps share sessions by domain:

- Apps on `*.example.com` → cookie on `.example.com`
- Apps on `*.example.com` → cookie on `.example.com`

Each domain has its own session. They do not cross.

## Access control

Gate manages access at two levels:

**Per application:** In the Gate dashboard you configure which users can access each app. Administrators automatically have access to all apps. If an unauthorized user tries to authenticate, Gate returns a 403 error.

**Per app roles and permissions:** Each client app owns its own role and permission model. Gate only authenticates users and controls which users can access each app.

## Internal vs third-party clients

Gate distinguishes two types of OAuth clients:

| Type                       | Consent             | Use case                            |
| -------------------------- | ------------------- | ----------------------------------- |
| **Internal (first-party)** | No, auto-approved   | Apps within the AM25 ecosystem      |
| **Third-party**            | Yes, consent screen | External apps integrating with Gate |

Configured in the Gate dashboard when creating or editing a client.

## Compatibility with standard libraries

Gate is an OAuth 2.0 and OpenID Connect compatible Identity Provider. Besides this SDK, you can integrate it with any library that supports OIDC Discovery:

```
Discovery: {issuer}/.well-known/openid-configuration
JWKS:      {issuer}/.well-known/jwks.json
```
