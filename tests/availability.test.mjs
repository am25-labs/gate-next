import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";
import { createLoader } from "./load.mjs";

const require = createRequire(import.meta.url);
const { NextRequest, NextResponse } = require("next/server");
const issuer = "https://gate.test";
const options = { issuer, clientId: "portal", clientSecret: "secret", redirectUri: "https://portal.test/api/auth/callback", protectedPaths: ["/dashboard"] };
const profile = { id: "user", email: "current@example.test", name: "Current", lastName: "User", profileImageUrl: null, isAdmin: false, organizationId: null, organizationType: null, organizationRole: null };

function fixture(t) {
  const jar = new Map([["am25_sess", "session"], ["am25_at", "access"]]);
  const state = { mode: "ok", status: 200, keysUnavailable: false, claims: { sub: "user", client_id: "portal" }, body: profile, nonce: undefined };
  const requests = [];
  const cookieStore = { get: (name) => jar.has(name) ? { value: jar.get(name) } : undefined };
  let GateUnavailableError;
  const jwks = { verifyTokenWithJWKS: async () => {
    if (state.keysUnavailable) throw new GateUnavailableError();
    return { ...state.claims, nonce: state.nonce };
  } };
  const load = createLoader({
    "next/server": { NextRequest, NextResponse }, "next/headers": { cookies: async () => cookieStore },
    "./jwks.js": jwks, "./lib/jwks.js": jwks, "../lib/jwks.js": jwks,
    react: { cache: (fn) => fn },
  });
  ({ GateUnavailableError } = load("lib/errors.ts"));
  t.mock.method(globalThis, "fetch", async (url, config) => {
    requests.push({ url, config });
    assert.ok(config.signal instanceof AbortSignal); assert.equal(config.cache, "no-store"); assert.equal(config.redirect, "error");
    if (state.mode === "offline") throw new Error("Offline");
    if (state.mode === "invalid-json") return new Response("invalid JSON");
    return Response.json(state.body, { status: state.status });
  });
  const request = (path) => new NextRequest(`https://portal.test${path}`, { headers: { Cookie: [...jar].map(([key, value]) => `${key}=${value}`).join("; ") } });
  const unavailable = async (response) => {
    assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: "gate_unavailable" });
    assert.equal(response.headers.get("cache-control"), "no-store"); assert.equal(response.headers.get("retry-after"), "5");
    assert.equal(response.headers.has("location"), false); assert.equal(response.headers.has("set-cookie"), false);
  };
  return { state, requests, jar, request, load, unavailable, GateUnavailableError };
}

test("proxy outages return 503 without redirects or cookie changes and recover on the next request", async (t) => {
  const f = fixture(t); const proxy = f.load("proxy.ts").createGateProxy(options);
  for (const status of [408, 429, 500, 502, 503, 504, 400]) {
    f.state.status = status;
    await f.unavailable(await proxy(f.request("/dashboard?tab=files")));
  }
  f.state.status = 200; f.state.mode = "offline";
  await f.unavailable(await proxy(f.request("/dashboard")));
  f.state.mode = "invalid-json";
  await f.unavailable(await proxy(f.request("/dashboard")));
  f.state.mode = "ok"; f.state.keysUnavailable = true;
  await f.unavailable(await proxy(f.request("/dashboard")));
  f.state.keysUnavailable = false; f.state.body = { id: "another-user" };
  await f.unavailable(await proxy(f.request("/dashboard")));
  f.state.body = profile;
  assert.equal(await proxy(f.request("/dashboard")), null);
});

test("the proxy retains real unauthenticated and denied-access flows and bypasses public paths", async (t) => {
  const f = fixture(t); const proxy = f.load("proxy.ts").createGateProxy(options);
  assert.equal(await proxy(f.request("/public")), null); assert.equal(f.requests.length, 0);
  f.state.status = 401;
  assert.equal(new URL((await proxy(f.request("/dashboard"))).headers.get("location")).pathname, "/oauth/authorize");
  f.state.status = 403;
  assert.equal((await proxy(f.request("/dashboard"))).headers.get("location"), "https://gate.test/unauthorized");
  const before = f.requests.length;
  f.state.claims.client_id = "another-app";
  assert.equal(new URL((await proxy(f.request("/dashboard"))).headers.get("location")).pathname, "/oauth/authorize");
  assert.equal(f.requests.length, before);
});

test("concurrent helpers share a typed outage within one request", async (t) => {
  const f = fixture(t); f.state.status = 503;
  const helpers = f.load("lib/session.ts").createSessionHelpers(options);
  const results = await Promise.allSettled([helpers.getSession(), helpers.getUser(), helpers.isAuthenticated()]);
  assert.ok(results.every((result) => result.status === "rejected" && result.reason instanceof f.GateUnavailableError));
  assert.equal(f.requests.length, 1);
  assert.equal(results[0].reason.status, 503); assert.equal(results[0].reason.code, "gate_unavailable");
});

test("directory outages never invoke a synchronization callback with an empty fallback", async (t) => {
  const f = fixture(t); f.state.status = 503;
  const helpers = f.load("lib/users.ts").createUserHelpers(options);
  let writes = 0;
  await assert.rejects(helpers.syncUsers(async () => { writes++; }), f.GateUnavailableError);
  assert.equal(writes, 0);
  f.state.status = 200; f.state.body = { users: [] };
  assert.deepEqual(await helpers.syncUsers(async () => { writes++; }), []);
  assert.equal(writes, 1);
  f.state.body = {};
  await assert.rejects(helpers.getUsers(), f.GateUnavailableError);
});

test("userinfo and step-up propagate outages while authorization failures remain distinct", async (t) => {
  const f = fixture(t); f.state.status = 503;
  const access = f.load("lib/access-token.ts").verifyActiveAccessToken;
  await assert.rejects(access("access", options), f.GateUnavailableError);
  f.state.status = 401;
  await assert.rejects(access("access", options), (error) => !(error instanceof f.GateUnavailableError));
  f.state.status = 200; f.state.mode = "invalid-json";
  await assert.rejects(access("access", options), f.GateUnavailableError);
  f.state.mode = "ok";
  const stepUp = f.load("lib/step-up.ts").createStepUpHelpers(options);
  for (const status of [503, 429]) {
    f.state.status = status;
    await assert.rejects(stepUp.createChallenge({ action: "delete" }), f.GateUnavailableError);
    await assert.rejects(stepUp.verifyChallenge({ challengeToken: "challenge", code: "123456" }), f.GateUnavailableError);
    await assert.rejects(stepUp.verifyOtp({ action: "delete", code: "123456" }), f.GateUnavailableError);
  }
  f.state.keysUnavailable = true;
  await assert.rejects(stepUp.verifyProof("proof", { action: "delete" }), f.GateUnavailableError);
  f.state.keysUnavailable = false;
  assert.equal(await stepUp.verifyProof("proof", { action: "delete" }), null);
});

test("callback outages preserve the OAuth transaction and logout outages preserve app cookies", async (t) => {
  const f = fixture(t);
  const login = await f.load("handlers/login.ts").createLoginHandler(options)(f.request("/api/auth/login?returnTo=%2Fdashboard"));
  for (const cookie of login.cookies.getAll()) f.jar.set(cookie.name, cookie.value);
  const loginUrl = new URL(login.headers.get("location")); f.state.nonce = loginUrl.searchParams.get("nonce");
  const state = loginUrl.searchParams.get("state");
  const callback = f.load("handlers/callback.ts").createCallbackHandler(options);
  f.state.status = 503;
  await f.unavailable(await callback(f.request(`/api/auth/callback?code=code&state=${state}`)));
  const logout = f.load("handlers/logout.ts").createLogoutHandler(options);
  await f.unavailable(await logout());
  f.state.status = 200; f.state.body = { session_token: "new-session", access_token: "new-access", id_token: "id" };
  const response = await callback(f.request(`/api/auth/callback?code=code&state=${state}`));
  assert.equal(response.headers.get("location"), "https://portal.test/dashboard");
  assert.equal(response.cookies.get("am25_sess").value, "new-session");
  assert.equal(response.cookies.get("am25_at").value, "new-access");
  const loggedOut = await logout();
  assert.equal(new URL(loggedOut.headers.get("location")).pathname, "/oauth/logout");
  assert.equal(loggedOut.cookies.get("am25_sess").maxAge, 0);
});

test("the transport deadline aborts a stalled request body without retrying a mutation", async (t) => {
  const load = createLoader();
  const { fetchGate, readGateJson } = load("lib/request.ts"); const { GateUnavailableError } = load("lib/errors.ts");
  t.mock.method(AbortSignal, "timeout", (duration) => {
    assert.equal(duration, 10_000);
    const controller = new AbortController();
    setTimeout(() => controller.abort(new DOMException("Timed out", "TimeoutError")), 5);
    return controller.signal;
  });
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (_url, options) => {
    calls++;
    return new Response(new ReadableStream({ start(controller) {
      options.signal.addEventListener("abort", () => controller.error(options.signal.reason), { once: true });
    } }));
  });
  const response = await fetchGate("https://gate.test/oauth/token", { method: "POST", body: "code=code" });
  await assert.rejects(readGateJson(response), GateUnavailableError);
  assert.equal(calls, 1);
});

test("JWKS outages are typed availability errors while expired or forged tokens remain authorization errors", async () => {
  const jose = require("jose");
  let failure; let timeout;
  const load = createLoader({ jose: { ...jose,
    createRemoteJWKSet: (_url, options) => { timeout = options.timeoutDuration; return () => {}; },
    jwtVerify: async () => { if (failure) throw failure; return { payload: { sub: "user" }, protectedHeader: { typ: "st+jwt" } }; },
  } });
  const { verifyTokenWithJWKS } = load("lib/jwks.ts"); const { GateUnavailableError } = load("lib/errors.ts");
  for (failure of [new Error("Offline"), new jose.errors.JWKSTimeout(), new jose.errors.JWKSInvalid("Invalid keys")]) {
    await assert.rejects(verifyTokenWithJWKS("token", issuer, "st+jwt"), GateUnavailableError);
  }
  for (failure of [new jose.errors.JWTExpired("Expired"), new jose.errors.JWSSignatureVerificationFailed(), new jose.errors.JWTInvalid("Invalid")]) {
    await assert.rejects(verifyTokenWithJWKS("token", issuer, "st+jwt"), (error) => !(error instanceof GateUnavailableError));
  }
  failure = null;
  assert.equal((await verifyTokenWithJWKS("token", issuer, "st+jwt")).sub, "user");
  assert.equal(timeout, 10_000);
});
