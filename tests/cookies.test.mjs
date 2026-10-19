import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL("../src/", import.meta.url));
function fixture(t) {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "production";
  t.after(() => { if (previous === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous; });
  const jar = new Map();
  const requests = [];
  let nonce;
  const response = (status, location) => ({ status, location, writes: [], cookies: { set(name, value, options) { this.owner.writes.push({ name, value, options }); } } });
  const redirect = (url) => { const result = response(307, new URL(url)); result.cookies.owner = result; return result; };
  const mocks = {
    "next/server": { NextResponse: { redirect, json: (body, { status }) => ({ status, body }) } },
    "next/headers": { cookies: async () => ({ get: (name) => jar.has(name) ? { value: jar.get(name) } : undefined }) },
  };
  const cache = new Map();
  function load(file) {
    const path = resolve(root, file);
    if (cache.has(path)) return cache.get(path);
    const { outputText } = ts.transpileModule(readFileSync(path, "utf8"), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } });
    const compiled = { exports: {} };
    new Function("require", "module", "exports", outputText)((name) => {
      if (name in mocks) return mocks[name];
      if (name.endsWith("jwks.js")) return { verifyTokenWithJWKS: async (_token, issuer, _type, options) => {
        assert.equal(issuer, "https://gate.example");
        assert.equal(options.audience, "portal");
        return { nonce };
      } };
      if (name.startsWith(".")) return load(resolve(dirname(path), name.replace(/\.js$/, ".ts")));
      return require(name);
    }, compiled, compiled.exports);
    cache.set(path, compiled.exports);
    return compiled.exports;
  }
  t.mock.method(globalThis, "fetch", async (url, options) => {
    requests.push({ url, options });
    return url.endsWith("/oauth/revoke") ? new Response(null, { status: 200 }) : Response.json({ session_token: "session", access_token: "access", id_token: "id" });
  });
  const options = { issuer: "https://gate.example", clientId: "portal", clientSecret: "test-secret", redirectUri: "https://portal.example/api/auth/callback", cookieDomain: ".example" };
  const request = (url) => ({ nextUrl: new URL(url), cookies: { get: (name) => jar.has(name) ? { value: jar.get(name) } : undefined } });
  return {
    load, jar, requests, options, request,
    login: async () => {
      const handler = load("handlers/login.ts").createLoginHandler(options);
      const result = await handler(request("https://portal.example/api/auth/login?returnTo=%2Fportal%2Fclient"));
      for (const cookie of result.writes) jar.set(cookie.name, cookie.value);
      nonce = result.location.searchParams.get("nonce");
      return result;
    },
  };
}
function assertHostOnly(cookie) {
  assert.equal(Object.hasOwn(cookie.options, "domain"), false);
  assert.equal(cookie.options.httpOnly, true);
  assert.equal(cookie.options.secure, true);
  assert.equal(cookie.options.sameSite, "lax");
  assert.equal(cookie.options.path, "/");
}

test("login and callback retain PKCE and nonce while issuing only host-bound cookies", async (t) => {
  const f = fixture(t);
  const login = await f.login();
  assert.equal(login.location.origin, "https://gate.example");
  assert.equal(login.location.pathname, "/oauth/authorize");
  assert.equal(login.location.searchParams.get("code_challenge_method"), "S256");
  assertHostOnly(login.writes[0]);
  assert.ok(login.writes[0].name.startsWith("__Host-"));
  const state = login.location.searchParams.get("state");
  const callback = f.load("handlers/callback.ts").createCallbackHandler(f.options);
  const result = await callback(f.request(`https://portal.example/api/auth/callback?code=test-code&state=${state}`));
  assert.equal(result.location.href, "https://portal.example/portal/client");
  const cookies = result.writes.filter((cookie) => ["am25_sess", "am25_at"].includes(cookie.name));
  assert.equal(cookies.length, 2);
  cookies.forEach(assertHostOnly);
  assert.equal(cookies.find((cookie) => cookie.name === "am25_at").options.maxAge, 3600);
  const exchange = f.requests[0];
  assert.equal(exchange.url, "https://gate.example/oauth/token");
  assert.equal(exchange.options.body.get("client_id"), "portal");
  assert.match(exchange.options.body.get("code_verifier"), /^[A-Za-z0-9_-]{43}$/);
  assert.equal(result.writes[0].options.maxAge, 0);
});

test("callback rejects an unbound state before exchanging credentials", async (t) => {
  const f = fixture(t);
  const callback = f.load("handlers/callback.ts").createCallbackHandler(f.options);
  const result = await callback(f.request("https://portal.example/api/auth/callback?code=test-code&state=unknown"));
  assert.equal(result.location.searchParams.get("error"), "invalid_oauth_state");
  assert.equal(f.requests.length, 0);
  assert.equal(result.writes.length, 0);
});

test("logout retains revocation and the Gate redirect while expiring only host-bound app cookies", async (t) => {
  const f = fixture(t);
  f.jar.set("am25_at", "access");
  f.jar.set("am25_sess", "session");
  const handler = f.load("handlers/logout.ts").createLogoutHandler(f.options);
  const result = await handler();
  assert.equal(f.requests[0].url, "https://gate.example/oauth/revoke");
  assert.equal(f.requests[0].options.body.get("token"), "access");
  assert.equal(f.requests[0].options.body.get("client_id"), "portal");
  assert.equal(result.location.origin, "https://gate.example");
  assert.equal(result.location.pathname, "/oauth/logout");
  assert.equal(result.location.searchParams.get("redirect_uri"), "https://portal.example/");
  assert.deepEqual(result.writes.map((cookie) => cookie.name), ["am25_sess", "am25_at"]);
  for (const cookie of result.writes) {
    assertHostOnly(cookie);
    assert.equal(cookie.value, "");
    assert.equal(cookie.options.maxAge, 0);
  }
});
