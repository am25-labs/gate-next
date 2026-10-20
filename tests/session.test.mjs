import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { SignJWT, jwtVerify } from "jose";
import ts from "typescript";

const issuer = "https://gate.test";
const ns = (name) => `${issuer}/${name}`;
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const source = ts.transpileModule(readFileSync(new URL("../src/lib/session.ts", import.meta.url), "utf8"), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;

async function fixture(t) {
  const issue = (claims = {}, { audience = "urn:am25:gate:session", type = "st+jwt" } = {}) => new SignJWT({ sub: "user", client_id: "portal", grant_id: "grant", sessionVersion: 2, email: "old@example.test", name: "Old", lastName: "Name", picture: "old.png", [ns("is_admin")]: true, [ns("organization_id")]: "old-org", [ns("organization_type")]: "INTERNAL", [ns("organization_role")]: "OWNER", ...claims }).setProtectedHeader({ alg: "RS256", typ: type }).setIssuedAt().setIssuer(issuer).setAudience(audience).setExpirationTime(claims.exp ?? "30d").sign(privateKey);
  const state = { token: await issue(), status: 200, fail: false, profile: { id: "user", email: "current@example.test", name: "Current", lastName: "Profile", profileImageUrl: null, isAdmin: false, organizationId: "new-org", organizationType: "CUSTOMER", organizationRole: "MEMBER" } };
  const makeStore = () => ({ get: (name) => name === "am25_sess" && state.token ? { value: state.token } : undefined });
  let store = makeStore();
  let verifications = 0;
  const requests = [];
  const mocks = {
    react: { cache: (fn) => fn },
    "next/headers": { cookies: async () => store },
    "./jwks.js": { verifyTokenWithJWKS: async (token, expectedIssuer, expectedType, options) => {
      verifications++;
      const { payload, protectedHeader } = await jwtVerify(token, publicKey, { ...options, issuer: expectedIssuer });
      if (protectedHeader.typ !== expectedType) throw new Error("Invalid token type");
      return payload;
    } },
  };
  const compiled = { exports: {} };
  new Function("require", "module", "exports", source)((name) => { if (!(name in mocks)) throw new Error(`Unexpected dependency: ${name}`); return mocks[name]; }, compiled, compiled.exports);
  t.mock.method(globalThis, "fetch", async (url, options) => {
    requests.push({ url, options });
    if (state.fail) throw new Error("Offline");
    return Response.json(state.profile, { status: state.status });
  });
  return { issue, state, requests, verifications: () => verifications, nextRequest: () => { store = makeStore(); }, helpers: compiled.exports.createSessionHelpers({ issuer: `${issuer}/`, clientId: "portal" }) };
}

test("one request shares a single active-session validation across concurrent helpers outside React rendering", async (t) => {
  const f = await fixture(t);
  const [session, user, authenticated, required] = await Promise.all([f.helpers.getSession(), f.helpers.getUser(), f.helpers.isAuthenticated(), f.helpers.requireAuth()]);
  assert.equal(authenticated, true); assert.deepEqual(required, user);
  assert.equal(user.email, "current@example.test"); assert.equal(user.name, "Current");
  assert.equal(user.picture, null); assert.equal(user.isAdmin, false);
  assert.equal(user.organizationId, "new-org"); assert.equal(user.organizationType, "CUSTOMER"); assert.equal(user.organizationRole, "MEMBER");
  assert.equal(session.grant_id, "grant"); assert.equal(session.sessionVersion, 2);
  assert.equal(session[ns("is_admin")], false); assert.equal(session[ns("organization_id")], "new-org");
  assert.equal(f.requests.length, 1); assert.equal(f.verifications(), 1);
  const request = f.requests[0];
  assert.equal(request.url, `${issuer}/api/auth/session?client_id=portal`);
  assert.equal(request.options.cache, "no-store");
  assert.equal(request.options.headers.Cookie, `am25_sess=${f.state.token}`);
});

test("a new HTTP request revalidates the same token and sees changed permissions and organization", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.helpers.requireAdmin(), /Not authorized/);
  f.state.profile.isAdmin = true;
  f.state.profile.organizationId = null; f.state.profile.organizationRole = null; f.state.profile.organizationType = null;
  f.nextRequest();
  const user = await f.helpers.requireAdmin();
  assert.equal(user.isAdmin, true); assert.equal(user.organizationId, null); assert.equal(user.organizationRole, null);
  assert.equal(f.requests.length, 2); assert.equal(f.verifications(), 2);
});

test("null profile values clear previous names, picture and organization instead of retaining JWT data", async (t) => {
  const f = await fixture(t);
  Object.assign(f.state.profile, { name: null, lastName: null, profileImageUrl: null, organizationId: null, organizationType: null, organizationRole: null });
  const user = await f.helpers.getUser();
  assert.equal(user.name, ""); assert.equal(user.lastName, ""); assert.equal(user.picture, null);
  assert.equal(user.organizationId, null); assert.equal(user.organizationType, null); assert.equal(user.organizationRole, null);
});

test("a cookie change within one request invalidates its memoized validation", async (t) => {
  const f = await fixture(t);
  await f.helpers.getUser();
  f.state.token = await f.issue({ sub: "other" }); f.state.profile.id = "other";
  assert.equal((await f.helpers.getUser()).id, "other");
  assert.equal(f.requests.length, 2);
  f.state.token = null;
  assert.equal(await f.helpers.getSession(), null);
});

test("wrong-client, wrong-audience, wrong-type and expired cookies cannot reach session validation", async (t) => {
  const f = await fixture(t);
  for (const token of ["forged", await f.issue({ client_id: "other" }), await f.issue({}, { audience: "other" }), await f.issue({}, { type: "at+jwt" }), await f.issue({ exp: Math.floor(Date.now() / 1000) - 1 })]) {
    f.state.token = token; f.nextRequest();
    assert.equal(await f.helpers.getUser(), null);
  }
  assert.equal(f.requests.length, 0);
});

test("revoked, denied and unavailable sessions fail closed without falling back to JWT admin claims", async (t) => {
  const f = await fixture(t);
  for (const status of [401, 403, 503]) {
    f.nextRequest(); f.state.status = status;
    assert.equal(await f.helpers.getSession(), null);
    await assert.rejects(f.helpers.requireAdmin(), /Not authenticated/);
  }
  f.nextRequest(); f.state.fail = true;
  assert.equal(await f.helpers.getUser(), null);
});

test("malformed, incomplete and mismatched current profiles are rejected", async (t) => {
  const f = await fixture(t); const profile = f.state.profile;
  for (const current of [null, {}, { ...profile, id: "another-user" }, { ...profile, isAdmin: "true" }, { ...profile, organizationType: "unknown" }, { ...profile, organizationRole: "ADMIN" }, { ...profile, email: undefined }, { ...profile, profileImageUrl: undefined }]) {
    f.nextRequest(); f.state.profile = current;
    assert.equal(await f.helpers.getSession(), null);
  }
});
