import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, mkdirSync, writeFileSync, utimesSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  CHECKIN,
  accountIdFromToken,
  exchangeCode,
  jwtClaims,
  jwtExpiryMs,
  needsSignIn,
  parseCheckTask,
  parseCredential,
  parseDayTask,
  parseExchange,
  tokenFileFor,
} from "../teleagent.mjs"

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
const JWT = `eyJhbGciOiJIUzI1NiJ9.${b64({ exp: 1760000000, sub: "acct-1" })}.c2lnbmF0dXJlLXBhcnQ`

test("parseCredential reads a callback URL, a bare token, and a code", () => {
  assert.deepEqual(parseCredential(`https://agent.teleai.com.cn/x/cowork/auth?code=ucc.abc12345&state=s`), { kind: "code", value: "ucc.abc12345" })
  assert.deepEqual(parseCredential(`https://agent.teleai.com.cn/x/cowork/auth?token=${JWT}`), { kind: "token", value: JWT })
  assert.deepEqual(parseCredential(`Em9xR4:${JWT}`), { kind: "token", value: `Em9xR4:${JWT}` })
  assert.deepEqual(parseCredential(JWT), { kind: "token", value: JWT })
  assert.deepEqual(parseCredential("ucc.0123456789abcdef"), { kind: "code", value: "ucc.0123456789abcdef" })
  // a short grant has no second long segment; only the ucc form names it
  assert.deepEqual(parseCredential("ucc.abc12345"), { kind: "code", value: "ucc.abc12345" })
  assert.deepEqual(parseCredential("abcd.0123456789abcdef0123"), { kind: "code", value: "abcd.0123456789abcdef0123" })
  // a callback URL with neither is not a credential
  assert.equal(parseCredential("https://agent.teleai.com.cn/x/cowork/auth?state=s"), null)
  assert.equal(parseCredential("hello world"), null)
  assert.equal(parseCredential(""), null)
  assert.equal(parseCredential(null), null)
})

test("parseExchange takes the token from JSON, a bare body or Location", () => {
  assert.deepEqual(
    parseExchange(JSON.stringify({ data: { token: JWT, deviceId: "d1", installId: "i1" } }), ""),
    { token: JWT, deviceId: "d1", installId: "i1", tenant: "", error: "" },
  )
  // a tenant the answer names goes back in front of a bare JWT
  assert.equal(parseExchange(JSON.stringify({ token: JWT, tenant: "Em9xR4" }), "").token, `Em9xR4:${JWT}`)
  // a token that already carries a tenant is not doubled
  assert.equal(parseExchange(JSON.stringify({ token: `Em9xR4:${JWT}` }), "").token, `Em9xR4:${JWT}`)
  assert.equal(parseExchange(`<html>${JWT}</html>`, "").token, JWT)
  assert.equal(parseExchange("", `https://agent.teleai.com.cn/cb?token=${JWT}`).token, JWT)
  const bad = parseExchange(JSON.stringify({ error: "code expired" }), "")
  assert.equal(bad.token, "")
  assert.equal(bad.error, "code expired")
})

test("exchangeCode trades the code at /cowork/auth and never sends it anywhere else", async () => {
  const seen = []
  const fetchImpl = async (url, init) => {
    seen.push({ url, init })
    return new Response(JSON.stringify({ data: { token: JWT, tenant: "Em9xR4" } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })
  }
  const out = await exchangeCode("ucc.abc12345", { fetchImpl })
  assert.equal(out.token, `Em9xR4:${JWT}`)
  assert.equal(seen.length, 1)
  assert.equal(
    seen[0].url,
    "https://agent.teleai.com.cn/superCowork/sapi/cowork/auth?code=ucc.abc12345",
  )
  assert.match(seen[0].init.headers["user-agent"], /Mozilla/)
})

test("exchangeCode says the HTTP status when no token comes back", async () => {
  const fetchImpl = async () => new Response(JSON.stringify({ code: "4001", message: "当前令牌是否存在" }), {
    status: 401,
    headers: { "content-type": "application/json" },
  })
  await assert.rejects(() => exchangeCode("ucc.dead", { fetchImpl }), /HTTP 401/)
  await assert.rejects(() => exchangeCode("  ", { fetchImpl }), /code/)
})

test("jwtClaims reads a bare JWT and one behind a tenant prefix, without verifying", () => {
  assert.equal(jwtClaims(JWT).sub, "acct-1")
  assert.equal(jwtClaims(`Em9xR4:${JWT}`).sub, "acct-1")
  assert.equal(jwtClaims("not-a-jwt"), null)
  assert.equal(jwtClaims("a.b.c"), null)
})

test("jwtExpiryMs turns exp seconds into the milliseconds magpie keeps", () => {
  assert.equal(jwtExpiryMs(JWT), 1_760_000_000_000)
  assert.equal(jwtExpiryMs(`Em9xR4:${JWT}`), 1_760_000_000_000)
  assert.equal(jwtExpiryMs("nope"), 0)
  assert.equal(jwtExpiryMs(`h.${b64({})}.s`), 0)
})

test("accountIdFromToken prefers the claim's own account name", () => {
  assert.equal(accountIdFromToken(JWT), "acct-1")
  const numeric = `h.${b64({ uid: 12345 })}.s`
  assert.equal(accountIdFromToken(numeric), "12345")
  const anonymous = `h.${b64({ exp: 1 })}.s`
  assert.match(accountIdFromToken(anonymous), /^web-[0-9a-f]{12}$/)
})

test("tokenFileFor picks the account a seat names, and refuses an account it no longer holds", () => {
  const root = mkdtempSync(join(tmpdir(), "ta-creds-"))
  try {
    const make = (name, at) => {
      const dir = join(root, "users", name, "app-auth")
      mkdirSync(dir, { recursive: true })
      const f = join(dir, "token.json")
      writeFileSync(f, "{}")
      utimesSync(f, new Date(at), new Date(at))
      return f
    }
    const a = make("v1_public_A", 1_700_000_000_000)
    const b = make("v1_public_B", 1_700_000_100_000)

    assert.equal(tokenFileFor("/home/x", root, "A").file, a)
    assert.equal(tokenFileFor("/home/x", root, "v1_public_A").file, a)
    assert.equal(tokenFileFor("/home/x", root, "B").file, b)
    // no name means the newest sign-in
    assert.equal(tokenFileFor("/home/x", root).file, b)
    // an account the app no longer holds is not replaced by another's token
    assert.equal(tokenFileFor("/home/x", root, "GONE"), null)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test("parseDayTask reads both nestings the portal has answered with", () => {
  const nested = parseDayTask({
    code: "0",
    data: { daily_task: { claimed_today: true, continuous_days: 4, points: "100" } },
  })
  assert.deepEqual(nested, { claimed: true, streak: 4, points: "100" })
  const flat = parseDayTask({ data: { claimed_today: false, days: 2, points: 50 } })
  assert.deepEqual(flat, { claimed: false, streak: 2, points: "50" })
  // a field the vendor sends as null says nothing, not false or zero
  const none = parseDayTask({ data: { claimed_today: null, continuous_days: null } })
  assert.deepEqual(none, { claimed: false, streak: 0, points: "" })
})

test("parseCheckTask counts 0 and 200 as done and anything else as refused", () => {
  assert.deepEqual(parseCheckTask({ code: 0 }), { ok: true, code: "0", message: "" })
  assert.deepEqual(parseCheckTask({ code: "200", message: "ok" }), { ok: true, code: "200", message: "ok" })
  assert.equal(parseCheckTask({}).ok, true)
  const bad = parseCheckTask({ code: "500", message: "活动已结束" })
  assert.equal(bad.ok, false)
  assert.equal(bad.message, "活动已结束")
})

test("needsSignIn treats an HTML or non-JSON 200 as a lost sign-in", () => {
  assert.equal(needsSignIn(200, "text/html; charset=utf-8", "<!doctype html>"), true)
  assert.equal(needsSignIn(200, "", "<html>"), true)
  assert.equal(needsSignIn(200, "text/plain", "not json"), true)
  assert.equal(needsSignIn(200, "application/json", "{}"), false)
  assert.equal(needsSignIn(200, "", "{}"), false)
  assert.equal(needsSignIn(200, "", '[{"code":0}]'), false)
  assert.equal(needsSignIn(200, "", "bad gateway"), true)
  assert.equal(needsSignIn(401, "application/json", '{"code":4001}'), true)
  assert.equal(needsSignIn(403, "application/json", "{}"), true)
})

test("the check-in paths are the portal's, under the same gateway", () => {
  assert.equal(CHECKIN.dayTask, "https://agent.teleai.com.cn/superCowork/sapi/user/portal/companyStore/v2/checkDayTask")
  assert.equal(CHECKIN.claim, "https://agent.teleai.com.cn/superCowork/sapi/user/portal/companyStore/checkTask")
  assert.equal(CHECKIN.claimType, "daily_login")
})
