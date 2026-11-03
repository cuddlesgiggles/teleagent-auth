import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { TeleAgentAuthPlugin } from "../index.mjs"

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
// a JWT that has not expired, so the trade's cache is exercised as it is live
const JWT = `eyJhbGciOiJIUzI1NiJ9.${b64({ exp: Math.floor(Date.now() / 1000) + 86_400, sub: "acct-1" })}.c2lnbmF0dXJlLXBhcnQ`

const jsonResponse = (body, status = 200, type = "application/json") =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": type } })

async function withFetch(mock, fn) {
  const real = globalThis.fetch
  globalThis.fetch = mock
  try {
    return await fn()
  } finally {
    globalThis.fetch = real
  }
}

test("checkin looks first, then claims, and reports the claim", async () => {
  const seen = []
  await withFetch(async (url, init) => {
    seen.push({ url: String(url), headers: init?.headers ?? {} })
    if (String(url).includes("checkDayTask")) return jsonResponse({ data: { daily_task: { claimed_today: false } } })
    return jsonResponse({ code: 0, message: "ok" })
  }, async () => {
    const p = await TeleAgentAuthPlugin({}, { token: JWT, deviceId: "aabbccddeeff", installId: "11111111-2222-4222-8222-333333333333" })
    const out = await p.auth.checkin(async () => ({ type: "api", key: JWT }))
    assert.deepEqual(out, { outcome: "claimed", message: "签到成功，积分已到账" })
    assert.equal(seen.length, 2)
    assert.match(seen[0].url, /\/v2\/checkDayTask$/)
    assert.match(seen[1].url, /\/checkTask\?type=daily_login$/)
    assert.equal(seen[0].headers["x-token"], JWT)
    assert.match(seen[0].headers.authorization, /^Bearer sk-/)
  })
})

test("checkin reports done without claiming when today is already done", async () => {
  const seen = []
  await withFetch(async (url) => {
    seen.push(String(url))
    return jsonResponse({ data: { daily_task: { claimed_today: true, continuous_days: 3, points: "100" } } })
  }, async () => {
    const p = await TeleAgentAuthPlugin({}, { token: JWT, deviceId: "aabbccddeeff", installId: "11111111-2222-4222-8222-333333333333" })
    const out = await p.auth.checkin(async () => ({ type: "api", key: JWT }))
    assert.equal(out.outcome, "done")
    assert.match(out.message, /100 积分/)
    assert.match(out.message, /连续 3 天/)
    assert.equal(seen.length, 1)
  })
})

test("checkin never takes an HTML 200 for a check-in", async () => {
  await withFetch(async () => new Response("<html>login</html>", {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  }), async () => {
    const p = await TeleAgentAuthPlugin({}, { token: JWT, deviceId: "aabbccddeeff", installId: "11111111-2222-4222-8222-333333333333" })
    const out = await p.auth.checkin(async () => ({ type: "api", key: JWT }))
    assert.equal(out.outcome, "failed")
    assert.match(out.message, /登录已失效/)
  })
})

test("a refused claim says what the portal said", async () => {
  await withFetch(async (url) => {
    if (String(url).includes("checkDayTask")) return jsonResponse({ data: { claimed_today: false } })
    return jsonResponse({ code: "500", message: "活动已结束" })
  }, async () => {
    const p = await TeleAgentAuthPlugin({}, { token: JWT, deviceId: "aabbccddeeff", installId: "11111111-2222-4222-8222-333333333333" })
    const out = await p.auth.checkin(async () => ({ type: "api", key: JWT }))
    assert.equal(out.outcome, "failed")
    assert.equal(out.message, "活动已结束")
  })
})

test("a pasted code is traded once and the JWT goes out on chat", async () => {
  const traded = `Em9xR4:${JWT}`
  const seen = []
  await withFetch(async (url, init) => {
    const u = String(url)
    seen.push({ url: u, headers: init?.headers ?? {} })
    if (u.includes("/cowork/auth?code=")) return jsonResponse({ data: { token: JWT, tenant: "Em9xR4" } })
    return jsonResponse({ ok: true })
  }, async () => {
    const p = await TeleAgentAuthPlugin({}, { home: "/definitely/not/here", appVersion: "2.7.0.000", deviceId: "aabbccddeeff", installId: "11111111-2222-4222-8222-333333333333" })
    const loader = await p.auth.loader(async () => ({ type: "api", key: "ucc.abc12345" }))
    const call = () => loader.fetch("https://agent.teleai.com.cn/superCowork/sapi/api/v1/chat/completions", {
      method: "POST",
      body: '{"messages":[]}',
    })
    await call()
    await call()
    assert.equal(seen.length, 3, "one trade and two chats")
    assert.match(seen[0].url, /\/cowork\/auth\?code=ucc\.abc12345$/)
    assert.equal(seen[1].headers.get("x-token"), traded)
    assert.equal(seen[2].headers.get("x-token"), traded)
  })
})

test("a machine without device-meta gets one saved pair across restarts", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ta-device-"))
  const file = join(dir, "device.json")
  const seen = []
  try {
    await withFetch(async (url, init) => {
      seen.push(init.headers)
      return jsonResponse({ ok: true })
    }, async () => {
      const call = async () => {
        const p = await TeleAgentAuthPlugin({}, { home: "/definitely/not/here", deviceFile: file })
        const loader = await p.auth.loader(async () => ({ type: "api", key: JWT }))
        await loader.fetch("https://agent.teleai.com.cn/superCowork/sapi/api/v1/chat/completions", {
          method: "POST",
          body: "{}",
        })
      }
      await call()
      await call()
    })
    assert.equal(seen.length, 2)
    const deviceId = seen[0].get("x-superagent-device-id")
    const installId = seen[0].get("x-superagent-install-id")
    assert.match(deviceId, /^[0-9a-f]{12}$/)
    assert.ok(installId)
    assert.equal(seen[1].get("x-superagent-device-id"), deviceId)
    assert.equal(seen[1].get("x-superagent-install-id"), installId)
    const saved = JSON.parse(readFileSync(file, "utf8"))
    assert.equal(saved.deviceId, deviceId)
    assert.equal(saved.installId, installId)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
