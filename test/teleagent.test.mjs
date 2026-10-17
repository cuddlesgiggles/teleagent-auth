import { test } from "node:test"
import assert from "node:assert/strict"
import { createCipheriv, randomBytes } from "node:crypto"
import { join } from "node:path"
import { BASE, NPM, PROVIDER, SAPI, appVersion, catalogFile, configModels, deviceMeta, gatewayHeaders, hmacHex, isoBeijing, jwtThirdSegment, mergedModels, modelOf, osType, parseLive, parseLocal, parsePoints, pathsFor, sha256Hex, signInOf, signChatHeaders, userDirs, versionFromLogs } from "../teleagent.mjs"
import { encryptedKey, unwrap } from "../safestore.mjs"

const NOW = Date.parse("2026-10-17T04:00:00Z") // 2026-10-17 12:00 北京时间

// the package ships no relay key; the tests run against a placeholder of the same shape
process.env.TELEAGENT_RELAY_KEY = "sk-placeholder-relay-key"

test("the gateway needs its five over the relay key; the chat sends the app's own group", () => {
  const g = gatewayHeaders({ token: "T", appVersion: "2.7.0.000", os: "Windows", now: NOW, nonce: "N" })
  assert.deepEqual(Object.keys(g).sort(), ["authorization", "x-app-version", "x-nonce", "x-os-type", "x-route-target", "x-timestamp", "x-token"])
  assert.equal(g["x-token"], "T")
  assert.equal(g["x-timestamp"], String(NOW / 1000))
  assert.equal(g["x-nonce"], "N")
  assert.equal(g["x-app-version"], "2.7.0.000")
  assert.equal(g["x-os-type"], "Windows")
  assert.match(g.authorization, /^Bearer sk-/)
  // the edge reads a mixed group as an attack: no X-SuperAgent on the gateway path
  assert.deepEqual(Object.keys(g).filter((k) => k.startsWith("x-superagent")), [])

  const r = signChatHeaders({ token: "T", method: "POST", path: "/p", body: "", ts: "1760000000", nonce: "N", appVersion: "2.7.0.000", deviceId: "D", installId: "I" })
  assert.deepEqual(Object.keys(r).sort(), ["authorization", "x-app-version", "x-route-target", "x-superagent-device-id", "x-superagent-install-id", "x-superagent-nonce", "x-superagent-sign-version", "x-superagent-signature", "x-superagent-timestamp", "x-token"])
  assert.equal(r["x-superagent-device-id"], "D")
  assert.equal(r["x-superagent-install-id"], "I")
  assert.equal(r["x-superagent-sign-version"], "v1")
  // the edge reads a mixed group as an attack: the gateway's own three must stay off
  assert.deepEqual(Object.keys(r).filter((k) => k === "x-nonce" || k === "x-timestamp" || k === "x-os-type"), [])
  const bare = signChatHeaders({ token: "T", method: "POST", path: "/p", body: "", ts: "1760000000", nonce: "N", appVersion: "2.7.0.000", deviceId: "", installId: "" })
  assert.deepEqual(Object.keys(bare).filter((k) => k.includes("device") || k.includes("install")), [])
  assert.deepEqual(deviceMeta(pathsFor("/nope").root), { deviceId: "", installId: "" })
})

test("no relay key in the package: the headers ask for it instead of shipping one", () => {
  const saved = process.env.TELEAGENT_RELAY_KEY
  delete process.env.TELEAGENT_RELAY_KEY
  assert.throws(() => gatewayHeaders({ token: "T", appVersion: "2.7.0.000", os: "Windows", now: NOW, nonce: "N" }), /TELEAGENT_RELAY_KEY/)
  assert.throws(() => signChatHeaders({ ...SIGN_KAT, method: "POST", body: "", deviceId: "D" }), /TELEAGENT_RELAY_KEY/)
  process.env.TELEAGENT_RELAY_KEY = saved
  assert.equal(gatewayHeaders({ token: "T", appVersion: "2.7.0.000", os: "Windows", now: NOW, nonce: "N" }).authorization, "Bearer sk-placeholder-relay-key")
})

// ── the signature: einoprovider.(*GatewaySigner).Sign ─────────────────────────
// Expected values computed independently (Python's hmac/hashlib over the same
// field order read out of the binary); if any separator, field or order in the
// implementation moves, these go red.
const SIGN_KAT = {
  token: "aGVhZGVy.cGF5bG9hZA.c2lnLXBhcnQ",
  installId: "11111111-2222-4222-8222-333333333333",
  ts: "1760000000",
  nonce: "11111111-2222-3333-4444-555555555555",
  appVersion: "2.7.0.000",
  path: "/superCowork/sapi/api/v1/chat/completions",
}
const signOf = (method, body) =>
  signChatHeaders({ ...SIGN_KAT, method, body, deviceId: "000000abcdef" })["x-superagent-signature"]

test("chat signature: two HMAC-SHA256 over the pinned field order, lowercase hex", () => {
  assert.equal(jwtThirdSegment(SIGN_KAT.token), "c2lnLXBhcnQ")
  // not a JWS ⇒ the whole token is the key, which is what jwtThirdSegment does
  assert.equal(jwtThirdSegment("a.b"), "a.b")
  assert.equal(sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  assert.equal(hmacHex("k", "m").length, 64)
  assert.equal(signOf("post", '{"model":"chat-flash","messages":[]}'), "be75086523a841e6c0836a88a5ed38b51c44a8d2cdfbf2ed0833f175840e21b2")
  // the method is upper-cased before joining, so "post" and "POST" must agree
  assert.equal(signOf("POST", '{"model":"chat-flash","messages":[]}'), signOf("post", '{"model":"chat-flash","messages":[]}'))
  // UTF-8 bytes, not the JS string length or a widened encoding
  assert.equal(signOf("POST", Buffer.from('{"messages":[{"role":"user","content":"你好"}]}', "utf8")), "d75dd30168f0a0cd92703305084f0e8e5ab791f82f3903359dda271f4add941f")
  // empty body, and a path that carries its query (url.RequestURI)
  assert.equal(
    signChatHeaders({ ...SIGN_KAT, method: "GET", path: SIGN_KAT.path + "/model-options?language=zh-CN", body: "", deviceId: "D" })["x-superagent-signature"],
    "45196173c21de463d8b56c6a0f9ff1ead627c5b28835b6bcb763cdec5110a6fc",
  )
  assert.notEqual(signOf("POST", "{}"), signOf("POST", '{"a":1}'))
  assert.notEqual(signOf("POST", "{}"), signChatHeaders({ ...SIGN_KAT, method: "POST", path: SIGN_KAT.path + "?x=1", body: "{}", deviceId: "D" })["x-superagent-signature"])
})

test("osType names the platform the way the app does", () => {
  assert.equal(osType("win32"), "Windows")
  assert.equal(osType("darwin"), "macOS")
  assert.equal(osType("linux"), "linux")
})

test("versionFromLogs reads the running build off electron-log's own names", () => {
  const names = ["main-2026-10-15-v-2.7.0.000.log", "main-2026-10-17-v-2.8.1.log", "main-2026-09-30-v-2.6.0.log"]
  assert.equal(versionFromLogs(names), "2.8.1")
  assert.equal(versionFromLogs([]), null)
  assert.equal(versionFromLogs(["main.log"]), null)
  assert.equal(appVersion(pathsFor("/nope").root), "2.7.0.000")
})

test("both catalog shapes parse: live says points_multiplier, the cache says creditMultiplier", () => {
  const live = parseLive({ data: { models: [
    { model: "chat-pro", display_name: "智能", category_name: "预置模型", is_default: true, points_multiplier: "0.6", context_limit: null },
    { model: "chat-flash", display_name: "极速", points_multiplier: "0.2" },
    { not_a_model: 1 },
  ] } })
  assert.equal(live.length, 2)
  assert.deepEqual({ id: live[0].id, name: live[0].name, rate: live[0].rate, default: live[0].default }, { id: "chat-pro", name: "智能", rate: 0.6, default: true })
  assert.equal(live[0].context, undefined)

  const local = parseLocal({ state: { catalog: { groups: [
    { title: "预置模型", category: "preset", models: [
      { modelID: "chat-pro", displayName: "智能", limits: { context: 400000, output: 65536 }, creditMultiplier: "0.6", isDefault: true, behavior: { toolStream: true } },
      { modelID: "chat-flagship", displayName: "旗舰", limits: { context: 400000, output: 65536 }, creditMultiplier: "1.0" },
    ] },
  ] } } })
  assert.equal(local.length, 2)
  assert.equal(local[0].context, 400000)
  assert.equal(local[0].output, 65536)
  assert.equal(local[0].toolStream, true)

  // live is what the account has now; local fills the limits live carries none of
  const merged = mergedModels(live, local)
  assert.deepEqual(merged.map((m) => m.id), ["chat-pro", "chat-flash"])
  assert.equal(merged[0].context, 400000)
  assert.equal(merged[0].output, 65536)
  assert.equal(merged[0].name, "智能")
  assert.equal(mergedModels([], local).length, 2)
})

test("modelOf gives magpie the fields it reads: rate, free, api, limits", () => {
  const m = modelOf({ id: "chat-pro", name: "智能", rate: 0.6, context: 400000, output: 65536 })
  assert.equal(m.api.id, "chat-pro")
  assert.equal(m.api.url, BASE)
  assert.equal(m.api.npm, NPM)
  assert.equal(m.providerID, PROVIDER)
  assert.equal(m.rate, 0.6)
  assert.equal(m.free, false)
  assert.equal(m.limit.context, 400000)
  assert.equal(m.capabilities.toolcall, true)
  const free = modelOf({ id: "x", name: "X", rate: 0 })
  assert.equal(free.free, true)
  assert.equal(configModels([{ id: "chat-pro", name: "智能", context: 4, output: 2, rate: 0.6, default: true }])["chat-pro"].limit.context, 4)
})

test("isoBeijing reads the vendor's UTC+8 clock", () => {
  assert.equal(isoBeijing("2026-10-17 23:59:59"), "2026-10-17T15:59:59.000Z")
  assert.equal(isoBeijing("2026-10-31T00:00:00Z"), "2026-10-31T00:00:00.000Z")
  assert.equal(isoBeijing(""), null)
  assert.equal(isoBeijing("not a date"), null)
})

const item = (o) => ({ status: "consuming", isAggregated: false, isExpired: false, usedRate: 0, ...o })
// the shape the vendor really answers with: one aggregate row, sources inside it
const POINTS = {
  code: 200,
  data: {
    pointsBalance: 6043.94,
    userRole: "INDIVIDUAL",
    groups: [{
      type: "campaign",
      typeName: "积分福利社",
      active: [
        item({
          name: "积分福利社", totalQuota: 6600, usedQuota: 556.06, balance: 6043.94, usedRate: 8.43,
          effectiveEnd: "2026-10-17 23:59:59", isAggregated: true,
          subItems: [
            item({ name: "每日登录积分", totalQuota: 100, usedQuota: 0, balance: 100, effectiveEnd: "2026-10-17 23:59:59", planCode: "bp_sys_daily_login" }),
            item({ name: "月度积分赠礼", totalQuota: 3000, usedQuota: 556.06, balance: 2443.94, usedRate: 18.54, effectiveEnd: "2026-10-31 23:59:59" }),
            item({ name: "早过期的", totalQuota: 50, usedQuota: 50, balance: 0, effectiveEnd: "2026-10-16 23:59:59", isExpired: true }),
          ],
        }),
      ],
      invalid: [],
    }],
  },
}

test("parsePoints: one window the pool spends against, one per source, soonest loss first", () => {
  const out = parsePoints(POINTS, NOW)
  assert.equal(out.plan, "INDIVIDUAL")
  assert.equal(out.balance, "6043.94 积分")
  assert.equal(out.signIn, "kept")
  assert.equal(out.windows.length, 4)
  const pool = out.windows[0]
  assert.equal(pool.name, "积分福利社")
  assert.equal(pool.limit, 6600, "the aggregate is not the sum of sources plus itself")
  assert.equal(pool.amount, 556.06)
  assert.equal(pool.used, 8.43)
  assert.equal(pool.unit, "points")
  assert.equal(pool.resetsAt, "2026-10-17T15:59:59.000Z")
  assert.equal(pool.runsOutAt, "2026-10-17T15:59:59.000Z")
  assert.equal(pool.runsOut, 100, "the daily grant is the first thing to die")
  const daily = out.windows[1]
  assert.equal(daily.name, "每日登录积分")
  assert.equal(daily.aside, true, "a source running out is not the account running out")
  assert.equal(daily.display, "100 剩")
  assert.equal(out.windows.find((w) => w.name === "早过期的").resetsAt, "2026-10-16T15:59:59.000Z")
})

test("parsePoints also reads sources listed beside the aggregate, and none at all", () => {
  const flat = parsePoints({ data: { pointsBalance: 5, userRole: "INDIVIDUAL", groups: [{ typeName: "G", active: [
    item({ name: "G", totalQuota: 100, usedQuota: 40, balance: 60, usedRate: 40, isAggregated: true, effectiveEnd: "2026-12-01 00:00:00" }),
    item({ name: "a", totalQuota: 100, usedQuota: 40, balance: 60, effectiveEnd: "2026-12-01 00:00:00" }),
  ] }] } }, NOW)
  assert.deepEqual(flat.windows.map((w) => w.name), ["G", "a"])
  assert.equal(flat.windows[0].limit, 100)
  assert.equal(flat.windows[0].runsOut, 60)

  const none = parsePoints({ data: { pointsBalance: 0, userRole: "INDIVIDUAL", groups: [{ typeName: "G", active: [] }] } }, NOW)
  assert.deepEqual(none.windows, [])
  assert.equal(none.balance, "0 积分")
})

test("parsePoints without an aggregate row sums the sources; no answer says so", () => {
  const noAgg = parsePoints({ data: { pointsBalance: 10, userRole: "INDIVIDUAL", groups: [{ typeName: "G", active: [
    item({ name: "a", totalQuota: 40, usedQuota: 10, balance: 30, effectiveEnd: "2026-12-01 00:00:00" }),
    item({ name: "b", totalQuota: 60, usedQuota: 20, balance: 40, effectiveEnd: "2026-11-01 00:00:00" }),
  ] }] } }, NOW)
  assert.equal(noAgg.windows[0].limit, 100)
  assert.equal(noAgg.windows[0].amount, 30)
  assert.equal(noAgg.windows[0].runsOutAt, "2026-10-31T16:00:00.000Z")
  assert.equal(noAgg.windows[0].runsOut, 40, "only b is left at that instant; a dies later")

  const bad = parsePoints({ data: { groups: [] } }, NOW)
  assert.match(bad.error, /没有回答积分明细/)
  assert.deepEqual(bad.windows, [])
})

test("signInOf names only the vendor's two ways of saying the token is gone", () => {
  assert.equal(signInOf(402, '{"code":5014,"message":"权限"}'), "expired")
  assert.equal(signInOf(401, '{"code":"4001","message":"当前令牌是否存在"}'), "expired")
  assert.equal(signInOf(401, "令牌不能为空"), "expired")
  assert.equal(signInOf(401, '{"code":40105,"message":"您的请求疑似攻击请求，请稍后重试"}'), "kept")
  assert.equal(signInOf(429, "slow down"), "kept")
  assert.equal(signInOf(402, '{"code":50140}'), "kept", "a code that only begins with 5014 is another error")
  assert.equal(signInOf(500, ""), "kept")
})

test("unwrap reads a v10 safeStorage blob and refuses a tampered one", () => {
  const key = randomBytes(32)
  const seal = (text, k = key) => {
    const nonce = randomBytes(12)
    const c = createCipheriv("aes-256-gcm", k, nonce)
    const ct = Buffer.concat([c.update(text, "utf8"), c.final()])
    return Buffer.concat([Buffer.from("v10", "latin1"), nonce, ct, c.getAuthTag()])
  }
  assert.equal(unwrap(key, seal("Em9x-secret-token")), "Em9x-secret-token")
  const bad = seal("x")
  bad[bad.length - 1] ^= 1
  assert.throws(() => unwrap(key, bad), /Unsupported|auth|tag|bad decrypt/i)
  assert.throws(() => unwrap(key, Buffer.concat([Buffer.from("v11", "latin1"), Buffer.alloc(40)])), /封装不是 v10/)
  assert.throws(() => unwrap(randomBytes(16), seal("x")), /不是 32 字节/)
})

test("encryptedKey strips the DPAPI marker and says when it is not there", () => {
  const raw = Buffer.concat([Buffer.from("DPAPI", "latin1"), randomBytes(32)])
  assert.equal(encryptedKey(JSON.stringify({ os_crypt: { encrypted_key: raw.toString("base64") } })).length, 32)
  assert.throws(() => encryptedKey(JSON.stringify({ os_crypt: {} })), /没有 os_crypt/)
  assert.throws(() => encryptedKey(JSON.stringify({ os_crypt: { encrypted_key: Buffer.from("nope").toString("base64") } })), /不是 DPAPI/)
})

test("userDirs lists accounts by their own sign-in file, newest first", () => {
  assert.deepEqual(userDirs("/definitely/not/here"), [])
})

test("the provider's own paths and endpoint strings are the ones measured", () => {
  const p = pathsFor("/home/x")
  assert.equal(p.root, join("/home/x", ".local", "share", "TeleAgent"))
  assert.equal(p.localState, join(p.root, "Local State"))
  assert.equal(p.users, join(p.root, "users"))
  assert.equal(SAPI, "https://agent.teleai.com.cn/superCowork/sapi")
  assert.equal(BASE, SAPI + "/api/v1")
  assert.equal(catalogFile("/nope", "u"), null)
})
