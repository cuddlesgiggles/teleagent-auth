// TeleAgent (China Telecom teleai agent IDE) as a magpie provider: its own
// relay, its own security headers, its own points.
//
// Verified on this machine 2026-10-17 against https://agent.teleai.com.cn:
//   GET  /superCowork/sapi/api/v1/model-options?language=zh-CN   -> 200 catalog
//   GET  /superCowork/sapi/api/v1/auth/session-code              -> 200 {data:{code}}
//   GET  /superCowork/sapi/user/portal/points/detail?code=<code> -> 200 {pointsBalance, groups[]}
// all three with gatewayHeaders(): the five X-* are required together — drop
// X-App-Version or X-OS-Type and the edge answers 40105 您的请求疑似攻击请求, and a
// version that is not the running build's does the same, so X-App-Version comes
// from the app's own log file names rather than a constant.
//
// The chat path needs signChatHeaders(), i.e. the per-request signature; without
// it the answer is 401 40104 unsupported sign version. It was read out of the
// running build's Go binary rather than guessed, and one empty-messages POST then
// answered 400 messages: at least one message is required — past the signature
// gate and into payload validation — with a 200 SSE stream from chat-flash after
// that. See the block above signChatHeaders for the exact scheme.
import { createHash, createHmac } from "node:crypto"
import { readdirSync, readFileSync, statSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

export const PROVIDER = "teleagent"
export const SITE_NAME = "TeleAgent"
export const SAPI = "https://agent.teleai.com.cn/superCowork/sapi"
export const BASE = SAPI + "/api/v1"
export const NPM = "@ai-sdk/openai-compatible"

// the relay key TeleAgent's own client ships: one global constant for every
// install, not a per-account secret — the account is the X-Token, and this key
// alone answers 4001 当前令牌是否存在. TELEAGENT_RELAY_KEY overrides it for a build
// that rotated the constant or a fork pointing at its own relay.
export const DEFAULT_RELAY_KEY = "sk-qvp4m6h9g20uM6PgYP7E"

export function relayKey() {
  return process.env.TELEAGENT_RELAY_KEY || DEFAULT_RELAY_KEY
}
export const FALLBACK_VERSION = "2.7.0.000"

export function osType(platform = process.platform) {
  return platform === "win32" ? "Windows" : platform === "darwin" ? "macOS" : platform
}

// the gateway (model-options, session-code, points) checks these five together,
// over the relay key; any one of them missing answers 40105 您的请求疑似攻击请求,
// and a wrong X-App-Version does the same
export function gatewayHeaders({ token, appVersion, os, now = Date.now(), nonce }) {
  return {
    authorization: "Bearer " + relayKey(),
    "x-route-target": "ops-gateway",
    "x-token": token,
    "x-timestamp": String(Math.floor(now / 1000)),
    "x-nonce": nonce,
    "x-app-version": appVersion,
    "x-os-type": os,
  }
}

// ── the per-request signature ────────────────────────────────────────────────
// Read out of `einoprovider.(*GatewaySigner).Sign` in the running build's Go
// binary (einoprovider.(*GatewaySigner).Sign, 0x140d98c40 in this build). Two
// HMACs, and the two joins do not use the same separator:
//
//   inner = hmacSha256Hex( key  = jwtThirdSegment(token)
//                        , data = "superagent-auth-v1" / token / installId / ts / nonce )
//   outer = hmacSha256Hex( key  = inner
//                        , data = "superagent-auth-v1" \n METHOD \n requestURI \n ts \n nonce \n appVersion \n sha256Hex(body) )
//
// ts is `time.Now().Unix()` printed with %d, nonce a UUIDv4, both hex lowercase,
// the body is hashed from the exact bytes going out (empty body ⇒ sha256 of
// nothing, e3b0c442…), and `strings.ToUpper` is applied to the method. The
// server compares `outer`; the whole map comes from this one function.
export const SIGN_TAG = "superagent-auth-v1"

// the app's own key derivation: split on "." and take the third part only when
// there are exactly three — a token that is not a JWS keeps being itself.
export function jwtThirdSegment(token) {
  const parts = String(token).split(".")
  return parts.length === 3 ? parts[2] : String(token)
}

export function sha256Hex(data) {
  return createHash("sha256").update(toBytes(data)).digest("hex")
}

export function hmacHex(key, data) {
  return createHmac("sha256", Buffer.from(String(key), "utf8")).update(String(data), "utf8").digest("hex")
}

function toBytes(b) {
  if (b == null || b === "") return new Uint8Array(0)
  if (typeof b === "string") return Buffer.from(b, "utf8")
  if (b instanceof Uint8Array) return b
  if (b instanceof ArrayBuffer) return new Uint8Array(b)
  throw new Error("签名需要能取到请求体的字节，收到 " + Object.prototype.toString.call(b))
}

// path here is what Go's url.URL.RequestURI() returns: escaped path plus query,
// no scheme and no host.
export function signChatHeaders({ token, method, path, body, ts, nonce, appVersion, deviceId, installId }) {
  const inner = hmacHex(jwtThirdSegment(token), [SIGN_TAG, token, installId, ts, nonce].join("/"))
  const signature = hmacHex(inner, [SIGN_TAG, String(method).toUpperCase(), path, ts, nonce, appVersion, sha256Hex(body)].join("\n"))
  return {
    authorization: "Bearer " + relayKey(),
    "x-route-target": "ops-gateway",
    "x-token": token,
    "x-superagent-timestamp": ts,
    "x-superagent-nonce": nonce,
    ...(deviceId ? { "x-superagent-device-id": deviceId } : {}),
    ...(installId ? { "x-superagent-install-id": installId } : {}),
    "x-superagent-sign-version": "v1",
    "x-superagent-signature": signature,
    "x-app-version": appVersion,
  }
}

export function deviceMeta(root) {
  try {
    const v = JSON.parse(readFileSync(join(root, "app-auth", "device-meta.json"), "utf8"))
    return { deviceId: typeof v?.deviceId === "string" ? v.deviceId : "", installId: typeof v?.installId === "string" ? v.installId : "" }
  } catch {
    return { deviceId: "", installId: "" }
  }
}

export function pathsFor(home = homedir(), userData) {
  const root =
    userData ||
    (process.platform === "darwin"
      ? join(home, "Library", "Application Support", "TeleAgent")
      : join(home, ".local", "share", "TeleAgent"))
  return { root, localState: join(root, "Local State"), users: join(root, "users"), logs: join(root, "logs") }
}

// userDirs lists the per-account folders under users/ (`v1_public_<id>`), newest
// sign-in first: TeleAgent keeps one per account it has been signed in to.
export function userDirs(dir) {
  let names = []
  try {
    names = readdirSync(dir)
  } catch {
    return []
  }
  const mtime = (n) => {
    try {
      return statSync(join(dir, n, "app-auth", "token.json")).mtimeMs
    } catch {
      return 0
    }
  }
  return names.filter((n) => mtime(n) > 0).sort((a, b) => mtime(b) - mtime(a))
}

export function tokenFileFor(home, userData) {
  const p = pathsFor(home, userData)
  for (const u of userDirs(p.users)) {
    const f = join(p.users, u, "app-auth", "token.json")
    try {
      if (readFileSync(f)) return { file: f, userDir: u, root: p.root, localState: p.localState }
    } catch {}
  }
  return null
}

// versionFromLogs: electron-log names each day's file main-<date>-v-<version>.log,
// which is the running build's own version string.
export function versionFromLogs(names) {
  const hits = (names ?? []).map((n) => /main[-.](\d{4}-\d{2}-\d{2})[-.\s]v-([\w.+-]+)\.log/.exec(n)).filter(Boolean)
  if (!hits.length) return null
  hits.sort((a, b) => (a[1] < b[1] ? 1 : a[1] > b[1] ? -1 : 0))
  return hits[0][2]
}

export function appVersion(root) {
  try {
    return versionFromLogs(readdirSync(join(root, "logs"))) ?? FALLBACK_VERSION
  } catch {
    return FALLBACK_VERSION
  }
}

// a field the vendor sends as null means it said nothing, which is not the same
// as the number zero
const num = (v) => {
  if (v === null || v === undefined || v === "") return undefined
  const n = Number(v)
  return Number.isFinite(n) ? n : undefined
}

// parseLive /model-options: model, display_name, points_multiplier, is_default
export function parseLive(json) {
  const out = []
  for (const m of json?.data?.models ?? []) {
    if (typeof m?.model !== "string") continue
    out.push({
      id: m.model,
      name: m.display_name || m.model,
      group: m.category_name || m.category || "",
      rate: num(m.points_multiplier),
      default: !!m.is_default,
      context: num(m.context_limit) ?? num(m.limits?.context),
      output: num(m.limits?.output),
    })
  }
  return out
}

// parseLocal model-catalog.json: modelID, displayName, creditMultiplier, limits
export function parseLocal(json) {
  const out = []
  for (const g of json?.state?.catalog?.groups ?? []) {
    for (const m of g.models ?? []) {
      if (typeof m?.modelID !== "string") continue
      out.push({
        id: m.modelID,
        name: m.displayName || m.modelID,
        group: g.title || g.category || "",
        rate: num(m.creditMultiplier),
        default: !!m.isDefault,
        context: num(m.limits?.context),
        output: num(m.limits?.output),
        toolStream: m.behavior?.toolStream === true,
      })
    }
  }
  return out
}

// mergedModels: what the account has now (live), filled in with the limits the
// app cached locally (its answer carries none).
export function mergedModels(live, local) {
  const byId = new Map(local.map((m) => [m.id, m]))
  const src = live.length ? live : local
  return src.map((m) => {
    const l = byId.get(m.id) ?? {}
    return {
      ...l,
      ...m,
      context: m.context || l.context || 0,
      output: m.output || l.output || 0,
      rate: m.rate ?? l.rate,
    }
  })
}

export function catalogFile(root, userDir) {
  try {
    return JSON.parse(readFileSync(join(root, "users", userDir, "model-catalog.json"), "utf8"))
  } catch {
    return null
  }
}

export function modelOf(m) {
  const rate = m.rate
  return {
    id: m.id,
    providerID: PROVIDER,
    name: m.name,
    api: { id: m.id, url: BASE, npm: NPM },
    status: "active",
    headers: {},
    options: m.toolStream ? { tool_stream: true } : {},
    cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
    limit: { context: m.context || 0, output: m.output || 0 },
    capabilities: {
      temperature: true,
      reasoning: false,
      attachment: false,
      toolcall: true,
      input: { text: true, image: false, audio: false, video: false, pdf: false },
      output: { text: true, image: false, audio: false, video: false, pdf: false },
      interleaved: false,
    },
    release_date: "",
    variants: {},
    // points are what every tier costs; nothing this vendor lists is free
    free: rate === 0,
    rate: rate ?? 0,
    rateWas: 0,
  }
}

export function configModels(list) {
  return Object.fromEntries(
    list.map((m) => [m.id, {
      name: m.name,
      limit: { context: m.context || 0, output: m.output || 0 },
      tool_call: true,
      ...(m.rate !== undefined && m.rate !== null ? { rate: m.rate } : {}),
      ...(m.default ? { options: { isDefault: true } } : {}),
    }]),
  )
}

// "2026-10-17 23:59:59" is the vendor's own clock, UTC+8 (its portal says so and
// the credits really reset at that instant).
export function isoBeijing(s) {
  const t = typeof s === "string" && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s.trim())
    ? Date.parse(s.trim().replace(" ", "T") + "+08:00")
    : Date.parse(s ?? "")
  return t > 0 ? new Date(t).toISOString() : null
}

const round = (n) => (Number.isInteger(n) ? String(n) : n.toFixed(2).replace(/0+$/, "").replace(/\.$/, ""))

// parsePoints turns points/detail into magpie's usage shape: one window per
// group (what the account is actually spending against), plus one per source so
// a 每日登录积分 that dies at midnight tonight is visible, and when the first
// credits left are lost (magpie's routing spends those first).
export function parsePoints(json, now = Date.now()) {
  const d = json?.data
  if (!d || typeof d.pointsBalance !== "number") return { error: "TeleAgent 没有回答积分明细", windows: [] }
  const windows = []
  let runsOutAt = 0
  let runsOut = 0
  for (const g of d.groups ?? []) {
    const active = (g.active ?? []).filter((it) => it && num(it.totalQuota) > 0)
    const agg = active.find((it) => it.isAggregated) ?? null
    // the sources ride inside the aggregate row (subItems), not beside it
    const parts = (agg?.subItems?.length ? agg.subItems : active.filter((it) => it !== agg)).filter((it) => it && num(it.totalQuota) > 0)
    const total = num(agg?.totalQuota) ?? parts.reduce((a, it) => a + num(it.totalQuota), 0)
    const used = num(agg?.usedQuota) ?? parts.reduce((a, it) => a + num(it.usedQuota), 0)
    if (total > 0) {
      const w = {
        name: g.typeName || g.type || "积分",
        used: num(agg?.usedRate) ?? (100 * used) / total,
        amount: used,
        limit: total,
        unit: "points",
        display: `${round(used)} / ${round(total)}`,
      }
      const end = isoBeijing(agg?.effectiveEnd)
      if (end) w.resetsAt = end
      for (const it of parts) {
        const left = num(it.balance) ?? 0
        const at = it.isExpired ? 0 : Date.parse(isoBeijing(it.effectiveEnd) ?? "")
        if (left > 0 && at > now && (!runsOutAt || at < runsOutAt)) {
          runsOutAt = at
          runsOut = left
        } else if (left > 0 && at > now && at === runsOutAt) runsOut += left
      }
      if (runsOutAt) {
        w.runsOutAt = new Date(runsOutAt).toISOString()
        w.runsOut = runsOut
      }
      windows.push(w)
    }
    for (const it of parts) {
      const end = isoBeijing(it.effectiveEnd)
      const w = {
        name: it.name || it.planCode || "积分来源",
        used: num(it.usedRate) ?? (num(it.totalQuota) ? (100 * num(it.usedQuota)) / num(it.totalQuota) : 0),
        amount: num(it.usedQuota) ?? 0,
        limit: num(it.totalQuota) ?? 0,
        unit: "points",
        aside: true,
        display: `${round(num(it.balance) ?? 0)} 剩`,
      }
      if (end) w.resetsAt = end
      windows.push(w)
    }
  }
  return {
    plan: d.userRole || "",
    balance: `${round(d.pointsBalance)} 积分`,
    windows,
    signIn: "kept",
  }
}

// signInOf: which answers mean the sign-in itself is gone. TeleAgent says it two
// ways: 4001 当前令牌是否存在 at the gate, and HTTP 402 with code 5014 from the
// relay, after which its own client clears the token. 40105 is the edge flagging
// the request shape, not the account, so it must not rest the account.
export function signInOf(status, text) {
  const s = String(text ?? "")
  if (status === 402 && /["']?code["']?\s*:\s*["']?5014(?![\d.])/.test(s)) return "expired"
  if (/"code"\s*:\s*"?4001/.test(s) || /当前令牌|令牌不能为空/.test(s)) return "expired"
  return "kept"
}
