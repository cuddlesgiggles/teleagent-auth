// TeleAgent (China Telecom teleai agent IDE) as a magpie provider: agents use
// its chat relay with the account TeleAgent itself signed in to, and magpie's
// usual multi-account routing and quota handling applies on top.
//
// The session token is read from TeleAgent's own store per request and never
// written into magpie's auth file: a copied token would be both apps' at once,
// and TeleAgent has no renewal endpoint — when it stops working the only fix is
// signing in again there, which is what the expired mark tells the user to do.
//
// What is proven on this machine and what is not is stated in teleagent.mjs:
// the model list, the sign-in read and the points work, and the chat goes through
// signChatHeaders(), the per-request signature read out of the app's own binary.
import { randomUUID } from "node:crypto"
import { statSync } from "node:fs"
import { homedir } from "node:os"
import { BASE, CHECKIN, LOGIN_PAGE_URL, NPM, PROVIDER, SAPI, SITE_NAME, accountIdFromToken, appVersion, catalogFile, configModels, deviceMeta, exchangeCode, gatewayHeaders, jwtExpiryMs, loadOrCreateDevice, mergedModels, modelOf, needsSignIn, osType, parseCheckTask, parseCredential, parseDayTask, parseLive, parseLocal, parsePoints, pathsFor, signInOf, signChatHeaders, tokenFileFor } from "./teleagent.mjs"
import { readToken } from "./safestore.mjs"

const PORTAL_POINTS = SAPI + "/user/portal/points/detail"

// what the vendor's preset tier is today (its live catalog and cached copy both
// said this on 2026-10-17); the signed-in list comes from the account itself
const FALLBACK_MODEL = [
  { id: "chat-pro", name: "智能", context: 400000, output: 65536, rate: 0.6, default: true },
  { id: "chat-flagship", name: "旗舰", context: 400000, output: 65536, rate: 1.0 },
  { id: "chat-flash", name: "极速", context: 400000, output: 65536, rate: 0.2 },
]

async function read(url, headers, method = "GET", body) {
  const res = await fetch(url, {
    method,
    headers: { ...headers, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
    body,
    signal: AbortSignal.timeout(20000),
  })
  const text = await res.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {}
  return { status: res.status, text, json, contentType: res.headers.get("content-type") ?? "" }
}

export const TeleAgentAuthPlugin = async (_input, options = {}) => {
  const str = (v) => (typeof v === "string" && v.trim() ? v.trim() : "")
  const home = str(options.home) || homedir()
  const userData = str(options.userData) || undefined
  const pinned = str(options.token)
  const p = pathsFor(home, userData)
  const os = str(options.osType) || osType()
  const version = str(options.appVersion) || appVersion(p.root)
  const device = { ...deviceMeta(p.root), ...(options.deviceId ? { deviceId: String(options.deviceId) } : {}), ...(options.installId ? { installId: String(options.installId) } : {}) }
  // the gateway refuses a request without both device headers, and a machine
  // that never installed the desktop app has no device-meta.json to read
  if (!device.deviceId || !device.installId) {
    const file = str(options.deviceFile)
    const made = file ? loadOrCreateDevice(file) : loadOrCreateDevice()
    device.deviceId ||= made.deviceId
    device.installId ||= made.installId
  }
  // TeleAgent rewrites token.json when it signs in again, so the cache keys on
  // what is on disk rather than on time. One entry per account file: a seat
  // bound to an older account must not be handed the newest account's token.
  const cache = new Map()

  async function tokenNow(accountId) {
    const found = tokenFileFor(home, userData, accountId)
    if (!found) {
      const who = accountId ? `账号 ${accountId} 的` : "已登录的"
      throw new Error(`${p.users} 下没有${who} ${SITE_NAME} 账号 —— 先开一次 ${SITE_NAME} 登录，或用网页登录建一个新账号`)
    }
    const stamp = [found.userDir, statSync(found.file).mtimeMs, statSync(found.localState).mtimeMs].join("|")
    const hit = cache.get(found.file)
    if (hit?.stamp === stamp) return hit.token
    const token = await readToken({ localStateFile: found.localState, tokenFile: found.file })
    cache.set(found.file, { stamp, token })
    return token
  }

  // a code from the official page is traded once; its JWT is kept until it
  // nears expiry, so a request never spends a one-time grant again
  const traded = new Map()
  async function credentialToToken(raw) {
    const value = str(raw)
    if (!value) throw new Error(`${SITE_NAME} 的凭据是空的`)
    const parsed = parseCredential(value)
    if (!parsed) return value
    if (parsed.kind === "token") return parsed.value
    const hit = traded.get(parsed.value)
    if (hit && (!hit.expires || hit.expires - Date.now() > 60_000)) return hit.token
    const out = await exchangeCode(parsed.value)
    traded.set(parsed.value, { token: out.token, expires: jwtExpiryMs(out.token) })
    return out.token
  }

  // an account's sign-in: the JWT the host saved for a web sign-in wins, then a
  // pasted token/code, then the desktop app's own store for that account
  async function tokenFor(auth) {
    if (pinned) return await credentialToToken(pinned)
    const access = str(auth?.access)
    if (access) return access
    if (auth?.type === "api" && str(auth.key)) return await credentialToToken(str(auth.key))
    return await tokenNow(auth?.accountId)
  }

  const gateway = (token) => gatewayHeaders({ token, appVersion: version, os, nonce: randomUUID() })

  function localCatalog() {
    const found = tokenFileFor(home, userData)
    return found ? parseLocal(catalogFile(found.root, found.userDir)) : []
  }

  return {
    config: async (cfg) => {
      cfg.provider ??= {}
      cfg.provider[PROVIDER] ??= {}
      const pr = cfg.provider[PROVIDER]
      pr.name ??= SITE_NAME
      pr.npm ??= NPM
      pr.api ??= BASE
      const local = localCatalog()
      pr.models = { ...configModels(local.length ? local : FALLBACK_MODEL), ...(pr.models ?? {}) }
    },

    provider: {
      id: PROVIDER,
      // the account's own list; a refused or unreachable answer keeps magpie's
      async models(provider, { auth } = {}) {
        try {
          const r = await read(BASE + "/model-options?language=zh-CN", gateway(await tokenFor(auth)))
          const ms = mergedModels(parseLive(r.json), localCatalog())
          return ms.length ? Object.fromEntries(ms.map((m) => [m.id, modelOf(m)])) : provider.models
        } catch {
          return provider.models
        }
      },
    },

    auth: {
      provider: PROVIDER,
      methods: [
        {
          type: "oauth",
          label: `${SITE_NAME} 桌面端的登录`,
          async authorize() {
            return {
              url: "",
              instructions: `用 ${SITE_NAME} 自己已登录的账号：解它本地存的会话令牌（DPAPI，仅 Windows；其他系统请用网页登录），不复制过来。`,
              method: "auto",
              async callback() {
                let token = ""
                try {
                  token = pinned ? await credentialToToken(pinned) : await tokenNow()
                } catch (e) {
                  return { type: "failed", error: e?.message ?? String(e) }
                }
                const found = tokenFileFor(home, userData)
                return {
                  type: "success",
                  refresh: "",
                  access: "",
                  expires: jwtExpiryMs(token),
                  source: "desktop",
                  accountId: (found?.userDir ?? SITE_NAME).replace(/^v1_public_/, ""),
                  appVersion: version,
                }
              },
            }
          },
        },
        {
          type: "oauth",
          label: `${SITE_NAME} 手机验证码登录（浏览器）`,
          async authorize() {
            return {
              url: LOGIN_PAGE_URL,
              // The check-in center opens this page, fills the phone and presses
              // 获取验证码 itself; the SMS is never sent from this plugin. After
              // the user types the code on the page, the center reads the
              // X-Token cookie and hands it back through callback(input).
              instructions:
                `页面已打开：手机号与「获取验证码」由签到中心代填代点（滑块在窗口里手动完成）。` +
                `在页面上输入短信验证码完成登录后会自动取回 X-Token；也可以在这里粘贴 …/cowork/auth?code=… 回调链接或 X-Token。`,
              method: "code",
              async callback(input) {
                try {
                  const parsed = parseCredential(input)
                  const token = parsed?.kind === "code"
                    ? (await exchangeCode(parsed.value)).token
                    : parsed?.kind === "token" ? parsed.value : ""
                  if (!token) {
                    return { type: "failed", error: "没认出这是回调链接、登录 code 还是 X-Token" }
                  }
                  return {
                    type: "success",
                    refresh: "",
                    access: token,
                    expires: jwtExpiryMs(token),
                    source: "web",
                    accountId: accountIdFromToken(token),
                  }
                } catch (e) {
                  return { type: "failed", error: e?.message ?? String(e) }
                }
              },
            }
          },
        },
        { type: "api", label: `${SITE_NAME} 会话令牌（X-Token）`, placeholder: "X-Token、网页回调链接，或回调里的 code" },
      ],

      async loader(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "oauth" && auth?.type !== "api") return {}
        return {
          baseURL: BASE,
          apiKey: "",
          async fetch(input, init) {
            const token = await tokenFor(await getAuth())
            const url = typeof input === "string" ? input : input?.url
            // the signature covers the method, the escaped path with its query and
            // the exact bytes of the body, so magpie's request is flattened first
            const body = init?.body ?? (typeof input === "object" && input ? input.body : null)
            const bytes = body == null ? new Uint8Array(0) : new Uint8Array(await new Response(body).arrayBuffer())
            const u = new URL(url)
            const headers = new Headers(init?.headers ?? input?.headers)
            const signed = signChatHeaders({
              token,
              method: (init?.method ?? (typeof input === "object" ? input.method : "") ?? "POST") || "POST",
              path: u.pathname + u.search,
              body: bytes,
              ts: String(Math.floor(Date.now() / 1000)),
              nonce: randomUUID(),
              appVersion: version,
              deviceId: device.deviceId,
              installId: device.installId,
            })
            for (const [k, v] of Object.entries(signed)) headers.set(k, v)
            headers.delete("x-api-key")
            headers.delete("content-length")
            const res = await fetch(input, { ...init, headers, body: bytes.length ? bytes : undefined })
            if (res.status < 400) return res
            const text = await res.clone().text().catch(() => "")
            const out = new Headers(res.headers)
            out.delete("content-length")
            out.delete("content-encoding")
            out.set("X-Magpie-Sign-In", signInOf(res.status, text))
            return new Response(res.body, { status: res.status, statusText: res.statusText, headers: out })
          },
        }
      },

      // points, split by source, and when the soonest of what is left is lost
      async usage(getAuth) {
        try {
          const h = gateway(await tokenFor(await getAuth()))
          const code = await read(BASE + "/auth/session-code", h)
          const sc = code.json?.data?.code
          if (typeof sc !== "string" || !sc) {
            return { error: `${SITE_NAME} 没给积分门户的会话码（HTTP ${code.status}）`, windows: [], signIn: "kept" }
          }
          const points = await read(PORTAL_POINTS + "?code=" + encodeURIComponent(sc), h)
          if (!points.json) return { error: `${SITE_NAME} 的积分明细不是 JSON（HTTP ${points.status}）`, windows: [], signIn: "kept" }
          return parsePoints(points.json)
        } catch (e) {
          return { error: e?.message ?? String(e), windows: [], signIn: "kept" }
        }
      },

      // the welfare portal's daily check-in: look first, claim only when today
      // is not already done, and never read an HTML login page as a success
      async checkin(getAuth) {
        try {
          const h = gateway(await tokenFor(await getAuth()))
          const day = await read(CHECKIN.dayTask, h)
          if (needsSignIn(day.status, day.contentType, day.text)) {
            return { outcome: "failed", message: `${SITE_NAME} 登录已失效，请重新网页登录` }
          }
          if (!day.json) {
            return { outcome: "failed", message: `签到状态不是 JSON（HTTP ${day.status}）` }
          }
          const st = parseDayTask(day.json)
          if (st.claimed) {
            const extra = [st.points && `${st.points} 积分`, st.streak && `连续 ${st.streak} 天`].filter(Boolean).join("，")
            return { outcome: "done", message: `今日已签到${extra ? `（${extra}）` : ""}` }
          }
          const claim = await read(CHECKIN.claim + "?type=" + encodeURIComponent(CHECKIN.claimType), h)
          if (needsSignIn(claim.status, claim.contentType, claim.text)) {
            return { outcome: "failed", message: `${SITE_NAME} 登录已失效，请重新网页登录` }
          }
          if (!claim.json) {
            return { outcome: "failed", message: `签到接口没返回 JSON（HTTP ${claim.status}）` }
          }
          const r = parseCheckTask(claim.json)
          if (!r.ok) {
            return { outcome: "failed", message: r.message || `签到返回 code ${r.code}` }
          }
          return { outcome: "claimed", message: "签到成功，积分已到账" }
        } catch (e) {
          return { outcome: "failed", message: e?.message ?? String(e) }
        }
      },
    },
  }
}

export const _internal = { read, FALLBACK_MODEL, PORTAL_POINTS }
