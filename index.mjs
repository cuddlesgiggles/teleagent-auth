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
import { BASE, NPM, PROVIDER, SAPI, SITE_NAME, appVersion, catalogFile, configModels, deviceMeta, gatewayHeaders, mergedModels, modelOf, osType, parseLive, parseLocal, parsePoints, pathsFor, signInOf, signChatHeaders, tokenFileFor } from "./teleagent.mjs"
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
  return { status: res.status, text, json }
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
  // TeleAgent rewrites token.json when it signs in again, so the cache keys on
  // what is on disk rather than on time
  let cache = { stamp: "", token: "" }

  async function tokenNow() {
    if (pinned) return pinned
    const found = tokenFileFor(home, userData)
    if (!found) {
      throw new Error(`${p.users} 下没有已登录的 ${SITE_NAME} 账号 —— 先开一次 ${SITE_NAME} 登录，或在插件选项里把会话令牌贴进 token`)
    }
    const stamp = [found.userDir, statSync(found.file).mtimeMs, statSync(found.localState).mtimeMs].join("|")
    if (cache.stamp !== stamp || !cache.token) {
      cache = { stamp, token: await readToken({ localStateFile: found.localState, tokenFile: found.file }) }
    }
    return cache.token
  }

  // an account's sign-in: a pasted token wins, else whatever ${SITE_NAME} has now
  async function tokenFor(auth) {
    if (auth?.type === "api" && str(auth.key)) return str(auth.key)
    return await tokenNow()
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
              instructions: `用 ${SITE_NAME} 自己已登录的账号：解它本地存的会话令牌（DPAPI，当前用户），不复制过来。`,
              method: "auto",
              async callback() {
                try {
                  await tokenNow()
                } catch (e) {
                  return { type: "failed", error: e?.message ?? String(e) }
                }
                const found = tokenFileFor(home, userData)
                return {
                  type: "success",
                  refresh: "",
                  access: "",
                  expires: 0,
                  source: "desktop",
                  accountId: (found?.userDir ?? SITE_NAME).replace(/^v1_public_/, ""),
                  appVersion: version,
                }
              },
            }
          },
        },
        { type: "api", label: `${SITE_NAME} 会话令牌（X-Token）`, placeholder: "TeleAgent 请求头里那条 X-Token" },
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
    },
  }
}

export const _internal = { read, FALLBACK_MODEL, PORTAL_POINTS }
