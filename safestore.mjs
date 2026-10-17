// TeleAgent keeps its session token the way Chromium keeps its secrets on
// Windows: the text is AES-256-GCM under a key that DPAPI protects for this one
// user. Both steps are what the app itself does at startup, run as this user, so
// no elevation is involved and nothing leaves the machine.
//
// unwrap() is the part that is pure (and tested); dpapi() needs Bun, which is
// the runtime magpie's plugin host uses.
import { createDecipheriv } from "node:crypto"
import { readFileSync } from "node:fs"

const PREFIX = "v10"

// unwrap decrypts one Electron safeStorage blob: "v10" + a 12-byte nonce +
// ciphertext + a 16-byte GCM tag.
export function unwrap(key, payload) {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error("TeleAgent 的密钥不是 32 字节")
  const head = Buffer.from(payload).subarray(0, PREFIX.length).toString("latin1")
  if (head !== PREFIX) throw new Error(`TeleAgent 的令牌封装不是 ${PREFIX}（读到 ${JSON.stringify(head)}）`)
  const body = Buffer.from(payload).subarray(PREFIX.length)
  if (body.length < 12 + 16) throw new Error("TeleAgent 的令牌太短，解不出来")
  const nonce = body.subarray(0, 12)
  const rest = body.subarray(12)
  const dec = createDecipheriv("aes-256-gcm", key, nonce)
  dec.setAuthTag(rest.subarray(rest.length - 16))
  return Buffer.concat([dec.update(rest.subarray(0, rest.length - 16)), dec.final()]).toString("utf8")
}

export function encryptedKey(localStateText) {
  const v = JSON.parse(localStateText)
  const b64 = v?.os_crypt?.encrypted_key
  if (typeof b64 !== "string" || !b64) throw new Error("TeleAgent 的 Local State 里没有 os_crypt.encrypted_key")
  const raw = Buffer.from(b64, "base64")
  if (raw.subarray(0, 5).toString("latin1") !== "DPAPI") throw new Error("TeleAgent 的 encrypted_key 不是 DPAPI 封装的")
  return raw.subarray(5)
}

async function dpapi(data) {
  const { dlopen, FFIType, ptr, toBuffer } = await import("bun:ffi")
  const crypt32 = dlopen("crypt32.dll", {
    CryptUnprotectData: {
      args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.u32, FFIType.ptr],
      returns: FFIType.u32,
    },
  })
  const kernel32 = dlopen("kernel32.dll", { LocalFree: { args: [FFIType.u64], returns: FFIType.u64 } })
  const src = Buffer.from(data)
  const inBlob = new ArrayBuffer(16)
  const inView = new DataView(inBlob)
  inView.setUint32(0, src.length, true)
  inView.setBigUint64(8, BigInt(ptr(src)), true)
  const outBlob = new ArrayBuffer(16)
  if (!crypt32.symbols.CryptUnprotectData(ptr(inBlob), null, null, null, null, 0, ptr(outBlob))) {
    throw new Error("CryptUnprotectData 拒绝了这份密钥（换用户或换机器就跑不通）")
  }
  const out = new DataView(outBlob)
  const len = out.getUint32(0, true)
  const p = out.getBigUint64(8, true)
  // toBuffer wants the address itself and is (pointer, offset, length); the
  // two-argument form reads the wrong bytes
  const bytes = Buffer.from(toBuffer(Number(p), 0, len))
  kernel32.symbols.LocalFree(p)
  return bytes
}

// readToken returns TeleAgent's own session token, or says why it can't. The
// failure text is for the user to act on, so it names the file it tried.
export async function readToken({ localStateFile, tokenFile }) {
  const rec = JSON.parse(readFileSync(tokenFile, "utf8"))
  if (rec?.version !== 1 || typeof rec?.encryptedToken !== "string") {
    throw new Error(`${tokenFile} 不是预期的样子（version/encryptedToken）`)
  }
  if (rec.scheme !== "safe_storage") {
    throw new Error(`${tokenFile} 的 scheme 是 ${rec.scheme}，本插件只解 safe_storage 的那种`)
  }
  const key = await dpapi(encryptedKey(readFileSync(localStateFile, "utf8")))
  const token = unwrap(key, Buffer.from(rec.encryptedToken, "base64"))
  if (!token.trim()) throw new Error(`${tokenFile} 解开是空的 —— TeleAgent 大概是退登了`)
  return token.trim()
}
