#!/usr/bin/env node
// Mutation check: 8 deliberate bugs, each must turn the tests red.
// Zero dependencies, Node >= 20. Copies the repo into a sibling scratch dir per mutation,
// patches one anchor, runs `node --test` there, and exits 1 if any mutation is still green.
import { cpSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const SRC = fileURLToPath(new URL("..", import.meta.url));
const DST = join(dirname(SRC), ".mut-teleagent");

const MUTS = [
  ["teleagent.mjs", "the inner join switches from / to \\n",
    "].join(\"/\")", "].join(\"\\n\")"],
  ["teleagent.mjs", "the inner join signs deviceId instead of installId",
    "[SIGN_TAG, token, installId, ts, nonce]", "[SIGN_TAG, token, deviceId, ts, nonce]"],
  ["teleagent.mjs", "the method is not upper-cased",
    "String(method).toUpperCase()", "String(method)"],
  ["teleagent.mjs", "appVersion drops out of the outer field list",
    "[SIGN_TAG, String(method).toUpperCase(), path, ts, nonce, appVersion, sha256Hex(body)]",
    "[SIGN_TAG, String(method).toUpperCase(), path, ts, nonce, sha256Hex(body)]"],
  ["teleagent.mjs", "the outer key is the token instead of the inner digest",
    "hmacHex(inner, [SIGN_TAG", "hmacHex(jwtThirdSegment(token), [SIGN_TAG"],
  ["teleagent.mjs", "the body is hashed with sha1 instead of sha256",
    'return createHash("sha256").update(toBytes(data)).digest("hex")',
    'return createHash("sha1").update(toBytes(data)).digest("hex")'],
  ["teleagent.mjs", "the relay key is sent blank",
    'authorization: "Bearer " + relayKey(),', 'authorization: "Bearer ",'],
  ["teleagent.mjs", "the shipped relay constant is emptied",
    'export const DEFAULT_RELAY_KEY = "sk-qvp4m6h9g20uM6PgYP7E"',
    'export const DEFAULT_RELAY_KEY = ""'],
  ["teleagent.mjs", "a web sign-in code is not recognised as a code",
    "if (/^ucc\\.", "if (/^zzz\\."],
  ["teleagent.mjs", "the code trade drops the code from its URL",
    '"/cowork/auth?code="', '"/cowork/auth?grant="'],
  ["teleagent.mjs", "a check-in answer of 0 is refused",
    'return { ok: code === "" || code === "0" || code === "200", code, message }',
    'return { ok: code === "", code, message }'],
  ["teleagent.mjs", "a seat bound to one account falls back to the newest",
    "  if (want) {", "  if (false) {"],
  ["teleagent.mjs", "an HTML 200 is read as a real answer",
    'if (body.startsWith("<")) return true', 'if (body.startsWith("<")) return false'],
  ["index.mjs", "a machine without device-meta sends no device pair",
    "if (!device.deviceId || !device.installId) {", "if (false) {"],
  ["weblogin.mjs", "the protocol box is never ticked",
    "await session.frame.click(LOGIN_SELECTORS.agree).catch(() => {})", "void 0"],
  ["weblogin.mjs", "a cookie other than X-Token is preferred",
    'const TOKEN_COOKIES = ["X-Token", "operationToken", "operToken"]',
    'const TOKEN_COOKIES = ["operationToken", "X-Token", "operToken"]'],
  ["weblogin.mjs", "any phone number is accepted",
    "return /^1[3-9]\\d{9}$/.test(digits) ? digits : null", "return digits"],
  ["weblogin.mjs", "the transient login token is taken for the session token",
    'pickSessionToken(await session.ctx.cookies(), { onlySession: true })',
    'pickSessionToken(await session.ctx.cookies(), { onlySession: false })'],
];

rmSync(DST, { recursive: true, force: true });
let bad = 0;
for (let i = 0; i < MUTS.length; i++) {
  const [file, label, old, neu] = MUTS[i];
  const d = join(DST, "m" + i);
  cpSync(SRC, d, { recursive: true, filter: (s) => !s.includes(join(SRC, ".git")) && !s.includes(join(SRC, "node_modules")) && !s.includes(".mut") });
  const p = join(d, file);
  const code = readFileSync(p, "utf8");
  const at = code.indexOf(old);
  if (at < 0) { console.log(`SKIP (anchor missing)  ${label}`); bad++; continue; }
  writeFileSync(p, code.slice(0, at) + neu + code.slice(at + old.length));
  const r = spawnSync(process.execPath, ["--test"], { cwd: d, encoding: "utf8" });
  const passed = /pass (\d+)/.exec(r.stdout)?.[1] ?? "?";
  if (r.status === 0) { console.log(`GREEN! (tests still pass)  ${label}`); bad++; }
  else console.log(`RED (pass=${passed})  ${label}`);
}
rmSync(DST, { recursive: true, force: true });
console.log(bad === 0 ? "all mutations red" : `${bad} mutation(s) not red`);
process.exit(bad === 0 ? 0 : 1);
