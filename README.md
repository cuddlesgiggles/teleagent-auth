# opencode-teleagent-auth

把 [TeleAgent](https://agent.teleai.com.cn)（中国电信 teleai 的桌面 agent IDE）做成 magpie 的一个供应商：
用 TeleAgent 自己存的登录态说话，读它自己的模型目录，报它自己的积分窗口，
并能在面板里走官方网页登录、领每日签到积分。

实测通过：2026-10-17，Windows，TeleAgent 2.7.0.000，magpie 0.1.1276。
登录、模型列表、积分明细、对话四条路径都在本机跑通过；对话那条要逐请求签名，
方案是从 TeleAgent 自己的主程序里读出来的，不是试出来的。

网页登录换 JWT 与签到端点的依据是公开实现 `hj01857655/TeleAgent2api` 的实测，
本包只搬了它的协议，没有在真机上重新验证过（见文末「没解决的问题」）。

## 装

```sh
magpie plugin add github:cuddlesgiggles/teleagent-auth   # 或 clone 下来：magpie plugin add ./teleagent-auth
magpie plugin login teleagent
```

登录方式三种：

1. **桌面端登录态**（Windows 默认，不用你贴任何东西）：解 TeleAgent 自己存的会话令牌；
2. **手机验证码登录（浏览器）**：插件只返回官方登录页 URL，**不自己开浏览器、不发短信**。
   签到中心（或你手动）打开页面后会填手机号、勾协议、点「获取验证码」；滑块在页面上手动完成，
   输入短信验证码登录成功后，`X-Token` 从浏览器 Cookie 里读回并交给插件。也接受粘贴
   `…/cowork/auth?code=…` 回调链接；
3. **贴 X-Token**：给没装 TeleAgent 的机器，或网页登录后从浏览器 cookie 里复制的那条。

> 网页登录拿到的**回调 code 不是会话令牌**，是一次性授权码；直接把它当 X-Token 用会被
> 签名门拒绝。插件会自动兑换，并把 JWT 的 `exp` 报给 magpie 做有效期。

## 关于那把中继 key

对话和目录都要带一个 `Authorization: Bearer <relay key>`。这把 key 是 TeleAgent 客户端自带的
全局常量——装了这个客户端的人手里都是同一把，账号身份在 `X-Token` 上，单用它厂商答
`4001 当前令牌是否存在`。本包**直接内置**，装完即用，不需要你先配什么。

如果你那份构建换了这把常量，或者要指到自己的中继上，用环境变量覆盖，不必改代码：

```sh
TELEAGENT_RELAY_KEY=<你那份客户端里的串> magpie gateway
```

## 登录态在哪

TeleAgent 这个构建在 Windows 上也用 Linux 风格的路径（实测本机是 `C:\Users\<你>\.local\share\TeleAgent`）：

- Windows / Linux：`~/.local/share/TeleAgent`
- macOS：`~/Library/Application Support/TeleAgent`

| 用途 | 相对路径 |
|---|---|
| 会话令牌（每个账号一份） | `users/v1_public_<账号id>/app-auth/token.json` |
| 解密主密钥 | `Local State`（Chromium 的 `os_crypt`，DPAPI 只对当前用户可解） |
| deviceId / installId | `app-auth/device-meta.json`（在**根目录**，不是 per-user 那层） |
| 当前构建版本 | `logs/main-<日期>-v-<版本>.log` 的文件名 |

令牌是 Chromium 的 `v10` 封装（AES-256-GCM），插件做的事和 TeleAgent 自己启动时一样：
本机、当前用户、不提权、不外传。**令牌不会被复制进 magpie 的账号文件**——一份拷贝同时属于
两个程序，谁先刷新谁把对方踢下线，所以每次请求现读、按两份文件的 mtime 缓存。

`X-App-Version` 也不写死，从日志文件名读当前构建的版本；版本不对会被边缘判定成攻击请求。

## 设备指纹

对话、目录、积分三组请求都要带 `X-Superagent-Device-Id` 和 `X-Superagent-Install-Id`；
缺任一个，网关回答 `401 40101 missing super agent signature headers`。桌面端从
`app-auth/device-meta.json` 读这两个值。**没装桌面端的机器**（网页登录的 macOS/Linux）
没有这个文件，插件会生成一对并写到 `~/.config/magpie/teleagent-device.json`（0600），
之后每次请求复用同一对；也可以用插件选项 `deviceId` / `installId` 或 `deviceFile` 覆盖。

> 这一对不校验与账号的绑定：实测同一对可以在不同账号上使用，换一对也能过。但同一台机器
> 应当保持稳定，否则每个请求都像一台新设备。多账号共用同一对是平台关联账号的直接线索。

## 模型与积分

```
GET /superCowork/sapi/api/v1/model-options?language=zh-CN    -> 供应商给的档位
GET /superCowork/sapi/api/v1/auth/session-code               -> 一次性的 code
GET /superCowork/sapi/user/portal/points/detail?code=<code>  -> pointsBalance + 分组明细
```

三条都走同一组网关头（`x-token / x-timestamp / x-nonce / x-app-version / x-os-type`，
缺 `x-app-version` 或 `x-os-type` 会拿到 `40105 您的请求疑似攻击请求`）。

积分按来源拆成窗口，并给出「剩余积分里最早作废的那笔什么时候没、还剩多少」——
magpie 的 smart 路由会优先烧那一笔。

## 网页登录与续期

```
GET https://agent.teleai.com.cn/superCowork/sapi/cowork/auth?code=<回调里的 code>
    -> { token | data.token | 正文/Location 里的 JWT }
```

官方登录页是 `.../cowork/auth?source=01`。登录完成后页面停在
`.../cowork/auth?code=...`（或跳去 `teleai-cowork://`），把这条地址粘贴回 magpie 即可。
插件先认出回调链接 / `ucc.…` code / `tenant:JWT` / 裸 JWT，再决定是兑换还是直接用。
同一个 code 只兑换一次，兑换出的 JWT 缓存到快过期为止。

厂商**没有给第三方 refresh token**，所以续期就是重新走一次网页登录，换一条新 JWT；
这比回桌面端重登轻，也比从 `Local State` 解 DPAPI 跨平台（macOS 没有 DPAPI 实现）。

多账号：桌面登录的账号绑定它自己的 `users/v1_public_<id>`，找不到就报错，不会悄悄用
最新登录的那个账号的令牌；网页登录的 JWT 按 magpie 账号单独保存，两边互不串号。

## 每日签到

```
GET /superCowork/sapi/user/portal/companyStore/v2/checkDayTask          -> claimed_today / points / 连续天数
GET /superCowork/sapi/user/portal/companyStore/checkTask?type=daily_login -> {code, message, data}
```

先查今天领没领，没领才发领取请求；`code` 为 `0` 或 `200` 才算成功。
登录失效时门户会回答 **HTTP 200 + HTML 登录页**，所以非 JSON 的 200 一律判失败，
不能当「已签到」。magpie 的插件签到开关和每日调度由 host 负责，本包只实现
`auth.checkin` 这个钩子。

## 对话的签名门

`/api/v1/chat/completions` 不吃网关那组头。探测到的边界（都是本机实测的回答）：

| 发的头 | 回答 |
|---|---|
| 只带网关那组 | 401 `40101 missing super agent security headers` |
| 只带 `x-superagent-*` | 403 `40301 检测到客户端版本过低` |
| `x-superagent-*` + 签名，缺版本头 | 401 `40101 missing super agent signature headers` |
| 两组都带 + 随手签的名 | 401 `40104 invalid signature` |

到 `40104` 已经进入真正的比对，再试只是撞风控。剩下的拼串顺序与密钥来源是从主程序
`runtimes/super-agent-code/bin/TeleAgent.exe`（Go 1.26，`-s -w` 剥了符号表但 pclntab 在）
里 `einoprovider.(*GatewaySigner).Sign` 的反汇编读出来的：

```
inner = hmacHex( key = jwtThirdSegment(X-Token)
               , data = "superagent-auth-v1" / X-Token / installId / ts / nonce )        ← 分隔符 /
sign  = hmacHex( key = inner
               , data = "superagent-auth-v1" \n METHOD \n requestURI \n ts \n nonce \n appVersion \n sha256Hex(body) )  ← 分隔符 \n
```

`X-SuperAgent-Signature` 发的是第二次那个。几个容易踩的点都写在源码注释里：`jwtThirdSegment`
只在**正好三段**时取第三段且不解 base64url；`ts` 是十进制秒（毫秒会 40103）；`nonce` 是
标准 UUIDv4；`requestURI` 是转义后的 path 加 query，不含 scheme 和 host；`METHOD` 过 `ToUpper`；
`body` 签的是真正发出去的那串字节（空 body 就是 `sha256("")`），所以插件在 `loader.fetch`
里先把 body 摊平成字节再签。

过了签名门之后的实据：`messages: []` 回答 `400 messages: at least one message is required`
（进到参数校验了），一条真实消息 `200` + SSE 流。

## 没解决的问题

- **续期没有 refresh token**：厂商不给第三方可复用的续期接口。网页登录能换新 JWT，
  但每次都要用户过一遍官方页面；桌面端登录态过期仍只能回 App 重登。
- **价格**：目录里的 `points_multiplier` 是积分倍率，不是钱；插件把它当相对消耗报给
  magpie，`cost` 全是 0。没有可信的单价，就不替它发明。
- **网页登录与签到未在本机真机复测**：`/cowork/auth` 换 JWT、`checkDayTask` /
  `checkTask` 两组端点来自 `hj01857655/TeleAgent2api` 的公开实现，本包只做了离线单测。
  第一次真机使用时，先用小号确认兑换返回的令牌形状（裸 JWT 还是 `tenant:JWT`）与签到的
  `code` 取值。
- **自动回调未做**：UPMS 是否接受 `127.0.0.1` 的 `redirect_uri` 未验证
  （公开实现用的是公网回调；另一个实现实测说 `cowork/auth` 会忽略 loopback，自己开窗读
  cookie）。所以当前只做「粘贴回调链接」，不自己起监听端口。
- **从系统浏览器读 cookie 未做**：Chrome/Safari 的 cookie 各自加密，跨浏览器路径也不同；
  官方客户端自己用 Electron 分区读 `X-Token` / `operationToken` / `operToken`。
  本包让用户从 DevTools 复制 `X-Token`，或走上面的 code 兑换。

厂商一升级，签名方案就可能变。真机用的是 `2.7.0.000`；换版本先看 `logs/` 里的版本名，
再对照 `40104` / `40105` 的回答。

## 测试

```sh
node --test        # 34 条：两组头集合、签名已知答案、两套目录格式、积分窗口、40105 与 5014 的分法、v10 解密、中继 key、凭据解析、code 兑换与缓存、JWT exp、多账号选择、设备指纹、签到链路与 HTML 假成功
npm run mutate     # 17 个变异，全要变红
```

测试不联网、不调 DPAPI。签名的三条已知答案是 Python 的 `hmac`/`hashlib` 独立算出来的，
用的字段值也是合成的（装你的机器上的 id 不会进这个仓库）；分隔符、字段顺序、`ToUpper`、
密钥来源、`sha256` 各改一处都会变红。`unwrap()` 用自造密钥验证 AES-GCM 与防篡改，
真机解密单独跑过，结果与独立实现（Python + ctypes）逐字节一致。

## License

MIT
