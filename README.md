# opencode-teleagent-auth

把 [TeleAgent](https://agent.teleai.com.cn)（中国电信 teleai 的桌面 agent IDE）做成 magpie 的一个供应商：
用 TeleAgent 自己存的登录态说话，读它自己的模型目录，报它自己的积分窗口。

实测通过：2026-10-17，Windows，TeleAgent 2.7.0.000，magpie 0.1.1276。
登录、模型列表、积分明细、对话四条路径都在本机跑通过；对话那条要逐请求签名，
方案是从 TeleAgent 自己的主程序里读出来的，不是试出来的。

## 装

```sh
magpie plugin add github:cuddlesgiggles/teleagent-auth   # 或 clone 下来：magpie plugin add ./teleagent-auth
magpie plugin login teleagent
```

登录方式两种：

1. **桌面端登录态**（默认，不用你贴任何东西）：解 TeleAgent 自己存的会话令牌；
2. **贴 X-Token**：给没装 TeleAgent 的机器。

## 装好之后要做的一件事

对话和目录都要带一个 `Authorization: Bearer <relay key>`。这把 key 是 TeleAgent 客户端
自带的全局常量，不是每个账号一把，也不属于我们能代你发布的材料——所以本包**不含它**，
运行时从环境变量取：

```sh
TELEAGENT_RELAY_KEY=<你自己那份 TeleAgent 安装里的那把> magpie gateway   # 或写进你启动 magpie 的环境
```

它在你本机 TeleAgent 的安装目录里，是一串 `sk-` 开头的定长串。没设这个变量时插件不会
静默降级，而是每条请求都明确报 `未设置 TELEAGENT_RELAY_KEY`。拿不到这把 key 就用不了本包，
这是设计上的限制，不是 bug。

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

## 没解决的两件事

- **续期**：厂商没有可复用的续期接口给第三方用，令牌过期就回 TeleAgent 桌面端重新登录，
  插件把状态报成 `expired`。
- **价格**：目录里没有可信的价格倍率，插件不替它发明一个，所以不声明 `free` / `rate`。

厂商一升级，签名方案就可能变。真机用的是 `2.7.0.000`；换版本先看 `logs/` 里的版本名，
再对照 `40104` / `40105` 的回答。

## 测试

```sh
node --test        # 16 条：两组头集合、签名已知答案、两套目录格式、积分窗口、40105 与 5014 的分法、v10 解密、缺 relay key 要报错
npm run mutate     # 8 个变异，全要变红
```

测试不联网、不调 DPAPI。签名的三条已知答案是 Python 的 `hmac`/`hashlib` 独立算出来的，
用的字段值也是合成的（装你的机器上的 id 不会进这个仓库）；分隔符、字段顺序、`ToUpper`、
密钥来源、`sha256` 各改一处都会变红。`unwrap()` 用自造密钥验证 AES-GCM 与防篡改，
真机解密单独跑过，结果与独立实现（Python + ctypes）逐字节一致。

## License

MIT
