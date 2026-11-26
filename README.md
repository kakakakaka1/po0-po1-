# po0 + po1 防火墙自动加白（Surge 模块）

在 [w0ven/po0fw](https://github.com/w0ven/po0fw) 的 po0 模块基础上，**新增一套 po1 加白**（腾讯云 ECS 白名单），两者互不干扰、各自独立配置。

> 本仓库**不存放任何 token / 密钥**。token 只在 Surge 的模块参数里填，随本机配置保存，不会上传到这里。

## 安装

```
https://raw.githubusercontent.com/kakakakaka1/po0-po1-/main/surge/po0-po1-firewall-whitelist.sgmodule
```

安装后在模块设置里填两个参数（都可留空，留空的那套就不工作）：

| 参数 | 填什么 |
|---|---|
| `tokens` | po0 的 token（`pgnfw_` 开头）。多台机器用英文逗号分隔。想钉死槽位就在 token 后面加 `@槽位号` |
| `tokens1` | po1 的 token（`ctecsfw_` 开头）。写法同上，`@槽位号` 表示钉固定槽位 |

## 两套 API 的差异（实测）

| | po0 | po1 |
|---|---|---|
| 地址 | `POST https://124.221.69.228/api/firewall/<token>/add?slot=N` | `GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>&slot=N` |
| token 位置 | URL 路径 | query 参数 |
| HTTP 方法 | POST | **只认 GET**（POST 会落到站点 404 页） |
| 成败判定 | HTTP 状态码 | **HTTP 恒 200，看 body 的 `status` 字段** |
| 加白粒度 | `/24` 段 | 单 IP `/32`（`entry_policy: single_ip`） |
| 重复请求 | 幂等 | 幂等（返回 `action: exists`） |

po1 成功响应示例：

```json
{"status":200,"msg":"固定槽位已更新为当前访问来源",
 "data":{"cidr":"203.0.113.10/32","action":"slot_pin","mode":"fixed","slot":4,
         "changed":1,"matched_cidr":"203.0.113.10/32","matched_slot":null,
         "removed_cidr":"","entry_policy":"single_ip","prefix_length":32}}
```

失败响应（token 无效 / 分享链接过期）同样是 HTTP 200：

```json
{"status":400,"msg":"白名单分享链接无效或已失效","data":[]}
```

## 分流规则

两个加白接口都必须直连，否则服务端看到的会是代理出口 IP：

```
IP-CIDR,124.221.69.228/32,DIRECT,no-resolve
DOMAIN-SUFFIX,guguyun.com,DIRECT
```

`www.guguyun.com` 是多 IP CDN（实测 `103.120.90.53` / `103.120.90.209` / `69.165.68.160`），所以用域名规则而不是 IP-CIDR。

## 面板

- `po0 防火墙加白`：`#1 📌5 ✅ 1/6` + 白名单条目
- `po1 防火墙加白`：`#1 📌4 ✅ 203.0.113.10/32 (slot 4) · 已在白名单`

po1 接口不返回完整白名单列表（只有本次写入的那条），所以面板只显示当前出口 IP、槽位和本次动作（新增 / 顶替 / 已存在）。

## 文件

- `surge/po0-po1-firewall-whitelist.sgmodule` — 模块本体，po0 部分直接引用上游脚本，不复制
- `scripts/po1-firewall-whitelist.js` — po1 脚本，兼容 Surge / Stash / Shadowrocket / Loon / Quantumult X

## 说明

- po1 未配置 `tokens1` 时**静默退出**，不弹通知，避免只配了 po0 的人每 10 分钟被吵一次。
- po1 是 GET 请求，天然幂等，失败（超时 / 5xx / 非 JSON 响应）会自动重试 3 次。
- 槽位冲突（po0 返回 403 `IP is already pinned to another slot.`）属于服务端状态，脚本只报错不自动处理，需要去对应面板删掉旧槽位。
