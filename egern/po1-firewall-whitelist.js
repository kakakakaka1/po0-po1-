/*
 * po1 防火墙自动加白 · Egern 原生脚本
 *
 * Egern 的运行模型与 Surge 系不同：入口是 `export default async function(ctx)`，
 * 没有 $httpClient/$persistentStore 等全局，只能用 ctx.*。因此本文件不复用
 * surge/ 那份脚本，业务逻辑保持一致，改动时请同步两份。
 *
 * 行为：GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>[&slot=N]
 *   把本机当前出口 IP 写入白名单。token 走 query（不是 URL 路径）；token 后的 @槽位
 *   会被剥成 &slot=N 传，语义与 Surge 版一致。
 *
 * ⚠️ 这个接口的 HTTP 状态码恒为 200，真实结果在 body 的 status 字段：
 *     成功 {status:200, msg, data:{cidr,action,mode,slot,changed,matched_cidr,
 *                                  matched_slot,removed_cidr,entry_policy,prefix_length}}
 *     失败 {status:400, msg:"白名单分享链接无效或已失效", data:[]}
 *   所以判定成败必须看 body.status，不能看 resp.status。
 *
 * data.action 实测取值：slot_pin（钉槽位写入/顶替）、exists（已存在，未写入）。
 * entry_policy 为 single_ip / prefix_length=32 —— 与 po0 的 /24 不同，这里是单 IP 粒度。
 * 接口不返回完整白名单列表，所以只能显示当前出口 IP、槽位和本次动作。
 */

const API_BASE = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist";
const TOKEN_PREFIX = "ctecsfw_";
const STORE_PREFIX = "po1_fw_";
const HIST_WINDOW_MS = 24 * 3600 * 1000; // 📶 标记的记账窗口

// tokens 分隔符兼容 , ， | ; 、 空白；每段可带 @槽位 后缀
function parseTokens(raw) {
  let str = String(raw || "").trim();
  if (/^["'].*["']$/.test(str)) str = str.slice(1, -1).trim();
  return str
    .split(/[,，|;、\s]+/)
    .map(function (s) {
      return s.trim();
    })
    .filter(function (s) {
      return s.indexOf(TOKEN_PREFIX) === 0;
    })
    .map(function (s) {
      const at = s.indexOf("@");
      if (at === -1) return { token: s, slot: null, invalidError: null };
      const tok = s.slice(0, at);
      const slotRaw = s.slice(at + 1);
      if (!/^\d+$/.test(slotRaw)) {
        return {
          token: tok,
          slot: null,
          invalidError: "槽位号 '@" + slotRaw + "' 无效（须为数字，如 @4）",
        };
      }
      return { token: tok, slot: parseInt(slotRaw, 10), invalidError: null };
    })
    .filter(function (item) {
      if (/[^\x20-\x7E]/.test(item.token)) return false;
      if (!/^ctecsfw_[A-Za-z0-9_-]+$/.test(item.token) && !item.invalidError) {
        item.invalidError = "token 含非法字符";
      }
      return true;
    });
}

// WiFi 有 ssid 视为非蜂窝；否则若有蜂窝载波/制式则视为蜂窝（仅用于 📶 标记）
function onCellular(ctx) {
  try {
    const d = ctx.device || {};
    const onWifi = !!(d.wifi && d.wifi.ssid);
    const hasCell = !!(d.cellular && (d.cellular.carrier || d.cellular.radio));
    return !onWifi && hasCell;
  } catch (e) {
    return false;
  }
}

function readHistory(ctx, key) {
  let h;
  try {
    h = ctx.storage.getJSON(key) || [];
  } catch (e) {
    h = [];
  }
  if (!Array.isArray(h)) h = [];
  const cutoff = Date.now() - HIST_WINDOW_MS;
  return h.filter(function (e) {
    return e && e.ts > cutoff;
  });
}

function sleep(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// GET 天然幂等（已存在的 IP 返回 exists，不重复写入），重试安全
const HTTP_RETRY = 3;
const HTTP_RETRY_DELAY_MS = 1500;

function isRetryable(status, text) {
  if (!status) return false;
  if (status >= 500 || status === 429) return true;
  if (status < 200 || status >= 300) return false;
  // HTTP 200 但 body 不是 JSON（站点 404 页 / 网关页）→ 视为瞬时异常
  try {
    JSON.parse(text);
    return false;
  } catch (e) {
    return true;
  }
}

// ⚠️ Egern 的 ctx.http 在非 2xx 时会直接 throw，不会把 resp 交回来。
// 必须从 error message 里把 status/body 解析出来，否则 4xx/5xx 分支永远走不到。
async function httpGetOnce(ctx, url) {
  let text = "";
  let status = 0;
  try {
    const resp = await ctx.http.get(url, {
      headers: { Accept: "application/json" },
      timeout: 15000,
    });
    status = resp.status;
    try {
      text = await resp.text();
    } catch (e) {}
  } catch (e) {
    const msg = String((e && e.message) || e);
    const m = msg.match(/status:\s*(\d{3})(?:\s*,\s*body:\s*([\s\S]*))?/i);
    if (m) {
      status = parseInt(m[1], 10);
      text = m[2] !== undefined ? m[2] : "";
    } else {
      return { netError: msg || "网络请求失败（超时 / 握手失败 / 被拦截）" };
    }
  }
  return { status: status, text: text };
}

async function apiCall(ctx, token, slot) {
  let url = API_BASE + "?token=" + encodeURIComponent(token);
  if (slot !== null && slot !== undefined && slot !== "") {
    url += "&slot=" + encodeURIComponent(slot);
  }

  let r = null;
  let exhausted = false;
  for (let attempt = 1; attempt <= HTTP_RETRY; attempt++) {
    r = await httpGetOnce(ctx, url);
    if (!r.netError && !isRetryable(r.status, r.text)) break;
    if (attempt < HTTP_RETRY) await sleep(HTTP_RETRY_DELAY_MS * attempt);
    else exhausted = true;
  }
  if (r.netError) return { error: r.netError + "（已重试 " + HTTP_RETRY + " 次）" };

  let body = null;
  try {
    body = JSON.parse(r.text);
  } catch (e) {}
  if (!body || typeof body !== "object") {
    return { error: "响应异常: " + String(r.text || "").slice(0, 80) };
  }

  // HTTP 恒 200，真实结果看 body.status
  const status = typeof body.status === "number" ? body.status : r.status;
  if (status !== 200) {
    const msg = body.msg || body.message || "请求被拒绝";
    const retrySuffix = exhausted ? "（已重试 " + HTTP_RETRY + " 次）" : "";
    return { error: "HTTP " + status + ": " + msg + retrySuffix };
  }

  const d = body.data && typeof body.data === "object" ? body.data : {};
  return {
    enabled: true,
    applied: !!d.cidr,
    currentIp: d.cidr || "",
    action: d.action || "",
    mode: d.mode || "",
    slot: d.slot === undefined ? null : d.slot,
    matchedSlot: d.matched_slot === undefined ? null : d.matched_slot,
    removed: d.removed_cidr || "",
    changed: d.changed,
    policy: d.entry_policy || "",
    msg: body.msg || "",
  };
}

async function ensure(ctx, item, index, cellular) {
  const kvState = STORE_PREFIX + index;
  const kvHist = STORE_PREFIX + "hist_" + index;
  if (item.invalidError) {
    return { kvState: kvState, kvHist: kvHist, slot: item.slot, st: { error: item.invalidError } };
  }
  const st = await apiCall(ctx, item.token, item.slot);
  if (st.applied) {
    const hist = readHistory(ctx, kvHist);
    const last = hist.length ? hist[hist.length - 1] : null;
    if (!last || last.ip !== st.currentIp) {
      hist.push({ ip: st.currentIp, src: cellular ? "cell" : "fixed", ts: Date.now() });
      try {
        ctx.storage.setJSON(kvHist, hist.slice(-10));
      } catch (e) {}
    }
  }
  return { kvState: kvState, kvHist: kvHist, slot: item.slot, st: st };
}

function isCellIpInHistory(hist, ip) {
  for (let i = 0; i < hist.length; i++) {
    if (hist[i].src === "cell" && hist[i].ip === ip) return true;
  }
  return false;
}

function actionText(st) {
  switch (st.action) {
    case "slot_pin":
      return st.removed ? "钉槽位·顶替 " + st.removed : "钉槽位·新增";
    case "exists":
      return "已在白名单";
    case "added":
      return "已新增";
    case "replaced":
      return st.removed ? "已替换 " + st.removed : "已替换";
    default:
      return st.action || st.msg || "已写入";
  }
}

// 每 token 一行：不含 token，只含 IP / 槽位 / 动作；钉住的槽位标 📌，蜂窝加的 IP 标 📶
function describe(ctx, index, c) {
  const st = c.st;
  const pin = c.slot !== null && c.slot !== undefined && c.slot !== "" ? " 📌" + c.slot : "";
  const head = "#" + (index + 1) + pin + " ";
  if (st.error) return head + "❌ " + st.error;
  if (!st.applied) return head + "❌ 加白未生效 " + (st.msg || "");

  const hist = readHistory(ctx, c.kvHist);
  const cellTag = isCellIpInHistory(hist, st.currentIp) ? " 📶" : "";
  const slotTag = st.slot !== null && st.slot !== undefined ? " (slot " + st.slot + ")" : "";
  return head + "✅ " + st.currentIp + slotTag + cellTag + " · " + actionText(st);
}

export default async function (ctx) {
  try {
    const raw = (ctx.env && ctx.env.tokens) || "";
    const tokens = parseTokens(raw);
    if (tokens.length === 0) {
      // po1 在模块里是可选功能，正常不打扰。但 Egern 没有 Surge 那种面板，
      // 装了没反应时无法区分「脚本没触发」和「触发了但没参数」，所以这里
      // 在原始值变化时提示一次（之后静默），用来定位问题。
      const KEY = "po1_fw_nokey";
      let seen = null;
      try {
        seen = ctx.storage.get(KEY);
      } catch (e) {}
      if (seen !== raw) {
        try {
          ctx.storage.set(KEY, raw);
        } catch (e) {}
        const hint = raw
          ? "收到 tokens1 长度 " + raw.length + "，但没有 ctecsfw_ 开头的条目（占位符可能没被替换）"
          : "tokens1 为空";
        ctx.notify({
          title: "po1 防火墙加白",
          subtitle: "未配置 token（此提示只弹一次）",
          body: hint + "。在模块参数 tokens1 填入 ctecsfw_ token，多个用英文逗号分割",
        });
      }
      return;
    }

    const cellular = onCellular(ctx);
    const results = await Promise.all(
      tokens.map(function (t, i) {
        return ensure(ctx, t, i, cellular);
      })
    );

    let okCount = 0;
    let exitIp = "?";
    let changed = false;
    const lines = [];
    for (let i = 0; i < results.length; i++) {
      const st = results[i].st;
      if (st.applied) okCount++;
      if (st.currentIp) exitIp = st.currentIp;
      lines.push(describe(ctx, i, results[i]));

      const slotKey =
        results[i].slot !== null && results[i].slot !== undefined ? String(results[i].slot) : "-";
      const state = (st.currentIp || "?") + "|" + (st.applied ? "1" : "0") + "|" + slotKey;
      try {
        if (ctx.storage.get(results[i].kvState) !== state) {
          ctx.storage.set(results[i].kvState, state);
          changed = true;
        }
      } catch (e) {
        changed = true;
      }
    }

    const allOk = okCount === results.length;
    const title =
      "po1 加白 " + okCount + "/" + results.length + " · 出口 " + exitIp + (cellular ? " 📶" : "");
    // 成功态仅在出口 IP / 加白状态 / 槽位变化时通知；失败或未生效每次必弹
    if (changed || !allOk) {
      ctx.notify({ title: "po1 防火墙加白", subtitle: title, body: lines.join("\n") });
    }
  } catch (e) {
    const msg = String((e && e.message) || e);
    ctx.notify({ title: "po1 防火墙加白", subtitle: "脚本异常", body: msg });
  }
}
