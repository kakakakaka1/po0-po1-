/*
 * po1 防火墙自动加白（腾讯云 ECS 白名单 / guguyun）
 * 兼容：Surge / Stash / Shadowrocket / Loon / Quantumult X
 *
 * GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>[&slot=N]
 *   把"当前请求源 IP"写入白名单。注意：该接口只认 GET，POST 会落到站点 404 页面。
 *   token 走 query，不在路径里；token 后可跟 @N 表示固定槽位（服务端也认 token 里的
 *   @N，但这里按 po0 的习惯剥成 &slot=N 传，语义一致且便于面板显示）。
 *
 * ⚠️ 该接口的 HTTP 状态码**恒为 200**，真实结果在 body 的 status 字段：
 *     成功 {status:200, msg:"...", data:{cidr,action,mode,slot,changed,matched_cidr,
 *                                     matched_slot,removed_cidr,entry_policy,prefix_length}}
 *     失败 {status:400, msg:"白名单分享链接无效或已失效", data:[]}
 *   所以判定成败必须看 body.status，不能看 response.status。
 *
 * data.action 取值（实测）：
 *   slot_pin  固定槽位写入/顶替（changed=1）
 *   exists    IP 已在白名单，未新增或替换（changed=0，matched_slot=当前槽位）
 *   （槽位无关的写入动作名未实测，脚本按"status=200 且 data.cidr 存在"判定生效）
 *
 * entry_policy 实测为 single_ip / prefix_length=32 —— 与 po0 的 /24 不同，
 * 这里是单 IP 粒度，换 IP 就会占一个新条目。
 *
 * token 来源（优先级从高到低）：
 * 1. argument: tokens=<ctecsfw_xxx>[@槽位],<ctecsfw_yyy>（模块参数）
 * 2. 持久化存储 key "po1fw_tokens"（Quantumult X 等不支持参数的客户端）
 * 3. 下面的 INLINE_TOKENS 常量
 */

var INLINE_TOKENS = "";

var API_BASE = "https://www.guguyun.com/cany_tencentecs/firewall/whitelist";
var TOKEN_PREFIX = "ctecsfw_";
var STORE_PREFIX = "po1_fw_";
var TOKENS_KEY = "po1fw_tokens";
var HIST_WINDOW_MS = 24 * 3600 * 1000;

/* ---------- 环境兼容层 ---------- */

var isQX = typeof $task !== "undefined";
var isSurgeLike = typeof $httpClient !== "undefined";

var envInfo = "";
try {
  if (typeof $environment !== "undefined" && $environment) {
    envInfo = JSON.stringify($environment).toLowerCase();
  }
} catch (e) {}

var isLoon = typeof $loon !== "undefined" || envInfo.indexOf("loon") >= 0;
var isSurgeFamily =
  envInfo.indexOf("surge-version") >= 0 ||
  envInfo.indexOf("shadowrocket") >= 0 ||
  envInfo.indexOf("stash") >= 0;

// timeout 单位：Surge 系是秒，Loon / QX 是毫秒；判定不了就不传，交给模块 timeout=60
var REQUEST_TIMEOUT = null;
if (isLoon || isQX) REQUEST_TIMEOUT = 15000;
else if (isSurgeFamily) REQUEST_TIMEOUT = 15;

function storeRead(key) {
  try {
    if (isQX) return $prefs.valueForKey(key);
    if (typeof $persistentStore !== "undefined") return $persistentStore.read(key);
  } catch (e) {}
  return null;
}

function storeWrite(value, key) {
  try {
    if (isQX) return $prefs.setValueForKey(value, key);
    if (typeof $persistentStore !== "undefined") return $persistentStore.write(value, key);
  } catch (e) {}
  return false;
}

function notify(title, subtitle, body) {
  try {
    if (isQX) $notify(title, subtitle, body);
    else if (typeof $notification !== "undefined") $notification.post(title, subtitle, body);
  } catch (e) {}
}

function safeDecodeURIComponent(s) {
  try {
    return decodeURIComponent(s);
  } catch (e) {
    return s;
  }
}

function describeHttpError(error) {
  var text;
  if (error === null || error === undefined) text = "";
  else if (typeof error === "object")
    text = String(error.message || error.error || error.description || "");
  else text = String(error);
  text = text.replace(/^\s+|\s+$/g, "");
  if (text === "" || text === "null" || text === "undefined" || text === "{}") {
    return "网络请求失败（超时 / 握手失败 / 被拦截）";
  }
  return text;
}

function httpRequestOnce(method, opts) {
  return new Promise(function (resolve) {
    if (isQX) {
      opts.method = method;
      $task.fetch(opts).then(
        function (resp) {
          resolve({ body: resp.body, status: resp.statusCode });
        },
        function (err) {
          resolve({ error: describeHttpError((err && err.error) || err) });
        }
      );
    } else if (isSurgeLike) {
      // 不能把 $httpClient.get 解引用成局部变量 —— Shadowrocket 是 ObjC 桥接对象
      var cb = function (error, response, body) {
        if (error) resolve({ error: describeHttpError(error) });
        else resolve({ body: body, status: response && (response.status || response.statusCode) });
      };
      if (method === "POST") $httpClient.post(opts, cb);
      else $httpClient.get(opts, cb);
    } else {
      resolve({ error: "unsupported client" });
    }
  });
}

function delay(ms) {
  return new Promise(function (resolve) {
    if (typeof setTimeout === "function") setTimeout(resolve, ms);
    else resolve();
  });
}

// GET 天然幂等（服务端对已存在的 IP 返回 exists，不重复写入），重试安全
var HTTP_RETRY = 3;
var HTTP_RETRY_DELAY_MS = 1500;

function isRetryable(r) {
  if (!r) return false;
  if (r.error) return true;
  if (!r.status) return false; // 拿不到状态码，重试也没意义
  if (r.status >= 500 || r.status === 429) return true;
  if (r.status < 200 || r.status >= 300) return false;
  // HTTP 200 但 body 不是 JSON（站点 404 页面 / 网关页）→ 视为瞬时异常
  try {
    JSON.parse(r.body);
    return false;
  } catch (e) {
    return true;
  }
}

function httpRequest(method, opts, attempt) {
  attempt = attempt || 1;
  return httpRequestOnce(method, opts).then(function (r) {
    if (!isRetryable(r)) return r;
    if (attempt >= HTTP_RETRY) {
      if (r.error) r.error = r.error + "（已重试 " + HTTP_RETRY + " 次）";
      else r.retried = HTTP_RETRY;
      return r;
    }
    return delay(HTTP_RETRY_DELAY_MS * attempt).then(function () {
      return httpRequest(method, opts, attempt + 1);
    });
  });
}

function getArgumentTokens() {
  if (typeof $argument === "undefined" || $argument === null) return "";
  if (typeof $argument === "object") return String($argument.tokens || "");
  if (typeof $argument === "string") {
    var arg = $argument.replace(/^\s+|\s+$/g, "");
    if (!arg) return "";
    if (/^["'].*["']$/.test(arg)) arg = arg.slice(1, -1).replace(/^\s+|\s+$/g, "");
    if (arg.charAt(0) === "{") {
      try {
        return String(JSON.parse(arg).tokens || "");
      } catch (e) {}
    }
    var pairs = arg.split("&");
    for (var i = 0; i < pairs.length; i++) {
      var idx = pairs[i].indexOf("=");
      if (idx > 0 && pairs[i].slice(0, idx).replace(/^\s+|\s+$/g, "") === "tokens") {
        return safeDecodeURIComponent(pairs[i].slice(idx + 1).replace(/^\s+|\s+$/g, ""));
      }
    }
    if (arg.indexOf(TOKEN_PREFIX) === 0) return arg;
  }
  return "";
}

function parseTokenEntries(raw) {
  return String(raw || "")
    .split(/[,，|;、\s]+/)
    .map(function (s) {
      return s.replace(/^\s+|\s+$/g, "");
    })
    .filter(function (s) {
      return s.indexOf(TOKEN_PREFIX) === 0;
    })
    .map(function (s) {
      var at = s.indexOf("@");
      if (at === -1) return { token: s, slot: null, invalidError: null };
      var tok = s.slice(0, at);
      var slotRaw = s.slice(at + 1);
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
      if (/[^\x20-\x7E]/.test(item.token)) return false; // 未替换的中文占位符
      if (!/^ctecsfw_[A-Za-z0-9_-]+$/.test(item.token) && !item.invalidError) {
        item.invalidError = "token 含非法字符";
      }
      return true;
    });
}

function onCellular() {
  try {
    var iface =
      ($network.v4 && $network.v4.primaryInterface) ||
      ($network.v6 && $network.v6.primaryInterface) ||
      "";
    return iface.indexOf("pdp_ip") === 0;
  } catch (e) {
    return false;
  }
}

function finish(title, content, allOk) {
  if (isQX) {
    $done();
    return;
  }
  $done({
    title: title,
    content: content,
    icon: allOk ? "checkmark.shield" : "exclamationmark.shield",
    "icon-color": allOk ? "#34C759" : "#FF3B30",
  });
}

/* ---------- 业务逻辑 ---------- */

function readHistory(key) {
  try {
    var h = JSON.parse(storeRead(key) || "[]");
    if (!Array.isArray(h)) return [];
    var cutoff = Date.now() - HIST_WINDOW_MS;
    return h.filter(function (e) {
      return e && e.ts > cutoff;
    });
  } catch (e) {
    return [];
  }
}

function apiCall(token, slot) {
  var url = API_BASE + "?token=" + encodeURIComponent(token);
  if (slot !== null && slot !== undefined && slot !== "") {
    url += "&slot=" + encodeURIComponent(slot);
  }
  var opts = {
    url: url,
    headers: { Accept: "application/json" },
  };
  if (REQUEST_TIMEOUT !== null) opts.timeout = REQUEST_TIMEOUT;

  return httpRequest("GET", opts).then(function (r) {
    if (r.error) return { error: r.error };

    var body = null;
    try {
      body = JSON.parse(r.body);
    } catch (e) {}

    if (!body || typeof body !== "object") {
      return { error: "响应异常: " + String(r.body || "").slice(0, 80) };
    }

    // 该接口 HTTP 恒 200，真实结果看 body.status
    var status = typeof body.status === "number" ? body.status : r.status;
    if (status !== 200) {
      var msg = body.msg || body.message || "请求被拒绝";
      var retrySuffix = r.retried ? "（已重试 " + r.retried + " 次）" : "";
      return { error: "HTTP " + status + ": " + msg + retrySuffix };
    }

    var d = body.data && typeof body.data === "object" ? body.data : {};
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
  });
}

function ensureWhitelisted(item, index) {
  var ctx = {
    kvState: STORE_PREFIX + index,
    kvHist: STORE_PREFIX + "hist_" + index,
    slot: item.slot,
  };

  if (item.invalidError) {
    ctx.st = { error: item.invalidError };
    return Promise.resolve(ctx);
  }

  return apiCall(item.token, item.slot).then(function (st) {
    if (st.applied) {
      var hist = readHistory(ctx.kvHist);
      var last = hist.length ? hist[hist.length - 1] : null;
      if (!last || last.ip !== st.currentIp) {
        hist.push({ ip: st.currentIp, src: onCellular() ? "cell" : "fixed", ts: Date.now() });
        storeWrite(JSON.stringify(hist.slice(-10)), ctx.kvHist);
      }
    }
    ctx.st = st;
    return ctx;
  });
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

// 每 token 一行：不含 token，只含 IP / 槽位 / 动作；蜂窝加的 IP 标 📶
function describe(index, ctx) {
  var st = ctx.st;
  var pin =
    ctx.slot !== null && ctx.slot !== undefined && ctx.slot !== "" ? " 📌" + ctx.slot : "";
  var head = "#" + (index + 1) + pin + " ";
  if (st.error) return head + "❌ " + st.error;
  if (!st.applied) return head + "❌ 加白未生效 " + (st.msg || "");

  var hist = readHistory(ctx.kvHist);
  var cellTag = isCellIpInHistory(hist, st.currentIp) ? " 📶" : "";
  var slotTag = st.slot !== null && st.slot !== undefined ? " (slot " + st.slot + ")" : "";
  return head + "✅ " + st.currentIp + slotTag + cellTag + " · " + actionText(st);
}

function isCellIpInHistory(hist, ip) {
  for (var i = 0; i < hist.length; i++) {
    if (hist[i].src === "cell" && hist[i].ip === ip) return true;
  }
  return false;
}

(function main() {
  try {
    var tokens = parseTokenEntries(
      getArgumentTokens() || storeRead(TOKENS_KEY) || INLINE_TOKENS || ""
    );

    if (tokens.length === 0) {
      // po1 在模块里是可选功能：没填 tokens1 时静默退出，不弹通知，
      // 否则只配了 po0 的人每 10 分钟被吵一次。
      finish(
        "po1 加白：未配置 token",
        "模块参数 tokens1 填入 ctecsfw_ token（多个用 , 或 | 分割）",
        false
      );
      return;
    }

    Promise.all(
      tokens.map(function (t, i) {
        return ensureWhitelisted(t, i);
      })
    )
      .then(function (results) {
        var okCount = 0;
        var exitIp = "?";
        var lines = [];
        var changed = false;

        for (var i = 0; i < results.length; i++) {
          var st = results[i].st;
          if (st.applied) okCount++;
          if (st.currentIp) exitIp = st.currentIp;
          lines.push(describe(i, results[i]));

          var slotKey =
            results[i].slot !== null && results[i].slot !== undefined
              ? String(results[i].slot)
              : "-";
          var state = (st.currentIp || "?") + "|" + (st.applied ? "1" : "0") + "|" + slotKey;
          if (storeRead(results[i].kvState) !== state) {
            storeWrite(state, results[i].kvState);
            changed = true;
          }
        }

        var allOk = okCount === results.length;
        var title =
          "po1 加白 " + okCount + "/" + results.length + " · 出口 " + exitIp + (onCellular() ? " 📶" : "");
        var content = lines.join("\n");

        // 成功态仅在出口 IP / 状态变化时通知；失败必须每次弹，避免错误被静默吞掉
        if (changed || !allOk) {
          notify("po1 防火墙加白", title, content);
        }
        finish(title, content, allOk);
      })
      .catch(function (e) {
        var msg = String(e && e.message ? e.message : e);
        notify("po1 防火墙加白", "脚本异常", msg);
        finish("po1 加白：脚本异常", msg, false);
      });
  } catch (e) {
    var msg = String(e && e.message ? e.message : e);
    notify("po1 防火墙加白", "脚本异常", msg);
    finish("po1 加白：脚本异常", msg, false);
  }
})();
