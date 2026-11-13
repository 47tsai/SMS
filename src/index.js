// Phase 1 (P0) hardening notes:
// - CORS is restricted to the inbox origin; the API key is compared in
//   constant time (SHA-256 digests first); ingest is rate-limited via the
//   SMS_LIMITER binding declared in wrangler.toml.
// - SMS content is still forwarded to Discord in full (user decision); long
//   messages are split across several embed fields instead of being dropped.
// - Retention is 30 days, measured from server-side ingestion time (UTC).
//   Discord copies are a separate copy and are NOT deleted by cleanup.
const ALLOWED_ORIGIN = "https://sms.chi.qzz.io";
const MAX_BODY_BYTES = 32 * 1024; // 32 KiB: message <=3500 chars (~10.5 KiB UTF-8) + overhead
const RETENTION_DAYS = 30;
const DISCORD_FIELD_LIMIT = 1024; // Discord embed field value limit

const corsHeaders = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
};

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders, ...securityHeaders },
  });
}

// Compares two equal-length byte arrays in constant time. Both inputs here
// are SHA-256 digests (32 bytes), so length never leaks information.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function authorized(request, env) {
  const expected = env.SMS_FORWARDER_API_KEY;
  const provided = request.headers.get("X-API-Key") ||
    request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
  if (!expected || !provided) return false;
  // Hash both sides first so the comparison is always over fixed-length digests.
  const encoder = new TextEncoder();
  const [providedHash, expectedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(provided)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  return timingSafeEqual(new Uint8Array(providedHash), new Uint8Array(expectedHash));
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

// Returns true when the request may proceed. Fails open (and logs) when the
// binding is missing or errors, so a limiter outage does not take down SMS
// ingest. The binding itself is declared in wrangler.toml ([[ratelimits]]).
async function checkRateLimit(env, key) {
  if (!env.SMS_LIMITER) return true;
  try {
    const { success } = await env.SMS_LIMITER.limit({ key });
    return success;
  } catch (error) {
    console.error("Rate limiter error:", error?.message || error);
    return true;
  }
}

class BodyTooLargeError extends Error {}

// Reads the request body as text, enforcing MAX_BODY_BYTES even when the
// client sends no Content-Length header.
async function readBodyText(request) {
  const contentLength = request.headers.get("Content-Length");
  if (contentLength !== null && Number(contentLength) > MAX_BODY_BYTES) {
    throw new BodyTooLargeError("Content-Length exceeds limit");
  }
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) throw new BodyTooLargeError("Body exceeds limit");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(body);
}

const MAX_SENDER_LENGTH = 200;
const MAX_MESSAGE_LENGTH = 3500;
const MAX_RECEIVED_AT_LENGTH = 100;

// Validates an ingest payload. Returns { ok: true, value } or
// { ok: false, error }. Over-long or mistyped fields are rejected (400);
// nothing here throws on null / array / non-object input.
function validatePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { ok: false, error: "Request body must be a JSON object" };
  }
  const sender = payload.sender ?? payload.from ?? "未知寄件者";
  const message = payload.message ?? payload.text ?? payload.body;
  const receivedAt = payload.receivedAt ?? payload.time ?? new Date().toISOString();
  if (typeof sender !== "string") return { ok: false, error: "sender must be a string" };
  if (sender.length > MAX_SENDER_LENGTH) return { ok: false, error: "sender is too long" };
  if (typeof message !== "string" || !message.trim()) return { ok: false, error: "Missing message" };
  if (message.length > MAX_MESSAGE_LENGTH) return { ok: false, error: "message is too long" };
  if (typeof receivedAt !== "string") return { ok: false, error: "receivedAt must be a string" };
  if (receivedAt.length > MAX_RECEIVED_AT_LENGTH) return { ok: false, error: "receivedAt is too long" };
  return { ok: true, value: { sender: sender || "未知寄件者", message, receivedAt: receivedAt || new Date().toISOString() } };
}

// Idempotency key for one SMS: SHA-256 over sender + message + receivedAt.
// A retry from the iOS Shortcut therefore stores and notifies only once.
async function computeIdempotencyKey(sender, message, receivedAt) {
  const data = new TextEncoder().encode([sender, message, receivedAt].join("\n"));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Splits a message into Discord embed field values of at most 1024
// characters each, without splitting a Unicode code point (e.g. emoji)
// across fields. Chunks joined in order reproduce the original message,
// so the full text still reaches Discord.
function splitMessageForDiscord(message) {
  const chars = Array.from(message);
  const chunks = [];
  for (let i = 0; i < chars.length; i += DISCORD_FIELD_LIMIT) {
    chunks.push(chars.slice(i, i + DISCORD_FIELD_LIMIT).join(""));
  }
  return chunks.length ? chunks : [""];
}

function messageFields(message) {
  const chunks = splitMessageForDiscord(message);
  if (chunks.length === 1) return [{ name: "💬 簡訊內容", value: chunks[0] || "(空白)", inline: false }];
  return chunks.map((chunk, i) => ({
    name: `💬 簡訊內容（${i + 1}/${chunks.length}）`,
    value: chunk,
    inline: false,
  }));
}

// Escapes one CSV cell value. A leading formula character (=, +, -, @, tab,
// CR) is neutralised with a leading single quote so spreadsheets do not
// execute the cell as a formula. (The inbox page inlines the same logic;
// keep the two in sync.)
function escapeCsvCell(value) {
  let text = String(value ?? "");
  if (/^[=+\-@\t\r]/.test(text.trimStart())) text = "'" + text;
  return '"' + text.replace(/"/g, '""') + '"';
}

export { validatePayload, computeIdempotencyKey, splitMessageForDiscord, messageFields, escapeCsvCell, timingSafeEqual };


function extractVerificationCode(message) {
  const text = String(message || "");
  const candidates = [...text.matchAll(/(?<![0-9])[0-9]{4,8}(?![0-9])/g)];
  if (!candidates.length) return "";
  const keyword = /碼|码|code/i;
  const keywords = [...text.matchAll(new RegExp(keyword.source, "gi"))];
  if (!keywords.length) return "";
  let best = null;
  for (const candidate of candidates) {
    const codeStart = candidate.index;
    const codeEnd = codeStart + candidate[0].length;
    for (const word of keywords) {
      const wordStart = word.index;
      const wordEnd = wordStart + word[0].length;
      const distance = wordEnd < codeStart
        ? codeStart - wordEnd
        : codeEnd < wordStart
          ? wordStart - codeEnd
          : 0;
      if (distance <= 64 && (!best || distance < best.distance)) {
        best = { code: candidate[0], distance };
      }
    }
  }
  return best ? best.code : "";
}

const SMS_CHI_AUTH_CLIENT_ID = "z2gX_1zn_jmwhnoia2JiVY6FeuTyPcun";

// Returns "ok" | "unauthorized" | "upstream_error" so callers can tell an
// invalid/expired token (401) apart from a Chi Auth outage (502).
// Never logs tokens or message content.
async function checkChiAuth(request) {
  const authorization = request.headers.get("Authorization") || "";
  if (!/^Bearer [A-Za-z0-9_-]{40,80}$/.test(authorization)) return "unauthorized";
  let response;
  try {
    response = await fetch("https://auth.chi.qzz.io/api/userinfo?client_id=" + encodeURIComponent(SMS_CHI_AUTH_CLIENT_ID), {
      headers: { Authorization: authorization, Accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
  } catch (error) {
    console.error("Chi Auth userinfo request failed:", error?.message || error);
    return "upstream_error";
  }
  if (!response.ok) {
    if (response.status >= 500) {
      console.error("Chi Auth userinfo returned HTTP", response.status);
      return "upstream_error";
    }
    return "unauthorized";
  }
  let identity;
  try {
    identity = await response.json();
  } catch (error) {
    console.error("Chi Auth userinfo returned invalid JSON:", error?.message || error);
    return "upstream_error";
  }
  return identity.sub === "chi-owner" && identity.aud === SMS_CHI_AUTH_CLIENT_ID ? "ok" : "unauthorized";
}

// Returns a Response when the request must not proceed, or null when the
// caller is authenticated as chi-owner.
async function requireChiAuth(request) {
  const status = await checkChiAuth(request);
  if (status === "upstream_error") return json({ error: "Authentication service is unavailable" }, 502);
  if (status !== "ok") return json({ error: "Unauthorized" }, 401);
  return null;
}

function page() {
  return new Response(String.raw`<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f6f8fc">
<meta name="description" content="Chi SMS 簡訊收件匣">
<meta name="referrer" content="no-referrer">
<link rel="icon" type="image/png" href="https://raw.githubusercontent.com/47tsai/chi-design-system/main/logo/blue-w.png">
<title>Chi SMS · 簡訊收件匣</title>
<link rel="stylesheet" href="https://chi.qzz.io/chi-design-system/tokens.css">
<link rel="stylesheet" href="https://chi.qzz.io/chi-design-system/components.css">
<link rel="stylesheet" href="https://chi.qzz.io/chi-design-system/navigation.css">
<style>
:root{font-synthesis:none}
html{min-height:100%;scroll-behavior:smooth}
body.chi-page{display:flex;min-height:100vh;min-height:100dvh;flex-direction:column}
.chi-site-header__inner{min-height:64px}
.sms-brand{display:inline-flex;align-items:center;gap:.65rem;color:var(--chi-color-text-strong);text-decoration:none;font-weight:750;letter-spacing:-.02em}
.sms-brand img{display:block;width:2rem;height:2rem;object-fit:contain}
.sms-brand .logo-dark{display:none}
[data-chi-theme=dark] .sms-brand .logo-light{display:none}
[data-chi-theme=dark] .sms-brand .logo-dark{display:block}
.sms-header-actions{display:flex;align-items:center;gap:.5rem}
.sms-theme{max-width:9rem;min-height:40px;padding:.4rem .6rem;border:1px solid var(--chi-color-border-strong);border-radius:var(--chi-radius-md);background:var(--chi-color-surface);color:var(--chi-color-text);font:inherit;font-size:var(--chi-text-sm)}
.sms-main{flex:1;width:min(calc(100% - 2.5rem),880px);margin:0 auto;padding:2.25rem 0 4rem}
.sms-page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:1rem;margin-bottom:1.75rem}
.sms-page-head h1{margin:0;color:var(--chi-color-text-strong);font-size:var(--chi-text-2xl);line-height:var(--chi-leading-tight);letter-spacing:-.035em}
.sms-page-head p{margin:.55rem 0 0;color:var(--chi-color-text-muted)}
.sms-section-label{margin:0 0 .75rem;color:var(--chi-color-text-muted);font-size:var(--chi-text-xs);font-weight:700;letter-spacing:.07em}
.sms-login{max-width:480px;margin:3rem auto}
.sms-login h2{margin:0;color:var(--chi-color-text-strong);font-size:var(--chi-text-xl)}
.sms-login .chi-description{margin:.5rem 0 1.25rem;text-align:left;font-size:var(--chi-text-sm)}
.sms-form{display:flex;flex-direction:column;gap:.85rem}
.sms-field{display:flex;flex-direction:column;gap:.4rem}
.sms-toolbar{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:.75rem;margin-bottom:1rem}
.sms-toolbar-actions{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.sms-list{display:flex;flex-direction:column;gap:.75rem}
.sms-item{padding:1.1rem 1.2rem;border:1px solid var(--chi-color-border);border-radius:var(--chi-radius-lg);background:var(--chi-color-surface)}
.sms-item-head{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem}
.sms-sender{margin:0;color:var(--chi-color-text-strong);font-size:var(--chi-text-md);font-weight:700;overflow-wrap:anywhere}
.sms-time{flex:none;color:var(--chi-color-text-muted);font-size:var(--chi-text-xs);text-align:right}
.sms-message{margin:.85rem 0 0;color:var(--chi-color-text);white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.75}
.sms-code-row{display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-top:1rem;padding:.7rem .8rem;border:1px solid var(--chi-color-accent-border);border-radius:var(--chi-radius-md);background:var(--chi-color-accent-soft)}
.sms-code-label{display:block;margin-bottom:.1rem;color:var(--chi-color-text-muted);font-size:var(--chi-text-xs)}
.sms-code{color:var(--chi-color-text-strong);font-family:var(--chi-font-mono);font-size:1.35rem;font-weight:750;letter-spacing:.08em;overflow-wrap:anywhere}
.sms-item-actions{display:flex;justify-content:flex-end;gap:.5rem;flex-wrap:wrap;margin-top:1rem}
.sms-item-actions .chi-button{min-height:36px;padding-inline:.8rem;font-size:var(--chi-text-xs)}
.sms-item-actions .sms-delete{color:var(--chi-color-danger,var(--chi-color-text));border-color:var(--chi-color-border-strong)}
.sms-hidden{display:none!important}
.sms-status{min-height:1.5rem;margin:.5rem 0;color:var(--chi-color-text-muted);font-size:var(--chi-text-sm)}
.sms-toast{position:fixed;right:1rem;bottom:1rem;z-index:50;max-width:min(26rem,calc(100vw - 2rem));padding:.75rem 1rem;border:1px solid var(--chi-color-border-strong);border-radius:var(--chi-radius-md);background:var(--chi-color-surface-raised);color:var(--chi-color-text);box-shadow:var(--chi-shadow-md)}
.sms-footer{border-top:1px solid var(--chi-color-border);background:var(--chi-color-surface)}
.sms-footer-inner{display:flex;min-height:60px;align-items:center;justify-content:space-between;gap:1rem;padding-block:1rem;color:var(--chi-color-text-muted);font-size:var(--chi-text-xs)}
.sms-footer a{color:inherit;text-decoration:none}
.sms-footer a:hover{color:var(--chi-color-accent)}
button:disabled{opacity:.6;cursor:wait}
@media(max-width:620px){
 .chi-container{width:calc(100% - 1.5rem)}
 .sms-main{width:calc(100% - 1.5rem);padding-top:1.5rem}
 .sms-page-head{align-items:flex-start;flex-direction:column}
 .sms-toolbar{grid-template-columns:1fr}
 .sms-toolbar-actions{justify-content:space-between}
 .sms-item{padding:1rem}
 .sms-item-head{flex-direction:column;gap:.35rem}
 .sms-time{text-align:left}
 .sms-footer-inner{align-items:flex-start;flex-direction:column;justify-content:center;gap:.25rem}
 .sms-theme{max-width:7.5rem}
}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important}}
</style>
</head>
<body class="chi-page">
<a class="chi-skip-link" href="#main-content">跳至主要內容</a>
<header class="chi-site-header">
  <div class="chi-container chi-site-header__inner">
    <a class="sms-brand" href="/" aria-label="Chi SMS 首頁">
      <img class="logo-light" src="https://raw.githubusercontent.com/47tsai/chi-design-system/main/logo/blue-b.png" alt="">
      <img class="logo-dark" src="https://raw.githubusercontent.com/47tsai/chi-design-system/main/logo/blue-w.png" alt="">
      <span>CHI SMS</span>
    </a>
    <div class="sms-header-actions">
      <select id="theme" class="sms-theme" aria-label="色彩主題">
        <option value="system">跟隨系統</option>
        <option value="light">淺色</option>
        <option value="dark">深色</option>
      </select>
      <button id="logout" class="chi-button sms-hidden" type="button">登出</button>
    </div>
  </div>
</header>
<main class="sms-main" id="main-content" tabindex="-1">
  <section id="login" class="chi-panel sms-login">
    <p class="sms-section-label">PRIVATE INBOX</p>
    <h2>登入簡訊收件匣</h2>
    <p class="chi-description">使用 Chi Auth 與已註冊的 Passkey 安全登入。Chi SMS 不會保存你的 Chi Auth 密碼或 Passkey。</p>
    <button id="loginChiAuth" class="chi-button chi-button--primary" type="button">使用 Chi Auth 登入</button>
    <p id="loginStatus" class="sms-status" role="status" aria-live="polite"></p>
  </section>
  <section id="inbox" class="sms-hidden">
    <div class="sms-page-head">
      <div><p class="sms-section-label">MESSAGES</p><h1>簡訊收件匣</h1><p>集中查看轉發簡訊，驗證碼可直接複製。</p></div>
      <span id="count" class="chi-badge">0 則簡訊</span>
    </div>
    <div class="sms-toolbar">
      <input id="search" class="chi-input" type="search" placeholder="搜尋寄件者或簡訊內容" aria-label="搜尋寄件者或簡訊內容">
      <div class="sms-toolbar-actions">
        <button id="refresh" class="chi-button" type="button">重新整理</button>
        <button id="export" class="chi-button" type="button">匯出 CSV</button>
        <button id="clear" class="chi-button chi-button--danger" type="button">清除全部簡訊</button>
      </div>
    </div>
    <p id="status" class="sms-status" role="status" aria-live="polite"></p>
    <div id="items" class="sms-list"></div>
  </section>
</main>
<footer class="sms-footer"><div class="chi-container sms-footer-inner"><span>CHI SMS · 私人簡訊收件匣</span><a href="https://chi.qzz.io/chi-design-system/" target="_blank" rel="noreferrer">Chi Design System</a></div></footer>
<div id="toast" class="sms-toast sms-hidden" role="status" aria-live="polite"></div>
<script>
(() => {
  const root = document.documentElement;
  const themeSelect = document.getElementById("theme");
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const savedTheme = () => { try { return localStorage.getItem("chi-sms-theme") || "system"; } catch { return "system"; } };
  let theme = savedTheme();
  function applyTheme(value) {
    theme = value;
    if (value === "dark" || (value === "system" && media.matches)) root.setAttribute("data-chi-theme", "dark");
    else root.removeAttribute("data-chi-theme");
    themeSelect.value = value;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = root.getAttribute("data-chi-theme") === "dark" ? "#17191f" : "#f6f8fc";
  }
  applyTheme(theme);
  themeSelect.addEventListener("change", () => {
    applyTheme(themeSelect.value);
    try { localStorage.setItem("chi-sms-theme", themeSelect.value); } catch {}
  });
  media.addEventListener?.("change", () => { if (theme === "system") applyTheme("system"); });

  let accessToken = "";
  try { accessToken = sessionStorage.getItem("chi-sms-access-token") || ""; } catch {}
  function setAccessToken(value) {
    accessToken = value || "";
    try {
      if (accessToken) sessionStorage.setItem("chi-sms-access-token", accessToken);
      else sessionStorage.removeItem("chi-sms-access-token");
    } catch {}
  }
  let toastTimer;
  const AUTH_ORIGIN = "https://auth.chi.qzz.io";
  const CHI_AUTH_CLIENT_ID = "${SMS_CHI_AUTH_CLIENT_ID}";
  const REDIRECT_URI = "https://sms.chi.qzz.io/";
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
  function showToast(message) {
    $("toast").textContent = message;
    $("toast").classList.remove("sms-hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => $("toast").classList.add("sms-hidden"), 2200);
  }
  function showInbox(on) {
    $("login").classList.toggle("sms-hidden", on);
    $("inbox").classList.toggle("sms-hidden", !on);
    $("logout").classList.toggle("sms-hidden", !on);
  }
  function extractCode(message) {
    const text = String(message || "");
    // Match standalone 4–8 digit codes, including codes prefixed with letters (e.g. G-718604).
    const candidates = [...text.matchAll(/(?<![0-9])[0-9]{4,8}(?![0-9])/g)];
    if (!candidates.length) return "";

    const keyword = /碼|码|code/i;
    const keywords = [...text.matchAll(new RegExp(keyword.source, "gi"))];
    if (keywords.length) {
      // Choose the numeric candidate nearest to a verification-code phrase.
      // This handles both “驗證碼：123456” and “G-123456 is your Google verification code”.
      let best = null;
      for (const candidate of candidates) {
        const codeStart = candidate.index;
        const codeEnd = codeStart + candidate[0].length;
        for (const word of keywords) {
          const wordStart = word.index;
          const wordEnd = wordStart + word[0].length;
          const distance = wordEnd < codeStart
            ? codeStart - wordEnd
            : codeEnd < wordStart
              ? wordStart - codeEnd
              : 0;
          if (distance <= 64 && (!best || distance < best.distance)) {
            best = { code: candidate[0], distance };
          }
        }
      }
      if (best) return best.code;
    }

    // Avoid mistaking order numbers, phone fragments, or unrelated IDs for verification codes.
    return "";
  }
  function formatDate(value) {
    if (value === null || value === undefined || value === "") return "時間未知";
    const raw = String(value).trim();
    const numeric = /^\d{10,13}$/.test(raw) ? Number(raw) : null;
    const date = new Date(numeric === null ? raw : (numeric < 1e12 ? numeric * 1000 : numeric));
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("zh-TW", { timeZone: "Asia/Taipei", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(date);
  }
  async function copyText(value, label) {
    try {
      await navigator.clipboard.writeText(value);
      showToast(label + "已複製");
    } catch {
      const area = document.createElement("textarea");
      area.value = value;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      const copied = document.execCommand("copy");
      area.remove();
      showToast(copied ? label + "已複製" : "複製失敗，請手動選取文字");
    }
  }
  async function load() {
    $("status").textContent = "正在載入簡訊…";
    try {
      const response = await fetch("/api/messages", { headers: { Authorization: "Bearer " + accessToken } });
      if (response.status === 401) {
        setAccessToken("");
        showInbox(false);
        $("loginStatus").textContent = "Chi Auth 授權已過期或失效，請重新登入。";
        throw new Error("授權已失效，請重新登入。");
      }
      if (!response.ok) throw new Error("讀取失敗，請稍後重試（" + response.status + "）。");
      const data = await response.json();
      window.smsMessages = data.messages || [];
      render();
      $("status").textContent = "";
    } catch (error) {
      $("status").textContent = error.message || "讀取失敗。";
    }
  }
  function render() {
    const query = $("search").value.trim().toLocaleLowerCase();
    const messages = (window.smsMessages || []).filter(message => (String(message.sender || "") + " " + String(message.message || "")).toLocaleLowerCase().includes(query));
    const codes = messages.filter(message => extractCode(message.message)).length;
    $("count").textContent = messages.length + " 則簡訊" + (codes ? " · " + codes + " 則含驗證碼" : "");
    if (!messages.length) {
      $("items").innerHTML = '<div class="chi-empty"><p>目前沒有符合的簡訊</p><p class="chi-help">收到新訊息後，會自動出現在這裡。</p></div>';
      return;
    }
    $("items").innerHTML = messages.map(message => {
      const code = extractCode(message.message);
      return '<article class="sms-item"><div class="sms-item-head"><h2 class="sms-sender">' + esc(message.sender || "未知寄件者") + '</h2><time class="sms-time">' + esc(formatDate(message.received_at)) + '</time></div>' +
        '<div class="sms-message">' + esc(message.message) + '</div>' +
        (code ? '<div class="sms-code-row"><div><span class="sms-code-label">偵測到驗證碼</span><span class="sms-code">' + esc(code) + '</span></div><button class="chi-button chi-button--primary" type="button" data-copy-code="' + esc(code) + '">複製驗證碼</button></div>' : '') +
        '<div class="sms-item-actions"><button class="chi-button" type="button" data-copy-message="' + esc(message.id) + '">複製完整簡訊</button><button class="chi-button sms-delete" type="button" data-delete-message="' + esc(message.id) + '">刪除此則</button></div></article>';
    }).join("");
  }
  function base64Url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function randomVerifier() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return base64Url(bytes);
  }
  async function createChallenge(verifier) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return base64Url(new Uint8Array(digest));
  }
  async function startChiAuthLogin() {
    if (!CHI_AUTH_CLIENT_ID || CHI_AUTH_CLIENT_ID.includes("__")) {
      $("loginStatus").textContent = "Chi Auth 尚未完成應用註冊，請先在 Chi Auth 登記 Chi SMS 回呼網址。";
      return;
    }
    $("loginChiAuth").disabled = true;
    $("loginStatus").textContent = "正在前往 Chi Auth…";
    try {
      const state = randomVerifier();
      const verifier = randomVerifier();
      sessionStorage.setItem("chi-sms-oauth-state", state);
      sessionStorage.setItem("chi-sms-oauth-verifier", verifier);
      const params = new URLSearchParams({
        response_type: "code",
        client_id: CHI_AUTH_CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_challenge: await createChallenge(verifier),
        code_challenge_method: "S256",
        state,
      });
      location.assign(AUTH_ORIGIN + "/api/authorize?" + params.toString());
    } catch (error) {
      $("loginStatus").textContent = error.message || "無法啟動 Chi Auth 登入。";
      $("loginChiAuth").disabled = false;
    }
  }
  async function completeChiAuthCallback() {
    const params = new URLSearchParams(location.search);
    const code = params.get("code");
    const returnedState = params.get("state");
    const authError = params.get("error");
    if (!code && !authError) {
      if (accessToken) {
        showInbox(true);
        await load();
      }
      return;
    }
    history.replaceState({}, document.title, location.pathname);
    if (authError) {
      $("loginStatus").textContent = "Chi Auth 登入未完成：" + authError;
      sessionStorage.removeItem("chi-sms-oauth-state");
      sessionStorage.removeItem("chi-sms-oauth-verifier");
      return;
    }
    const expectedState = sessionStorage.getItem("chi-sms-oauth-state");
    const verifier = sessionStorage.getItem("chi-sms-oauth-verifier");
    sessionStorage.removeItem("chi-sms-oauth-state");
    sessionStorage.removeItem("chi-sms-oauth-verifier");
    if (!expectedState || !verifier || !returnedState || returnedState !== expectedState) {
      $("loginStatus").textContent = "登入驗證失敗，請重新嘗試。";
      return;
    }
    $("loginStatus").textContent = "正在完成 Chi Auth 登入…";
    $("loginChiAuth").disabled = true;
    try {
      const response = await fetch(AUTH_ORIGIN + "/api/token?client_id=" + encodeURIComponent(CHI_AUTH_CLIENT_ID), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          client_id: CHI_AUTH_CLIENT_ID,
          code,
          redirect_uri: REDIRECT_URI,
          code_verifier: verifier,
        }),
        cache: "no-store",
      });
      const token = await response.json().catch(() => ({}));
      if (!response.ok || typeof token.access_token !== "string") {
        throw new Error(token.error || "Chi Auth 授權碼交換失敗。");
      }
      setAccessToken(token.access_token);
      const identity = await fetch(AUTH_ORIGIN + "/api/userinfo?client_id=" + encodeURIComponent(CHI_AUTH_CLIENT_ID), {
        headers: { Authorization: "Bearer " + accessToken },
        cache: "no-store",
      });
      if (!identity.ok) throw new Error("無法驗證 Chi Auth 身分，請重新登入。");
      const user = await identity.json();
      if (user.sub !== "chi-owner") throw new Error("此 Chi Auth 帳號無權存取收件匣。");
      showInbox(true);
      await load();
      $("loginStatus").textContent = "";
    } catch (error) {
      setAccessToken("");
      showInbox(false);
      $("loginStatus").textContent = error.message || "Chi Auth 登入失敗。";
    } finally {
      $("loginChiAuth").disabled = false;
    }
  }
  $("loginChiAuth").addEventListener("click", startChiAuthLogin);
  void completeChiAuthCallback();
  $("refresh").addEventListener("click", load);
  $("clear").addEventListener("click", async () => {
    if (!(window.smsMessages || []).length) {
      showToast("目前沒有簡訊可清除");
      return;
    }
    if (!window.confirm("確定清除資料庫中的全部簡訊？此操作無法復原，也不會刪除 Discord 中的通知。")) return;
    const button = $("clear");
    button.disabled = true;
    $("status").textContent = "正在清除簡訊…";
    try {
      const response = await fetch("/api/messages/clear", {
        method: "POST",
        headers: { Authorization: "Bearer " + accessToken },
      });
      if (response.status === 401) {
        setAccessToken("");
        showInbox(false);
        throw new Error("Chi Auth 授權已過期，請重新登入。");
      }
      if (!response.ok) throw new Error("清除失敗（" + response.status + "）。");
      window.smsMessages = [];
      render();
      $("status").textContent = "";
      showToast("已清除全部簡訊");
    } catch (error) {
      $("status").textContent = error.message || "清除失敗。";
    } finally {
      button.disabled = false;
    }
  });
  $("search").addEventListener("input", render);
  $("items").addEventListener("click", event => {
    const codeButton = event.target.closest("[data-copy-code]");
    if (codeButton) { copyText(codeButton.getAttribute("data-copy-code"), "驗證碼"); return; }
    const messageButton = event.target.closest("[data-copy-message]");
    if (messageButton) {
      const message = (window.smsMessages || []).find(item => String(item.id) === messageButton.getAttribute("data-copy-message"));
      if (message) copyText(String(message.message || ""), "完整簡訊");
      return;
    }
    const deleteButton = event.target.closest("[data-delete-message]");
    if (deleteButton) {
      const id = deleteButton.getAttribute("data-delete-message");
      const message = (window.smsMessages || []).find(item => String(item.id) === id);
      if (!message) return;
      if (!window.confirm("確定刪除這則簡訊？此操作無法復原，也不會刪除 Discord 中的通知。")) return;
      deleteButton.disabled = true;
      fetch("/api/messages/" + encodeURIComponent(id), {
        method: "DELETE",
        headers: { Authorization: "Bearer " + accessToken },
      }).then(async response => {
        if (response.status === 401) {
          setAccessToken("");
          showInbox(false);
          throw new Error("Chi Auth 授權已過期，請重新登入。");
        }
        if (!response.ok) throw new Error("刪除失敗（" + response.status + "）。");
        window.smsMessages = (window.smsMessages || []).filter(item => String(item.id) !== id);
        render();
        showToast("已刪除這則簡訊");
      }).catch(error => {
        $("status").textContent = error.message || "刪除失敗。";
      });
    }
  });
  $("export").addEventListener("click", () => {
    const messages = (window.smsMessages || []).filter(message => {
      const query = $("search").value.trim().toLocaleLowerCase();
      return (String(message.sender || "") + " " + String(message.message || "")).toLocaleLowerCase().includes(query);
    });
    if (!messages.length) {
      showToast("沒有可匯出的簡訊");
      return;
    }
    // Same formula-injection guard as escapeCsvCell() above: neutralise a
    // leading =, +, -, @, tab or CR with a leading single quote.
    const quote = value => {
      let text = String(value ?? "");
      if (/^[=+\-@\t\r]/.test(text.trimStart())) text = "'" + text;
      return '"' + text.replace(/"/g, '""') + '"';
    };
    const rows = [
      ["寄件者", "簡訊內容", "收到時間", "驗證碼"],
      ...messages.map(message => [message.sender || "未知寄件者", message.message || "", message.received_at || "", extractCode(message.message)])
    ];
    const csv = "\uFEFF" + rows.map(row => row.map(quote).join(",")).join("\r\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "chi-sms-" + new Date().toISOString().slice(0, 10) + ".csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast("已匯出 " + messages.length + " 則簡訊");
  });
  $("logout").addEventListener("click", () => {
    setAccessToken("");
    window.smsMessages = [];
    $("items").innerHTML = "";
    $("search").value = "";
    $("status").textContent = "";
    $("loginStatus").textContent = "";
    showInbox(false);
    $("loginChiAuth").focus();
  });
})();
</script>
</body>
</html>`, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      // The page is a single file with inline <style>/<script>, so
      // 'unsafe-inline' is required for now; the policy still blocks
      // framing and restricts every other source to the Chi origins.
      "Content-Security-Policy": "default-src 'self'; style-src 'self' https://chi.qzz.io 'unsafe-inline'; img-src 'self' https://raw.githubusercontent.com data:; font-src 'self' https://chi.qzz.io; script-src 'self' 'unsafe-inline'; connect-src 'self' https://auth.chi.qzz.io; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      ...securityHeaders,
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      const origin = request.headers.get("Origin");
      if (origin && origin !== ALLOWED_ORIGIN) return new Response(null, { status: 403, headers: corsHeaders });
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method === "GET" && url.pathname === "/") return page();

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ service: "SMS Forwarder", status: "ok" });
    }

    if (request.method === "GET" && url.pathname === "/api/messages") {
      const authError = await requireChiAuth(request);
      if (authError) return authError;
      if (!env.SMS_DB) return json({ error: "Database is not configured" }, 503);
      try {
        const result = await env.SMS_DB.prepare(
          "SELECT id, sender, message, received_at FROM messages ORDER BY id DESC LIMIT 500"
        ).all();
        return json({ messages: result.results || [] });
      } catch (error) {
        console.error("Could not read messages:", error?.message || error);
        return json({ error: "Could not read messages" }, 500);
      }
    }

    const messageDeleteMatch = url.pathname.match(/^\/api\/messages\/(\d+)$/);
    if (request.method === "DELETE" && messageDeleteMatch) {
      const authError = await requireChiAuth(request);
      if (authError) return authError;
      if (!(await checkRateLimit(env, `admin:${clientIp(request)}`))) {
        return json({ error: "Too many requests" }, 429);
      }
      if (!env.SMS_DB) return json({ error: "Database is not configured" }, 503);
      const id = Number(messageDeleteMatch[1]);
      if (!Number.isSafeInteger(id) || id < 1) return json({ error: "Invalid message ID" }, 400);
      try {
        const result = await env.SMS_DB.prepare("DELETE FROM messages WHERE id = ?").bind(id).run();
        if (!Number(result.meta?.changes || 0)) return json({ error: "Message not found" }, 404);
        return json({ ok: true, deleted: id });
      } catch (error) {
        console.error("Could not delete message:", error?.message || error);
        return json({ error: "Could not delete message" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/messages/clear") {
      const authError = await requireChiAuth(request);
      if (authError) return authError;
      if (!(await checkRateLimit(env, `admin:${clientIp(request)}`))) {
        return json({ error: "Too many requests" }, 429);
      }
      if (!env.SMS_DB) return json({ error: "Database is not configured" }, 503);
      try {
        const result = await env.SMS_DB.prepare("DELETE FROM messages").run();
        return json({ ok: true, cleared: Number(result.meta?.changes || 0) });
      } catch (error) {
        console.error("Could not clear messages:", error?.message || error);
        return json({ error: "Could not clear messages" }, 500);
      }
    }

    if (request.method !== "POST" || !["/", "/sms"].includes(url.pathname)) {
      return json({ error: "Not found" }, 404);
    }

    // Ingest path: rate-limit per client IP first (before auth, so API-key
    // guessing is also throttled), then authenticate with a timing-safe
    // comparison, then enforce the body size limit before parsing.
    if (!(await checkRateLimit(env, `ingest:${clientIp(request)}`))) {
      return json({ error: "Too many requests" }, 429);
    }
    if (!(await authorized(request, env))) return json({ error: "Unauthorized" }, 401);

    let rawBody;
    try {
      rawBody = await readBodyText(request);
    } catch (error) {
      if (error instanceof BodyTooLargeError) {
        return json({ error: "Request body too large", limitBytes: MAX_BODY_BYTES }, 413);
      }
      console.error("Could not read request body:", error?.message || error);
      return json({ error: "Could not read request body" }, 400);
    }
    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return json({ error: "Request body must be valid JSON" }, 400);
    }
    const validation = validatePayload(payload);
    if (!validation.ok) return json({ error: validation.error }, 400);
    const { sender, message, receivedAt } = validation.value;

    // Idempotency: the same (sender, message, receivedAt) is stored and
    // notified only once, so an iOS Shortcut retry cannot duplicate it.
    let savedId = null;
    let duplicate = false;
    if (env.SMS_DB) {
      const idempotencyKey = await computeIdempotencyKey(sender, message, receivedAt);
      try {
        const existing = await env.SMS_DB.prepare(
          "SELECT id FROM messages WHERE idempotency_key = ?"
        ).bind(idempotencyKey).first();
        if (existing) {
          duplicate = true;
          savedId = existing.id;
        } else {
          const inserted = await env.SMS_DB.prepare(
            "INSERT INTO messages (sender, message, received_at, idempotency_key, expires_at) VALUES (?, ?, ?, ?, datetime('now', '+30 days'))"
          ).bind(sender, message, receivedAt, idempotencyKey).run();
          savedId = inserted.meta?.last_row_id ?? null;
        }
      } catch (error) {
        // A concurrent identical request may have inserted first; treat the
        // unique-index conflict as a duplicate instead of failing.
        if (/UNIQUE constraint failed/i.test(error?.message || "")) {
          try {
            const existing = await env.SMS_DB.prepare(
              "SELECT id FROM messages WHERE idempotency_key = ?"
            ).bind(idempotencyKey).first();
            if (existing) { duplicate = true; savedId = existing.id; }
          } catch (lookupError) {
            console.error("Could not look up duplicate message:", lookupError?.message || lookupError);
          }
          if (!duplicate) return json({ error: "Could not save message to database" }, 500);
        } else {
          console.error("Could not save message to database:", error?.message || error);
          return json({ error: "Could not save message to database" }, 500);
        }
      }
    }
    if (duplicate) {
      return json({ ok: true, saved: Boolean(env.SMS_DB), duplicate: true, id: savedId, discord: { ok: true, skipped: "duplicate" } });
    }

    if (!env.DISCORD_WEBHOOK_URL) {
      return json({ ok: false, saved: Boolean(env.SMS_DB), id: savedId, discord: { ok: false, error: "Discord webhook is not configured" } }, 500);
    }

    const verificationCode = extractVerificationCode(message);
    // Android may send Unix milliseconds as a string; iOS may send an ISO date.
    const receivedAtText = String(receivedAt).trim();
    const receivedAtNumber = /^\d{10,13}$/.test(receivedAtText) ? Number(receivedAtText) : null;
    const receivedDate = new Date(receivedAtNumber === null ? receivedAtText : (receivedAtNumber < 1e12 ? receivedAtNumber * 1000 : receivedAtNumber));
    const validReceivedDate = Number.isNaN(receivedDate.getTime()) ? null : receivedDate;
    const discordReceivedAt = validReceivedDate
      ? new Intl.DateTimeFormat("zh-TW", { timeZone: "Asia/Taipei", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(validReceivedDate)
      : receivedAt;
    const discordFields = [
      { name: "📱 寄件者", value: sender, inline: true },
      { name: "🕒 收到時間", value: discordReceivedAt, inline: true },
    ];
    if (verificationCode) {
      discordFields.push({
        name: "🔐 驗證碼",
        value: "`" + verificationCode + "`",
        inline: false,
      });
    }
    // The full message is sent, split across fields if it exceeds Discord's
    // 1024-character per-field limit (see messageFields()).
    discordFields.push(...messageFields(message));

    const discordPayload = {
      username: "SMS Forwarder",
      allowed_mentions: { parse: [] },
      embeds: [{
        title: verificationCode ? "🔐 收到簡訊驗證碼" : "📩 收到新簡訊",
        color: 5793266,
        fields: discordFields,
        footer: { text: "Android SMS Forwarder" },
        timestamp: (validReceivedDate || new Date()).toISOString(),
      }],
    };

    let discordResponse;
    try {
      discordResponse = await fetch(env.DISCORD_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(discordPayload),
        signal: AbortSignal.timeout(10000),
      });
    } catch (error) {
      console.error("Could not reach Discord:", error?.message || error);
      return json({ ok: false, saved: Boolean(env.SMS_DB), id: savedId, discord: { ok: false, error: "Could not reach Discord" } }, 502);
    }

    if (!discordResponse.ok) {
      console.error("Discord rejected the message: HTTP", discordResponse.status);
      return json({ ok: false, saved: Boolean(env.SMS_DB), id: savedId, discord: { ok: false, status: discordResponse.status, error: "Discord rejected the message" } }, 502);
    }
    return json({ ok: true, saved: Boolean(env.SMS_DB), id: savedId, discord: { ok: true, status: discordResponse.status } });
  },

  // Deletes messages older than RETENTION_DAYS (30). Runs daily via the cron
  // trigger in wrangler.toml (03:00 Taipei). Expiry is based on server-side
  // ingestion time (created_at / expires_at, UTC), NOT on receivedAt:
  // receivedAt is a raw local-time string supplied by the iOS Shortcut with
  // no timezone, so it cannot be compared reliably. Rows created before the
  // 0002 migration have expires_at NULL and fall back to created_at.
  // Discord copies are a separate copy and are NOT deleted by this job.
  async scheduled(event, env) {
    if (!env.SMS_DB) {
      console.error("Scheduled cleanup: database is not configured");
      return;
    }
    try {
      const result = await env.SMS_DB.prepare(
        "DELETE FROM messages WHERE (expires_at IS NOT NULL AND expires_at <= datetime('now')) OR (expires_at IS NULL AND created_at <= datetime('now', '-30 days'))"
      ).run();
      console.log(`Scheduled cleanup: deleted ${Number(result.meta?.changes || 0)} expired messages`);
    } catch (error) {
      console.error("Scheduled cleanup failed:", error?.message || error);
      throw error;
    }
  },
};