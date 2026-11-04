const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders },
  });
}

function safeText(value, maxLength = 1000) {
  if (value === undefined || value === null) return "";
  return String(value).slice(0, maxLength);
}

function authorized(request, env) {
  const expected = env.SMS_FORWARDER_API_KEY;
  const provided = request.headers.get("X-API-Key") ||
    request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
  return Boolean(expected && provided && provided === expected);
}


function extractVerificationCode(message) {
  const text = String(message || "");
  const candidates = [...text.matchAll(/(?<![0-9])[0-9]{4,8}(?![0-9])/g)];
  if (!candidates.length) return "";
  const keyword = /驗證碼|验证码|認證碼|认证码|安全代碼|安全代码|安全碼|安全码|security\s*code|verification\s*code|one[- ]time\s*code|\bOTP\b/i;
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

async function authorizedChiAuth(request) {
  const authorization = request.headers.get("Authorization") || "";
  if (!/^Bearer [A-Za-z0-9_-]{40,80}$/.test(authorization)) return false;
  try {
    const response = await fetch("https://auth.chi.qzz.io/api/userinfo?client_id=" + encodeURIComponent(SMS_CHI_AUTH_CLIENT_ID), {
      headers: { Authorization: authorization, Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) return false;
    const identity = await response.json();
    return identity.sub === "chi-owner" && identity.aud === SMS_CHI_AUTH_CLIENT_ID;
  } catch {
    return false;
  }
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

    const keyword = /驗證碼|验证码|認證碼|认证码|安全代碼|安全代码|安全碼|安全码|security\s*code|verification\s*code|one[- ]time\s*code|\bOTP\b/i;
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
    if (!value) return "時間未知";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("zh-TW", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(date);
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
    const quote = value => '"' + String(value ?? "").replace(/"/g, '""') + '"';
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
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method === "GET" && url.pathname === "/") return page();

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ service: "SMS Forwarder", status: "ok" });
    }

    if (request.method === "GET" && url.pathname === "/api/messages") {
      if (!(await authorizedChiAuth(request))) return json({ error: "Unauthorized" }, 401);
      if (!env.SMS_DB) return json({ error: "Database is not configured" }, 503);
      try {
        const result = await env.SMS_DB.prepare(
          "SELECT id, sender, message, received_at FROM messages ORDER BY id DESC LIMIT 500"
        ).all();
        return json({ messages: result.results || [] });
      } catch {
        return json({ error: "Could not read messages" }, 500);
      }
    }

    const messageDeleteMatch = url.pathname.match(/^\/api\/messages\/(\d+)$/);
    if (request.method === "DELETE" && messageDeleteMatch) {
      if (!(await authorizedChiAuth(request))) return json({ error: "Unauthorized" }, 401);
      if (!env.SMS_DB) return json({ error: "Database is not configured" }, 503);
      const id = Number(messageDeleteMatch[1]);
      if (!Number.isSafeInteger(id) || id < 1) return json({ error: "Invalid message ID" }, 400);
      try {
        const result = await env.SMS_DB.prepare("DELETE FROM messages WHERE id = ?").bind(id).run();
        if (!Number(result.meta?.changes || 0)) return json({ error: "Message not found" }, 404);
        return json({ ok: true, deleted: id });
      } catch {
        return json({ error: "Could not delete message" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/messages/clear") {
      if (!(await authorizedChiAuth(request))) return json({ error: "Unauthorized" }, 401);
      if (!env.SMS_DB) return json({ error: "Database is not configured" }, 503);
      try {
        const result = await env.SMS_DB.prepare("DELETE FROM messages").run();
        return json({ ok: true, cleared: Number(result.meta?.changes || 0) });
      } catch {
        return json({ error: "Could not clear messages" }, 500);
      }
    }

    if (request.method !== "POST" || !["/", "/sms"].includes(url.pathname)) {
      return json({ error: "Not found" }, 404);
    }

    if (!authorized(request, env)) return json({ error: "Unauthorized" }, 401);

    let payload;
    try {
      payload = await request.json();
    } catch {
      return json({ error: "Request body must be valid JSON" }, 400);
    }

    const sender = safeText(payload.sender ?? payload.from ?? "未知寄件者", 200);
    const message = safeText(payload.message ?? payload.text ?? payload.body, 3500);
    const receivedAt = safeText(payload.receivedAt ?? payload.time ?? new Date().toISOString(), 100);
    if (!message.trim()) return json({ error: "Missing message" }, 400);

    if (env.SMS_DB) {
      try {
        await env.SMS_DB.prepare(
          "INSERT INTO messages (sender, message, received_at) VALUES (?, ?, ?)"
        ).bind(sender || "未知寄件者", message, receivedAt || new Date().toISOString()).run();
      } catch {
        return json({ error: "Could not save message to database" }, 500);
      }
    }

    if (!env.DISCORD_WEBHOOK_URL) return json({ error: "Discord webhook is not configured" }, 500);

    const verificationCode = extractVerificationCode(message);
    const discordFields = [
      { name: "📱 寄件者", value: sender || "未知寄件者", inline: true },
      { name: "🕒 收到時間", value: receivedAt || "未知時間", inline: true },
    ];
    if (verificationCode) {
      discordFields.push({
        name: "🔐 驗證碼",
        value: "`" + verificationCode + "`",
        inline: false,
      });
    }
    discordFields.push({ name: "💬 簡訊內容", value: message || "(空白)", inline: false });

    const discordPayload = {
      username: "SMS Forwarder",
      allowed_mentions: { parse: [] },
      embeds: [{
        title: verificationCode ? "🔐 收到簡訊驗證碼" : "📩 收到新簡訊",
        color: 5793266,
        fields: discordFields,
        footer: { text: "iPhone SMS Forwarder" },
        timestamp: new Date().toISOString(),
      }],
    };

    let discordResponse;
    try {
      discordResponse = await fetch(env.DISCORD_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(discordPayload),
      });
    } catch {
      return json({ error: "Could not reach Discord", saved: Boolean(env.SMS_DB) }, 502);
    }

    if (!discordResponse.ok) {
      return json({ error: "Discord rejected the message", status: discordResponse.status, saved: Boolean(env.SMS_DB) }, 502);
    }
    return json({ ok: true, saved: Boolean(env.SMS_DB) });
  },
};
