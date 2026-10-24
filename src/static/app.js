"use strict";
// All DOM is built with createElement/textContent: server data is never parsed as HTML. The server decides every
// authorisation question; this UI only hides what the server would refuse anyway.
const root = document.getElementById("root"), toasts = document.getElementById("toasts");
let me = null, csrf = sessionStorage.getItem("csrf") || "", expired = false;
const NS = "http://www.w3.org/2000/svg";
const ICONS = {
  home: "M3 11l9-8 9 8M5 10v10h14V10", file: "M6 2h9l5 5v15H6zM14 2v6h6", shield: "M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01", user: "M12 12a4 4 0 100-8 4 4 0 000 8zM4 21c0-4 4-6 8-6s8 2 8 6", users: "M9 11a4 4 0 100-8 4 4 0 000 8zM2 21c0-4 3-6 7-6s7 2 7 6M17 4a4 4 0 010 7M22 21c0-3-2-5-4-5.6",
  search: "M11 19a8 8 0 100-16 8 8 0 000 16zM21 21l-4.3-4.3", upload: "M12 16V4M7 9l5-5 5 5M4 20h16", down: "M12 4v12M7 11l5 5 5-5M4 20h16", plus: "M12 5v14M5 12h14",
  grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z", sun: "M12 17a5 5 0 100-10 5 5 0 000 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4", moon: "M21 13A9 9 0 1111 3a7 7 0 0010 10z",
  menu: "M3 6h18M3 12h18M3 18h18", out: "M9 21H5V3h4M16 17l5-5-5-5M21 12H9", trash: "M4 7h16M10 11v6M14 11v6M6 7l1 14h10l1-14M9 7V4h6v3", check: "M5 13l4 4L19 7",
  x: "M6 6l12 12M18 6L6 18", alert: "M12 9v4M12 17h.01M10.3 3.9L2 18a2 2 0 001.7 3h16.6a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z", lock: "M6 11h12v10H6zM8 11V7a4 4 0 018 0v4",
  key: "M15 8a4 4 0 11-3 6.6L4 22v-3H2v-2h3l5.6-5.6A4 4 0 0115 8z", clock: "M12 21a9 9 0 100-18 9 9 0 000 18zM12 7v5l3 2", left: "M15 18l-6-6 6-6", eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 15a3 3 0 100-6 3 3 0 000 6z",
  spark: "M12 3l2.1 5.9L20 11l-5.9 2.1L12 19l-2.1-5.9L4 11l5.9-2.1z", restore: "M3 12a9 9 0 109-9 9 9 0 00-7 3.5M3 4v5h5", edit: "M4 20h4L19 9l-4-4L4 16zM14 6l4 4", swap: "M7 7h13l-4-4M17 17H4l4 4", pulse: "M3 12h4l3-8 4 16 3-8h4"
};
function icon(n) { const s = document.createElementNS(NS, "svg"); s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("class", "i"); s.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(NS, "path"); p.setAttribute("d", ICONS[n] || ICONS.file); s.append(p); return s; }
function h(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
const ic = (n, ...t) => [icon(n), ...t];
const btn = (label, onclick, cls = "", ico, extra = {}) => h("button", { type: "button", class: "btn " + cls, onclick, ...extra }, ico ? icon(ico) : null, label);
// The API can return timestamps without a timezone (SQLite). They are UTC, so mark them as such;
// otherwise the browser would read them as local time and show them hours off.
const toDate = d => { const t = String(d); return new Date(/(Z|[+-]\d\d:?\d\d)$/i.test(t) ? t : t.replace(" ", "T") + "Z"); };
const fmtDate = d => d ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(toDate(d)) : "-";
const fmtDay = d => d ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(toDate(d)) : "-";
const fmtSize = n => n == null ? "-" : n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
const ago = d => { const s = (Date.now() - toDate(d)) / 1000; return s < 60 ? "just now" : s < 3600 ? Math.floor(s / 60) + " min ago" : s < 86400 ? Math.floor(s / 3600) + " h ago" : fmtDay(d); };
const nice = a => { const t = String(a || "").replace(/_/g, " ").toLowerCase(); return t.charAt(0).toUpperCase() + t.slice(1); };
const initials = n => (n || "?").slice(0, 2).toUpperCase();
function ftype(name) {
  const x = (/\.([a-z0-9]+)$/i.exec(name || "") || [])[1]?.toLowerCase() || "";
  const m = { pdf: "pdf", doc: "doc", docx: "doc", odt: "doc", xls: "xls", xlsx: "xls", csv: "xls", ppt: "ppt", pptx: "ppt", png: "img", jpg: "img", jpeg: "img", gif: "img", webp: "img", zip: "zip", txt: "txt", md: "txt" };
  return h("span", { class: "ft " + (m[x] || "txt"), "aria-hidden": "true" }, (x || "doc").slice(0, 4).toUpperCase());
}
function toast(text, kind = "ok") {
  const t = h("div", { class: "toast " + (kind === "err" ? "err" : ""), role: kind === "err" ? "alert" : null }, icon(kind === "err" ? "alert" : "check"), h("span", {}, text));
  toasts.append(t); setTimeout(() => t.remove(), kind === "err" ? 7000 : 4000);
}
async function api(method, path, body, raw) {
  const opt = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") opt.headers["X-CSRF-Token"] = csrf;
  if (body instanceof FormData) opt.body = body;
  else if (body) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (!r.ok) {
    let d = r.statusText; try { const j = await r.json(); d = typeof j.detail === "string" ? j.detail
      : Array.isArray(j.detail) ? j.detail.map(x => `${(x.loc || []).slice(1).join(".")}: ${x.msg}`).join(" | ") : JSON.stringify(j.detail); } catch {}
    if (r.status === 401 && me && !path.includes("/auth/login")) { me = null; expired = true; sessionStorage.removeItem("csrf"); shell = null; route(); }
    throw Object.assign(new Error(d), { status: r.status });
  }
  return raw ? r : r.json();
}
// Runs an action: toast on success/failure, then refresh the current view.
async function act(fn, okMsg, after) {
  try { const r = await fn(); if (okMsg) toast(typeof okMsg === "function" ? okMsg(r) : okMsg); if (after) await after(r); else await route(); }
  catch (e) { if (e.status !== 401) toast(e.message, "err"); }
}
// ---- dialogs ----
function dialog(title, body, buttons) {
  const d = h("dialog", { "aria-labelledby": "dt" }), box = h("div", { class: "dlg" }, h("h2", { id: "dt" }, title), body,
    h("div", { class: "acts" }, buttons(v => d.close(v))));
  d.append(box); document.body.append(d); d.addEventListener("close", () => d.remove()); d.showModal(); return d;
}
const confirmBox = (title, text, label, danger = true) => new Promise(res => {
  const d = dialog(title, h("p", { class: "mute" }, text), close => [btn("Cancel", () => close("no"), "alt"), btn(label, () => close("yes"), danger ? "bad" : "")]);
  d.addEventListener("close", () => res(d.returnValue === "yes"));
});
const formBox = (title, fields, label, onOk) => {
  const form = h("form", { class: "fields" }, ...fields);
  const d = dialog(title, form, close => [btn("Cancel", () => close("no"), "alt"), btn(label, async () => { if (!form.reportValidity()) return; const ok = await onOk(); if (ok !== false) close("ok"); })]);
  form.addEventListener("submit", e => { e.preventDefault(); d.querySelector(".acts .btn:last-child").click(); }); return d;
};
const fld = (label, input, hint) => h("label", { class: "f" }, label, input, hint ? h("small", {}, hint) : null);
const inp = (type = "text", extra = {}) => h("input", { class: "in", type, ...extra });
// ---- theme ----
function toggleTheme() {
  const t = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", t); try { localStorage.setItem("tv-theme", t); } catch {}
  if (shell) shell.themeBtn.replaceChildren(icon(t === "dark" ? "sun" : "moon"));
}
const themeIcon = () => icon(document.documentElement.getAttribute("data-theme") === "dark" ? "sun" : "moon");
// ---- states ----
const skeleton = () => h("div", { "aria-busy": "true", "aria-label": "Loading" }, h("div", { class: "sk t" }), h("div", { class: "grid stats" }, ...[1, 2, 3].map(() => h("div", { class: "card" }, h("div", { class: "sk" }), h("div", { class: "sk" })))), h("div", { class: "card" }, h("div", { class: "sk b" }), h("div", { class: "sk" }), h("div", { class: "sk" })));
const empty = (ico, title, text, action, bad) => h("div", { class: "empty" + (bad ? " bad" : "") }, h("div", { class: "big" }, icon(ico)), h("h2", {}, title), h("p", {}, text), action);
const denied = (text) => empty("lock", "Access denied", text || "This item doesn't exist, or you haven't been granted access. The server doesn't reveal which.", btn("Back to documents", () => { location.hash = "#/documents"; }, "alt", "left"), true);
function errorView(e) { if (e.status === 403 || e.status === 404) return denied(); return empty("alert", "Something went wrong", e.message, btn("Try again", () => route(), "", "restore"), true); }
const outcome = s => h("span", { class: "badge " + (s === "SUCCESS" ? "ok" : s === "DENIED" ? "bad" : "warn") }, icon(s === "SUCCESS" ? "check" : s === "DENIED" ? "lock" : "alert"), s === "DENIED" ? "Refused" : nice(s));
const head = (title, sub, ...actions) => h("div", { class: "head" }, h("div", {}, h("h1", {}, title), sub ? h("p", {}, sub) : null), h("div", { class: "row" }, ...actions));
// ---- auth screens ----
let authTab = "login";
function pwField(id, label, hint, auto = "current-password") {
  const i = inp("password", { id, required: true, autocomplete: auto }), b = h("button", { type: "button", class: "btn ghost sm", "aria-label": "Show password", onclick: () => { const s = i.type === "password"; i.type = s ? "text" : "password"; b.setAttribute("aria-label", s ? "Hide password" : "Show password"); } }, icon("eye"));
  return h("label", { class: "f" }, label, h("div", { class: "pw" }, i, b), hint ? h("small", {}, hint) : null);
}
function authView(hash) {
  const side = h("section", { class: "hero" }, h("div", { class: "brand" }, h("span", { class: "logo" }, icon("shield")), "TrustVault"),
    h("h1", {}, "Share documents. Prove who opened them."),
    ...[["lock", "Server-enforced access", "Only people you grant can read a file, through any route."], ["pulse", "Tamper-evident audit trail", "Every access, including refused attempts, is chained and verifiable."], ["clock", "Instant revocation", "Take access away and everything issued stops working at once."]]
      .map(([i, t, d]) => h("div", { class: "sec" }, h("span", { class: "ic" }, icon(i)), h("div", {}, h("b", {}, t), d))));
  let card;
  const formWrap = (title, sub, ...c) => h("div", { class: "card" }, h("h1", {}, title), h("p", { class: "mute" }, sub), h("div", { class: "fields" }, ...c));
  const go = (t) => { authTab = t; route(); };
  const link = (t, l) => h("button", { type: "button", class: "btn ghost sm", onclick: () => go(t) }, l);
  if (expired) card = h("div", { class: "alert", role: "alert" }, icon("clock"), h("div", {}, h("b", {}, "Your session has expired."), " Sign in again to continue. Nothing was lost."));
  const v = id => document.getElementById(id).value;
  if (hash.startsWith("#reset=")) {
    const f = formWrap("Choose a new password", "Use 10+ characters with upper, lower, a number and a symbol.", pwField("np", "New password", null, "new-password"),
      btn("Reset password", () => act(async () => { await api("POST", "/api/auth/reset-password", { token: hash.slice(7), new_password: v("np") }); location.hash = ""; authTab = "login"; }, "Password reset. Sign in.", () => route()), "", "key"));
    return h("div", { class: "auth" }, side, h("div", { class: "pane" }, f));
  }
  if (hash.startsWith("#confirm-email=")) {
    const f = formWrap("Confirm email change", "Confirm to apply the new address. You will be signed out.", btn("Confirm", () => act(async () => { await api("POST", "/api/auth/email-change-confirm", { token: hash.slice(15) }); location.hash = ""; }, "Email updated. Sign in again.", () => route()), "", "check"));
    return h("div", { class: "auth" }, side, h("div", { class: "pane" }, f));
  }
  const body = authTab === "register" ? formWrap("Create account", "New accounts start as owners. An administrator can change a role later.",
    fld("Username", inp("text", { id: "ru", required: true, autocomplete: "username" })), fld("Email", inp("email", { id: "re", required: true, autocomplete: "email" })), pwField("rp", "Password", "10+ characters with Aa1!", "new-password"),
    btn("Create account", () => act(async () => { await api("POST", "/api/auth/register", { username: v("ru"), email: v("re"), password: v("rp") }); authTab = "login"; }, "Account created. Sign in.", () => route()), "", "user"), link("login", "Back to sign in"))
    : authTab === "forgot" ? formWrap("Reset password", "We'll email a link if the address is registered.", fld("Email", inp("email", { id: "fe", required: true, autocomplete: "email" })),
      btn("Send reset link", () => act(() => api("POST", "/api/auth/forgot-password", { email: v("fe") }), r => r.message), "", "key"), link("login", "Back to sign in"))
    : formWrap("Sign in", "Welcome back to your secure workspace.", fld("Username", inp("text", { id: "lu", required: true, autocomplete: "username" })), pwField("lp", "Password"),
      btn("Sign in", () => act(async () => { const r = await api("POST", "/api/auth/login", { username: v("lu"), password: v("lp") }); csrf = r.csrf_token; sessionStorage.setItem("csrf", csrf); expired = false; location.hash = "#/dashboard"; }), "", "lock"),
      h("div", { class: "row" }, link("forgot", "Forgot password?"), link("register", "Create account")));
  const pane = h("div", { class: "pane" }, h("div", {}, expired && card ? card : null, body));
  const el = h("div", { class: "auth" }, side, pane);
  el.addEventListener("keydown", e => { if (e.key === "Enter" && e.target.tagName === "INPUT") body.querySelector(".btn:not(.ghost)")?.click(); });
  return el;
}
// ---- shell ----
let shell = null;
const NAV = () => [["dashboard", "Overview", "home"], ["documents", "Documents", "file"], ...(me.role !== "viewer" ? [["audit", "Audit trail", "list"]] : []),
  ["security", "Security center", "shield"], ...(me.role === "admin" ? [["users", "Users", "users"]] : []), ["profile", "Profile", "user"]];
function buildShell() {
  const nav = h("nav", { class: "nav", "aria-label": "Main" }), side = h("aside", { class: "side" }), view = h("main", { class: "view", id: "view", tabindex: "-1" });
  const themeBtn = h("button", { type: "button", class: "btn ghost", "aria-label": "Toggle dark mode", onclick: toggleTheme }, themeIcon());
  const title = h("div", { class: "grow mute" });
  side.append(h("div", { class: "brand" }, h("span", { class: "logo" }, icon("shield")), "TrustVault"), nav,
    h("div", { class: "foot" }, h("div", { class: "user" }, h("span", { class: "avatar" }, initials(me.username)), h("div", {}, h("div", {}, me.username), h("span", { class: "badge" }, me.role))),
      btn("Sign out", () => confirmBox("Sign out?", "Your session will end on this device.", "Sign out", false).then(ok => ok && act(async () => { await api("POST", "/api/auth/logout"); me = null; expired = false; sessionStorage.removeItem("csrf"); shell = null; location.hash = ""; }, null, () => route())), "alt", "out")));
  const menu = h("button", { type: "button", class: "btn ghost menu", "aria-label": "Open navigation", onclick: () => side.classList.toggle("open") }, icon("menu"));
  root.replaceChildren(h("div", { class: "shell" }, side, h("div", { class: "main" }, h("header", { class: "top" }, menu, title, h("span", { class: "badge ok" }, icon("lock"), "Encrypted session"), themeBtn), view)));
  shell = { nav, view, themeBtn, side, title };
}
function markNav(page) {
  shell.nav.replaceChildren(...NAV().map(([k, l, i]) => h("a", { href: "#/" + k, "aria-current": k === page || (k === "documents" && page === "doc") ? "page" : null, onclick: () => shell.side.classList.remove("open") }, icon(i), l)));
}
async function route() {
  const hash = location.hash;
  if (!me && !hash.startsWith("#reset=") && !hash.startsWith("#confirm-email=")) {
    try { me = await api("GET", "/api/auth/me"); csrf = me.csrf_token; sessionStorage.setItem("csrf", csrf); expired = false; } catch { me = null; }
  }
  if (!me || hash.startsWith("#reset=") || hash.startsWith("#confirm-email=")) { shell = null; root.replaceChildren(authView(hash)); return; }
  if (!shell) buildShell();
  const [, page = "dashboard", id] = hash.replace(/^#/, "").split("/");
  const views = { dashboard: dashboardView, documents: libraryView, doc: detailView, audit: auditView, security: securityView, users: usersView, profile: profileView };
  const key = page === "documents" && id ? "doc" : page; markNav(key === "doc" ? "documents" : key);
  const fn = views[key] || dashboardView, mine = ++token;
  shell.view.replaceChildren(skeleton());
  try { const out = await fn(id); if (mine === token) { shell.view.replaceChildren(...[out].flat(Infinity).filter(Boolean)); document.title = "TrustVault | " + nice(key === "doc" ? "document" : key); } }
  catch (e) { if (e.status !== 401 && mine === token) shell.view.replaceChildren(errorView(e)); }
}
let token = 0;
// ---- shared pieces ----
const sortedActivity = rows => h("ul", { class: "act" }, ...rows.map(r => h("li", {}, h("span", { class: "dot " + (r.status === "DENIED" ? "bad" : "") }, icon(r.status === "DENIED" ? "lock" : "pulse")),
  h("div", {}, h("b", {}, nice(r.action)), h("div", { class: "sm mute" }, `${r.actor_username || "system"} · ${ago(r.timestamp)}`), r.status !== "SUCCESS" ? outcome(r.status) : null))));
function eventTable(rows, withRes) {
  if (!rows.length) return empty("list", "No events found", "Nothing matches these filters yet.");
  return h("div", { class: "tw" }, h("table", {}, h("caption", { class: "sr" }, "Audit events"), h("thead", {}, h("tr", {}, ["#", "Time", "Actor", "Action", "Outcome", withRes ? "Resource" : "Detail"].map(t => h("th", { scope: "col" }, t)))),
    h("tbody", {}, ...rows.map(r => h("tr", {}, h("td", { class: "mono" }, r.sequence_number), h("td", {}, fmtDate(r.timestamp)), h("td", {}, r.actor_username || "-", r.actor_role ? h("span", { class: "badge n" }, r.actor_role) : null),
      h("td", {}, nice(r.action)), h("td", {}, outcome(r.status), r.reason ? h("div", { class: "sm mute" }, nice(r.reason)) : null),
      h("td", { class: "mono" }, withRes ? (r.resource_id || "-") : JSON.stringify(r.metadata || {})))))));
}
async function download(url) {
  const r = await api("GET", url, null, true), name = /filename="([^"]+)"/.exec(r.headers.get("content-disposition") || "")?.[1] || "download";
  const a = h("a", { href: URL.createObjectURL(await r.blob()), download: name }); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
const shareBtn = d => d.owner === me.username ? btn("Share", () => { detailTab = "sharing"; location.hash = "#/documents/" + d.id; }, "sm", "users") : null;
const docRow = d => h("div", { class: "dn" }, ftype(d.title), h("div", {}, h("a", { href: "#/documents/" + d.id }, d.title), h("div", { class: "sm mute" }, `${d.owner} · ${fmtSize(d.file_size_bytes)}`)));
function uploadDialog() {
  const t = inp("text", { required: true, maxlength: 200 }), c = inp("text", { maxlength: 100, placeholder: "e.g. Contracts" }), f = inp("file", { required: true });
  formBox("Upload document", [fld("Title", t), fld("Category", c), fld("File", f, "Content is validated and encrypted on the server before it is stored.")], "Upload", async () => {
    const fd = new FormData(); fd.append("title", t.value); fd.append("category", c.value); fd.append("file", f.files[0]);
    try { const r = await api("POST", "/api/documents", fd); toast("Uploaded and encrypted."); location.hash = "#/documents/" + r.id; route(); } catch (e) { toast(e.message, "err"); return false; }
  });
}
// ---- dashboard ----
async function dashboardView() {
  const [list, pending, adminDash, adminAct] = await Promise.all([api("GET", "/api/documents?limit=100"), me.role === "owner" ? api("GET", "/api/documents/pending-transfers").catch(() => []) : [],
    me.role === "admin" ? api("GET", "/api/admin/dashboard").catch(() => null) : null, me.role === "admin" ? api("GET", "/api/admin/audit?limit=6").catch(() => []) : []]);
  const bytes = list.items.reduce((a, d) => a + (d.file_size_bytes || 0), 0), cats = Object.keys(list.facets.category).length;
  const stat = (i, n, l) => h("div", { class: "card stat" }, h("span", { class: "ic" }, icon(i)), h("div", {}, h("b", {}, n), h("span", {}, l)));
  const alerts = adminDash ? [...adminDash.repeated_refusals.map(r => `${r.subject} was refused ${r.count} times in 24h`), adminDash.failed_audit_verifications ? "An audit chain verification failed" : null].filter(Boolean) : [];
  return [head(`Welcome back, ${me.username}`, "Here's what's happening in your vault.", me.role === "owner" ? btn("Upload document", uploadDialog, "", "upload") : null, btn("Browse documents", () => { location.hash = "#/documents"; }, "alt", "file")),
    ...alerts.map(a => h("div", { class: "alert bad", role: "alert" }, icon("alert"), a)),
    ...pending.map(p => h("div", { class: "alert" }, icon("swap"), h("div", {}, `${p.from_username} wants to transfer a "${p.category}" document to you. `, h("button", { class: "btn sm", onclick: () => act(() => api("POST", `/api/documents/${p.document_id}/transfer-accept`), "You now own it.") }, "Accept"), " ", h("button", { class: "btn sm alt", onclick: () => act(() => api("POST", `/api/documents/${p.document_id}/transfer-reject`), "Transfer rejected.") }, "Reject")))),
    h("div", { class: "grid stats" }, stat("file", list.total, "Documents you can access"), stat("grid", cats, "Categories"), stat("lock", fmtSize(bytes), "Encrypted storage"),
      adminDash ? stat("alert", adminDash.login_failures, "Failed sign-ins (24h)") : stat("shield", "Active", "Session protection")),
    h("div", { class: "grid two" }, h("div", { class: "card" }, h("h2", {}, "Recent documents", btn("View all", () => { location.hash = "#/documents"; }, "ghost sm")),
      list.items.length ? h("div", { class: "tw" }, h("table", {}, h("tbody", {}, ...list.items.slice(0, 6).map(d => h("tr", {}, h("td", {}, docRow(d)), h("td", { class: "sm mute" }, ago(d.created_at)))))))
        : empty("file", "No documents yet", me.role === "owner" ? "Upload your first document to get started." : "Documents shared with you will appear here.", me.role === "owner" ? btn("Upload", uploadDialog, "", "upload") : null)),
      h("div", { class: "card" }, h("h2", {}, me.role === "admin" ? "Recent activity" : "Quick actions"),
        me.role === "admin" ? (adminAct.length ? sortedActivity(adminAct) : empty("pulse", "No activity", "Events will show here.")) :
          h("div", { class: "fields" }, btn("Open security center", () => { location.hash = "#/security"; }, "alt", "shield"), btn("Account settings", () => { location.hash = "#/profile"; }, "alt", "user"),
            me.role === "owner" ? btn("Review audit trail", () => { location.hash = "#/audit"; }, "alt", "list") : null)))];
}
// ---- library ----
let F = { q: "", owner: "", category: "", from: "", to: "", sort: "created_at", order: "desc", page: 1 }, layout = innerWidth < 640 ? "grid" : "list";
async function libraryView() {
  const p = new URLSearchParams({ limit: "12", page: F.page, sort: F.sort, order: F.order });
  for (const [k, v] of [["q", F.q], ["owner", F.owner], ["category", F.category], ["created_from", F.from], ["created_to", F.to]]) if (v) p.set(k, v);
  const [list, trash] = await Promise.all([api("GET", "/api/documents?" + p), me.role === "owner" ? api("GET", "/api/documents/trash") : []]);
  const apply = () => { F.page = 1; route(); }, set = (k, v) => { F[k] = v; apply(); };
  const q = inp("search", { value: F.q, placeholder: "Search by name", "aria-label": "Search by name" }), own = inp("text", { value: F.owner, placeholder: "Owner", "aria-label": "Owner username" });
  const from = inp("date", { value: F.from, "aria-label": "Created from" }), to = inp("date", { value: F.to, "aria-label": "Created to" });
  const sort = h("select", { class: "in", "aria-label": "Sort", onchange: e => { [F.sort, F.order] = e.target.value.split(":"); apply(); } }, ...[["created_at:desc", "Newest first"], ["created_at:asc", "Oldest first"], ["updated_at:desc", "Recently updated"], ["file_size_bytes:desc", "Largest first"], ["file_size_bytes:asc", "Smallest first"]].map(([v, l]) => h("option", { value: v, selected: v === `${F.sort}:${F.order}` }, l)));
  const filt = () => { F.q = q.value; F.owner = own.value; F.from = from.value; F.to = to.value; apply(); };
  const bar = h("form", { class: "card", onsubmit: e => { e.preventDefault(); filt(); } }, h("div", { class: "row" }, h("div", { class: "search" }, icon("search"), q), own, from, to, sort, btn("Search", () => filt(), "", "search", { type: "submit" }),
    btn("Clear", () => { F = { ...F, q: "", owner: "", category: "", from: "", to: "" }; apply(); }, "alt")),
    h("div", { class: "chips", role: "group", "aria-label": "Categories" }, ...Object.entries(list.facets.category).map(([c, n]) => h("button", { type: "button", class: "chip", "aria-pressed": F.category === c && c !== "" ? "true" : "false", onclick: () => set("category", F.category === c ? "" : c) }, `${c || "Uncategorised"} (${n})`))));
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Layout" }, ...[["list", "list", "List view"], ["grid", "grid", "Grid view"]].map(([k, i, l]) => h("button", { type: "button", "aria-label": l, "aria-pressed": layout === k ? "true" : "false", onclick: () => { layout = k; route(); } }, icon(i))));
  const items = !list.items.length ? empty("search", "No documents found", F.q || F.category || F.owner ? "Try different filters." : "Nothing has been shared with you yet.", me.role === "owner" ? btn("Upload document", uploadDialog, "", "upload") : null) :
    layout === "grid" ? h("div", { class: "docs" }, ...list.items.map(d => h("div", { class: "dc" }, docRow(d), h("div", { class: "row" }, h("span", { class: "badge" }, d.category || "Uncategorised"), h("span", { class: "sm mute" }, fmtDay(d.created_at))), h("div", { class: "row" }, shareBtn(d), btn("Download", () => act(() => download(`/api/documents/${d.id}/download`), "Download started.", () => {}), "alt sm", "down")))))
    : h("div", { class: "card" }, h("div", { class: "tw" }, h("table", {}, h("caption", { class: "sr" }, "Documents"), h("thead", {}, h("tr", {}, ["Name", "Category", "Created", "Size", ""].map(t => h("th", { scope: "col" }, t)))),
      h("tbody", {}, ...list.items.map(d => h("tr", {}, h("td", {}, docRow(d)), h("td", {}, h("span", { class: "badge" }, d.category || "Uncategorised")), h("td", {}, fmtDay(d.created_at)), h("td", {}, fmtSize(d.file_size_bytes)),
        h("td", {}, h("div", { class: "row" }, shareBtn(d), btn("Download", () => act(() => download(`/api/documents/${d.id}/download`), "Download started.", () => {}), "alt sm", "down")))))))));
  const pages = Math.max(1, Math.ceil(list.total / list.limit));
  return [head("Documents", `${list.total} document${list.total === 1 ? "" : "s"} you can access`, seg, me.role === "owner" ? btn("Upload", uploadDialog, "", "upload") : null), bar, items,
    pages > 1 ? h("div", { class: "pager" }, h("span", { class: "sm mute" }, `Page ${F.page} of ${pages}`), btn("Previous", () => { F.page--; route(); }, "alt sm", null, { disabled: F.page <= 1 }), btn("Next", () => { F.page++; route(); }, "alt sm", null, { disabled: F.page >= pages })) : null,
    trash.length ? h("div", { class: "card" }, h("h2", {}, ...ic("trash", `Trash (${trash.length})`)), h("p", { class: "mute sm" }, "Deleted documents keep their grants; restoring brings back the ones that are still valid."),
      ...trash.map(d => h("div", { class: "row" }, h("span", {}, d.title), h("span", { class: "sm mute" }, "deleted " + fmtDate(d.deleted_at)), btn("Restore", () => act(() => api("POST", `/api/documents/${d.id}/restore`), "Restored."), "alt sm", "restore")))) : null];
}
// ---- document detail ----
const idNames = new Map();   // grantee id -> email, learned this session only (the API returns ids)
let detailTab = "overview", sugg = null;
async function detailView(id) {
  const [doc, vers] = await Promise.all([api("GET", `/api/documents/${id}`), api("GET", `/api/documents/${id}/versions`)]);
  let grants = null; try { grants = await api("GET", `/api/documents/${id}/grants`); } catch { /* not the owner */ }
  const isOwner = !!grants, latest = vers[0] || null, name = latest?.filename || doc.title;
  const lastV = [...vers].sort((a, b) => b.version_number - a.version_number)[0];
  const tabs = [["overview", "Overview"], ["versions", "Versions"], ...(isOwner ? [["sharing", "Sharing & access"], ["activity", "Activity"]] : [])];
  if (!tabs.some(t => t[0] === detailTab)) detailTab = "overview";
  const tablist = h("div", { class: "tabs", role: "tablist" }, ...tabs.map(([k, l]) => h("button", { role: "tab", "aria-selected": detailTab === k ? "true" : "false", onclick: () => { detailTab = k; route(); } }, l)));
  const newVersion = () => { const f = inp("file", { required: true }); formBox("Upload new version", [fld("File", f, "Earlier versions are kept.")], "Upload", async () => { const fd = new FormData(); fd.append("file", f.files[0]); try { await api("POST", `/api/documents/${id}/versions`, fd); toast("New version uploaded."); route(); } catch (e) { toast(e.message, "err"); return false; } }); };
  const editDetails = () => { const t = inp("text", { value: doc.title, required: true, maxlength: 200 }), c = inp("text", { value: doc.category, maxlength: 100 });
    formBox("Edit details", [fld("Title", t), fld("Category", c)], "Save", async () => { try { await api("PATCH", `/api/documents/${id}`, { title: t.value, category: c.value }); toast("Details saved."); route(); } catch (e) { toast(e.message, "err"); return false; } }); };
  let body;
  if (detailTab === "versions") body = h("div", { class: "card" }, h("div", { class: "tw" }, h("table", {}, h("thead", {}, h("tr", {}, ["Version", "File", "Size", "Uploaded", ""].map(t => h("th", { scope: "col" }, t)))),
    h("tbody", {}, ...vers.map(v => h("tr", {}, h("td", {}, "v" + v.version_number, v === lastV ? h("span", { class: "badge ok" }, "current") : null), h("td", {}, h("div", { class: "dn" }, ftype(v.filename), v.filename)), h("td", {}, fmtSize(v.file_size_bytes)), h("td", {}, fmtDate(v.created_at)),
      h("td", {}, btn("Download", () => act(() => download(`/api/documents/${id}/versions/${v.version_number}/download`), "Download started.", () => {}), "alt sm", "down"))))))));
  else if (detailTab === "sharing") body = sharingPanel(id, grants);
  else if (detailTab === "activity") { const rows = await api("GET", `/api/documents/${id}/audit`); body = h("div", { class: "card" }, h("h2", {}, "Everything that happened to this document"), h("p", { class: "mute sm" }, "Includes refused attempts."), eventTable(rows, false)); }
  else body = h("div", { class: "grid two" }, h("div", { class: "card" }, h("h2", {}, "Details"), h("dl", { class: "meta" },
    ...[["Category", doc.category || "Uncategorised"], ["Versions", doc.versions], ["Created", fmtDate(doc.created_at)], ["File", name], ["Size", fmtSize(lastV?.file_size_bytes)], ["Your access", isOwner ? "Owner" : "Shared with you"]].map(([k, v]) => h("div", {}, h("dt", {}, k), h("dd", {}, v))))),
    h("div", { class: "card" }, h("h2", {}, "Security status"), ...[["lock", "Encrypted at rest", "AES-256-GCM, authenticated on every download."], ["eye", "Every access is audited", "Downloads and refused attempts are recorded."], ["clock", "Revocation is immediate", "Removed access stops working instantly."]].map(([i, t, d]) => h("div", { class: "sec" }, h("span", { class: "ic" }, icon(i)), h("div", {}, h("b", {}, t), h("span", { class: "sm mute" }, d))))));
  return [h("a", { class: "crumb", href: "#/documents" }, icon("left"), "Documents"),
    h("div", { class: "head" }, h("div", { class: "dn" }, ftype(name), h("div", {}, h("h1", {}, doc.title), h("div", { class: "row" }, h("span", { class: "badge" }, doc.category || "Uncategorised"), h("span", { class: "badge n" }, "v" + doc.versions), h("span", { class: "badge ok" }, icon("lock"), "Encrypted")))),
      h("div", { class: "row" }, btn("Download", () => act(() => download(`/api/documents/${id}/download`), "Download started.", () => {}), "", "down"), btn("New version", newVersion, "alt", "upload"),
        isOwner ? [btn("Share", () => { detailTab = "sharing"; route(); }, "alt", "users"), btn("Edit", editDetails, "alt", "edit"), btn("Delete", () => confirmBox("Move to trash?", `"${doc.title}" will be hidden from everyone. Grants are preserved so you can restore it.`, "Move to trash").then(ok => ok && act(() => api("DELETE", `/api/documents/${id}`), "Moved to trash.", () => { location.hash = "#/documents"; })), "alt", "trash")] : null)),
    tablist, body];
}
function sharingPanel(id, grants) {
  const em = inp("email", { required: true, placeholder: "name@company.com", "aria-label": "Grantee email" }), lv = h("select", { class: "in", "aria-label": "Access level" }, h("option", { value: "read" }, "Can read"), h("option", { value: "edit" }, "Can edit")), ex = inp("datetime-local", { "aria-label": "Expiry (optional)" });
  const grant = () => { if (!em.reportValidity()) return; const b = { grantee_email: em.value, level: lv.value }; if (ex.value) b.expires_at = new Date(ex.value).toISOString();
    act(async () => { const r = await api("POST", `/api/documents/${id}/grants`, b); const g = (await api("GET", `/api/documents/${id}/grants`)).find(x => x.id === r.grant_id); if (g) idNames.set(g.grantee_user_id, b.grantee_email); }, `Access granted to ${em.value}.`); };
  const who = g => idNames.get(g.grantee_user_id) || "User " + g.grantee_user_id.slice(0, 8);
  const state = g => g.revoked_at ? h("span", { class: "badge bad" }, "Revoked") : g.expires_at ? (new Date(g.expires_at) < new Date() ? h("span", { class: "badge n" }, "Expired") : h("span", { class: "badge warn" }, "Until " + fmtDate(g.expires_at))) : h("span", { class: "badge ok" }, "Active");
  const te = inp("email", { placeholder: "new owner's email" });
  const aiList = sugg && sugg.docId === id ? h("div", { class: "card" }, h("h2", {}, ...ic("spark", "AI suggestions")), h("div", { class: "alert" }, icon("shield"), "Advisory only. Nothing is granted until you decide, and both the suggestion and your decision are audited."),
    ...(sugg.items.length ? sugg.items.map(s => h("div", { class: "row" }, h("b", {}, s.username), h("span", { class: "sm mute" }, s.reason), btn("Grant read", () => decideAi(s, "grant", "read"), "sm"), btn("Grant edit", () => decideAi(s, "grant", "edit"), "alt sm"), btn("Reject", () => decideAi(s, "reject"), "alt sm"))) : [h("p", { class: "mute" }, "No suggestions left.")])) : null;
  return [h("div", { class: "card" }, h("h2", {}, "Share this document"), h("div", { class: "row" }, em, lv, h("label", { class: "f sm" }, "Expires (optional)", ex), btn("Grant access", grant, "", "plus")), h("p", { class: "sm mute" }, "Exact email match only. Leave expiry empty for no expiry.")),
    h("div", { class: "card" }, h("h2", {}, "People with access"), grants.length ? h("div", { class: "tw" }, h("table", {}, h("thead", {}, h("tr", {}, ["Person", "Level", "Status", "Granted", ""].map(t => h("th", { scope: "col" }, t)))), h("tbody", {}, ...grants.map(g => h("tr", {}, h("td", {}, h("div", { class: "dn" }, h("span", { class: "avatar" }, initials(who(g))), who(g))), h("td", {}, h("span", { class: "badge" }, g.level)), h("td", {}, state(g)), h("td", {}, fmtDate(g.granted_at)),
      h("td", {}, g.revoked_at ? null : btn("Revoke", () => confirmBox("Revoke access?", `${who(g)} will lose access immediately, and anything they were issued stops working.`, "Revoke").then(ok => ok && act(() => api("POST", `/api/documents/${id}/grants/${g.id}/revoke`), "Access revoked instantly.")), "alt sm", "x"))))))) : empty("users", "Not shared yet", "Only you can see this document.")),
    aiList, h("div", { class: "card" }, h("h2", {}, "Advanced"), h("div", { class: "row" }, btn("AI: suggest who should see this", () => act(async () => { const r = await api("POST", `/api/documents/${id}/grantee-suggestions`); sugg = { docId: id, id: r.suggestion_id, items: r.suggestions }; }, "Suggestions ready. Review each one."), "alt", "spark")),
      h("div", { class: "row" }, te, btn("Request ownership transfer", () => te.reportValidity() && act(() => api("POST", `/api/documents/${id}/transfer-request`, { target_email: te.value }), "Transfer requested. The recipient must accept."), "alt", "swap"), btn("Cancel transfer", () => act(() => api("POST", `/api/documents/${id}/transfer-cancel`), "Transfer cancelled."), "alt")))];
}
async function decideAi(s, action, level) {
  await act(async () => { await api("POST", `/api/documents/${sugg.docId}/grantee-suggestions/${sugg.id}/decisions`, action === "reject" ? { user_id: s.user_id, action } : { user_id: s.user_id, action, level }); sugg.items = sugg.items.filter(x => x !== s); }, action === "reject" ? `Rejected ${s.username}.` : `You granted ${level} access to ${s.username}.`);
}
// ---- audit ----
let AF = { kind: "", status: "", actor: "", resource_id: "", doc: "" };
async function auditView() {
  if (me.role === "viewer") return denied("Audit trails are available to owners and administrators.");
  if (me.role === "owner") {
    const list = await api("GET", "/api/documents?limit=100"), sel = h("select", { class: "in", "aria-label": "Document", onchange: e => { AF.doc = e.target.value; route(); } }, h("option", { value: "" }, "Choose a document"), ...list.items.map(d => h("option", { value: d.id, selected: d.id === AF.doc }, d.title)));
    let rows = null; if (AF.doc) { try { rows = await api("GET", `/api/documents/${AF.doc}/audit`); } catch (e) { rows = []; toast("Only the owner can view a document's history.", "err"); } }
    return [head("Audit trail", "Who accessed your documents, including refused attempts."), h("div", { class: "card" }, h("div", { class: "row" }, sel)), h("div", { class: "card" }, rows ? eventTable(rows, false) : empty("list", "Select a document", "Choose one of your documents to see its full history."))];
  }
  const q = new URLSearchParams({ limit: "50" }); for (const [k, v] of Object.entries(AF)) if (v && k !== "doc") q.set(k, v);
  const rows = await api("GET", "/api/admin/audit?" + q);
  const s = (id, opts, cur, label) => h("select", { class: "in", "aria-label": label, id }, ...opts.map(([v, l]) => h("option", { value: v, selected: v === cur }, l)));
  const k = s("ak", [["", "All kinds"], ["document", "Documents"], ["permission", "Permissions"], ["admin", "Admin"], ["auth", "Authentication"]], AF.kind, "Kind"), st = s("as", [["", "Any outcome"], ["SUCCESS", "Success"], ["DENIED", "Refused"], ["ERROR", "Error"]], AF.status, "Outcome");
  const a = inp("text", { placeholder: "Actor username", value: AF.actor, "aria-label": "Actor" }), r = inp("text", { placeholder: "Resource ID", value: AF.resource_id, "aria-label": "Resource id" });
  const go = () => { AF = { ...AF, kind: k.value, status: st.value, actor: a.value, resource_id: r.value }; route(); };
  return [head("Audit trail", "Document activity and permission changes. Identifiers only: admins never see titles or contents.", btn("Verify integrity", () => act(() => api("POST", "/api/admin/audit/verify"), r => r.status === "VALID" ? `Audit chain valid (${r.total_records} records)` : "Chain corrupted"), "alt", "shield")),
    h("form", { class: "card", onsubmit: e => { e.preventDefault(); go(); } }, h("div", { class: "row" }, k, st, a, r, btn("Apply", go, "", "search", { type: "submit" }), btn("Reset", () => { AF = { kind: "", status: "", actor: "", resource_id: "", doc: "" }; route(); }, "alt"))), h("div", { class: "card" }, eventTable(rows, true))];
}
// ---- security center ----
async function securityView() {
  const dash = me.role === "admin" ? await api("GET", "/api/admin/dashboard").catch(() => null) : null;
  const items = [["lock", "Encryption at rest", "Every file is AES-256-GCM encrypted; tampering is detected on download."], ["pulse", "Tamper-evident audit", "Records are hash-chained with HMAC so quiet edits are detectable."], ["clock", "Instant revocation", "Access is checked on every request and again before bytes are released."], ["key", "Session protection", "HttpOnly session cookie with CSRF tokens; role changes end sessions."], ["shield", "Hardened browser policy", "Strict CSP, no inline scripts, no third-party resources."], ["alert", "Abuse limits", "Rate limiting on sign-in, uploads and password reset."]];
  return [head("Security center", "How your vault is protected, and what needs attention."),
    dash ? h("div", { class: "card" }, h("h2", {}, "Alerts (last 24 hours)"), (dash.repeated_refusals.length || dash.failed_audit_verifications) ? [...dash.repeated_refusals.map(r => h("div", { class: "alert bad" }, icon("alert"), `${r.subject} refused ${r.count} times`)), dash.failed_audit_verifications ? h("div", { class: "alert bad" }, icon("alert"), "Audit verification failed") : null] : h("div", { class: "alert ok" }, icon("check"), "No repeated refusals or integrity failures."),
      h("div", { class: "grid stats" }, ...[["Role changes", dash.role_changes], ["Admin-triggered resets", dash.admin_triggered_resets], ["Failed sign-ins", dash.login_failures], ["Failed verifications", dash.failed_audit_verifications]].map(([l, n]) => h("div", { class: "stat" }, h("div", {}, h("b", {}, n), h("span", {}, l)))))) : null,
    h("div", { class: "card" }, h("h2", {}, "Active protections"), h("div", { class: "grid stats" }, ...items.map(([i, t, d]) => h("div", { class: "sec" }, h("span", { class: "ic" }, icon(i)), h("div", {}, h("b", {}, t), h("span", { class: "sm mute" }, d)))))),
    h("div", { class: "card" }, h("h2", {}, "Your session"), h("div", { class: "row" }, h("span", { class: "badge ok" }, icon("check"), "Signed in as " + me.username), h("span", { class: "badge" }, me.role), btn("Change password", () => { location.hash = "#/profile"; }, "alt sm", "key")))];
}
// ---- users (admin) ----

async function usersView() {
  if (me.role !== "admin") {
    return denied("Only administrators can manage users.");
  }

  const users = await api("GET", "/api/admin/users");

  const rows = users.map((u) => {
    const roleSelect = h(
      "select",
      {
        class: "in",
        "aria-label": "Role for " + u.username,
        onchange: (e) => {
          const newRole = e.target.value;

          confirmBox(
            "Change role?",
            `${u.username} becomes ${newRole}. Their sessions end immediately.`,
            "Change role",
            false
          ).then((ok) => {
            if (ok) {
              act(
                () =>
                  api("POST", `/api/admin/users/${u.id}/role`, {
                    role: newRole,
                  }),
                "Role changed; sessions ended."
              );
            } else {
              route();
            }
          });
        },
      },
      ...["admin", "owner", "viewer"].map((r) =>
        h("option", { value: r, selected: r === u.role }, r)
      )
    );

    const statusBadge = h(
      "span",
      { class: "badge " + (u.is_active ? "ok" : "bad") },
      u.is_active ? "Active" : "Disabled"
    );

    const toggleButton = btn(
      u.is_active ? "Disable" : "Enable",
      () =>
        confirmBox(
          u.is_active ? "Disable account?" : "Enable account?",
          u.username,
          u.is_active ? "Disable" : "Enable",
          u.is_active
        ).then((ok) => {
          if (ok) {
            return act(
              () =>
                api("POST", `/api/admin/users/${u.id}/status`, {
                  is_active: !u.is_active,
                }),
              "Status changed."
            );
          }
        }),
      "alt sm"
    );

    const resetButton = btn(
      "Send reset",
      () =>
        act(
          () =>
            api("POST", `/api/admin/users/${u.id}/trigger-reset`),
          "Reset request processed."
        ),
      "alt sm",
      "key"
    );

    return h(
      "tr",
      {},
      h(
        "td",
        {},
        h(
          "div",
          { class: "dn" },
          h("span", { class: "avatar" }, initials(u.username)),
          u.username
        )
      ),
      h("td", {}, roleSelect),
      h("td", {}, statusBadge),
      h(
        "td",
        {},
        h("div", { class: "row" }, toggleButton, resetButton)
      )
    );
  });

  const table = h(
    "div",
    { class: "card" },
    h(
      "div",
      { class: "tw" },
      h(
        "table",
        {},
        h(
          "thead",
          {},
          h(
            "tr",
            {},
            ...["User", "Role", "Status", ""].map((t) =>
              h("th", { scope: "col" }, t)
            )
          )
        ),
        h("tbody", {}, ...rows)
      )
    )
  );

  return [head("Users", `${users.length} accounts`), table];
}
// ---- profile ----
function profileView() {
  const cp = inp("password", { autocomplete: "current-password", required: true }), np = inp("password", { autocomplete: "new-password", required: true, minlength: 10 }), c2 = inp("password", { autocomplete: "current-password", required: true }), ne = inp("email", { required: true });
  const chk = f => f.reportValidity();
  return [head("Profile & settings", "Manage your account and preferences."),
    h("div", { class: "card" }, h("div", { class: "dn" }, h("span", { class: "avatar" }, initials(me.username)), h("div", {}, h("h2", {}, me.username), h("div", { class: "row" }, h("span", { class: "badge" }, me.role), me.email ? h("span", { class: "sm mute" }, me.email) : null)))),
    h("div", { class: "card" }, h("h2", {}, "Appearance"), h("div", { class: "row" }, btn("Switch light / dark theme", toggleTheme, "alt", "sun"))),
    h("form", { class: "card", onsubmit: e => { e.preventDefault(); if (chk(e.target)) act(() => api("POST", "/api/auth/change-password", { current_password: cp.value, new_password: np.value }), "Password changed. Sign in again.", () => { me = null; shell = null; route(); }); } },
      h("h2", {}, "Change password"), h("div", { class: "fields" }, fld("Current password", cp), fld("New password", np, "10+ characters with Aa1!"), btn("Update password", () => {}, "", "key", { type: "submit" }))),
    h("form", { class: "card", onsubmit: e => { e.preventDefault(); if (chk(e.target)) act(() => api("POST", "/api/auth/email-change-request", { current_password: c2.value, new_email: ne.value }), "Confirmation sent to your current email."); } },
      h("h2", {}, "Change email"), h("div", { class: "fields" }, fld("Current password", c2), fld("New email", ne, "A confirmation link goes to your current address."), btn("Request change", () => {}, "alt", "swap", { type: "submit" })))];
}
window.addEventListener("hashchange", route); route();