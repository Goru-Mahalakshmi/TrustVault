"use strict";
// All DOM is built with textContent / createElement: server data is never parsed as HTML.
const app = document.getElementById("app"), who = document.getElementById("who");
let me = null, csrf = sessionStorage.getItem("csrf") || "", flash = null;

function h(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
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
    throw Object.assign(new Error(d), { status: r.status });
  }
  return raw ? r : r.json();
}
const say = (text, kind = "ok") => { flash = { text, kind }; };
const banner = () => flash ? h("div", { class: "msg " + flash.kind }, flash.text) : null;
async function run(fn, after) { try { await fn(); } catch (e) { say(e.message, "err"); } if (after) await after(); else await render(); }

async function loadMe() {
  try { me = await api("GET", "/api/auth/me"); csrf = me.csrf_token; sessionStorage.setItem("csrf", csrf); }
  catch { me = null; sessionStorage.removeItem("csrf"); }
}
async function render() {
  const hash = location.hash;
  await loadMe();
  who.replaceChildren();
  if (me) who.append(h("span", { class: "mute" }, `${me.username} · `), h("span", { class: "pill" }, me.role), " ",
    h("button", { class: "alt", onclick: () => run(async () => { await api("POST", "/api/auth/logout"); me = null; }) }, "Log out"));
  const view = hash.startsWith("#reset=") ? resetView(hash.slice(7)) : hash.startsWith("#confirm-email=") ? confirmView(hash.slice(15))
    : !me ? authView() : [await docsView(), me.role === "owner" ? await transfersView() : null, me.role === "admin" ? await adminView() : null,
      accountView()];
  app.replaceChildren(banner(), ...[view].flat(Infinity).filter(Boolean)); flash = null;
}
const field = (id, type = "text", ph = "") => h("input", { id, type, placeholder: ph, autocomplete: "off" });
const val = id => document.getElementById(id).value;

function authView() {
  return [h("div", { class: "card" }, h("h2", {}, "Log in"),
    h("div", { class: "row" }, field("lu", "text", "username"), field("lp", "password", "password"),
      h("button", { onclick: () => run(async () => { const r = await api("POST", "/api/auth/login", { username: val("lu"), password: val("lp") }); csrf = r.csrf_token; }) }, "Log in")),
    h("div", { class: "row" }, field("fe", "email", "email for password reset"),
      h("button", { class: "alt", onclick: () => run(async () => { const r = await api("POST", "/api/auth/forgot-password", { email: val("fe") }); say(r.message); }) }, "Forgot password"))),
    h("div", { class: "card" }, h("h2", {}, "Create account"),
      h("div", { class: "row" }, field("ru", "text", "username"), field("re", "email", "email"), field("rp", "password", "password (10+, Aa1!)"),
        h("button", { onclick: () => run(async () => { await api("POST", "/api/auth/register", { username: val("ru"), email: val("re"), password: val("rp") }); say("Account created. Log in."); }) }, "Register")))];
}
function resetView(token) {
  return h("div", { class: "card" }, h("h2", {}, "Choose a new password"), h("div", { class: "row" }, field("np", "password", "new password"),
    h("button", { onclick: () => run(async () => { await api("POST", "/api/auth/reset-password", { token, new_password: val("np") }); location.hash = ""; say("Password reset. Log in."); }) }, "Reset")));
}
function confirmView(token) {
  return h("div", { class: "card" }, h("h2", {}, "Confirm email change"),
    h("button", { onclick: () => run(async () => { await api("POST", "/api/auth/email-change-confirm", { token }); location.hash = ""; say("Email updated. Log in again."); }) }, "Confirm"));
}
function accountView() {
  return h("div", { class: "card" }, h("h2", {}, "Account"),
    h("div", { class: "row" }, field("cp", "password", "current password"), field("np2", "password", "new password"),
      h("button", { class: "alt", onclick: () => run(async () => { await api("POST", "/api/auth/change-password", { current_password: val("cp"), new_password: val("np2") }); say("Password changed. Log in again."); }) }, "Change password")),
    h("div", { class: "row" }, field("cp2", "password", "current password"), field("ne", "email", "new email"),
      h("button", { class: "alt", onclick: () => run(async () => { await api("POST", "/api/auth/email-change-request", { current_password: val("cp2"), new_email: val("ne") }); say("Confirmation sent to your CURRENT email."); }) }, "Change email")));
}

let selected = null;
async function docsView() {
  const list = await api("GET", "/api/documents?limit=50");
  const card = h("div", { class: "card" }, h("h2", {}, `Documents (${list.total})`));
  if (me.role === "owner") card.append(h("div", { class: "row" }, field("t", "text", "title"), field("c", "text", "category"), h("input", { id: "f", type: "file" }),
    h("button", { onclick: () => run(async () => { const fd = new FormData(); fd.append("title", val("t")); fd.append("category", val("c")); fd.append("file", document.getElementById("f").files[0]); await api("POST", "/api/documents", fd); say("Uploaded & encrypted."); }) }, "Upload")));
  const tb = h("table", {}, h("tr", {}, h("th", {}, "Title"), h("th", {}, "Category"), h("th", {}, "Size"), h("th", {})));
  for (const d of list.items) tb.append(h("tr", {}, h("td", {}, d.title), h("td", {}, d.category), h("td", {}, d.file_size_bytes + " B"), h("td", {},
    h("button", { onclick: () => run(() => download(d)) }, "Download"), " ", h("button", { class: "alt", onclick: () => { selected = d; render(); } }, "Manage"))));
  card.append(tb);
  return [card, selected ? await manageView(selected) : null];
}
async function download(d) {
  const r = await api("GET", `/api/documents/${d.id}/download`, null, true);
  const name = /filename="([^"]+)"/.exec(r.headers.get("content-disposition") || "")?.[1] || "download";
  const a = h("a", { href: URL.createObjectURL(await r.blob()), download: name }); a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
async function manageView(d) {
  const card = h("div", { class: "card" }, h("h2", {}, `Manage: ${d.title}`));
  const isOwner = me.role === "owner";
  card.append(h("div", { class: "row" }, h("input", { id: "nv", type: "file" }),
    h("button", { class: "alt", onclick: () => run(async () => { const fd = new FormData(); fd.append("file", document.getElementById("nv").files[0]); await api("POST", `/api/documents/${d.id}/versions`, fd); say("New version uploaded."); }) }, "Upload new version")));
  let grants = null; try { grants = await api("GET", `/api/documents/${d.id}/grants`); } catch { /* not the owner: 403 */ }
  if (grants) {
    card.append(h("h2", {}, "Access"),
      h("div", { class: "row" }, field("ge", "email", "grantee email (exact)"), h("select", { id: "gl" }, h("option", {}, "read"), h("option", {}, "edit")),
        h("button", { onclick: () => run(async () => { await api("POST", `/api/documents/${d.id}/grants`, { grantee_email: val("ge"), level: val("gl") }); say("Access granted."); }) }, "Grant")));
    const tb = h("table", {}, h("tr", {}, h("th", {}, "Grantee id"), h("th", {}, "Level"), h("th", {}, "State"), h("th", {})));
    for (const g of grants) tb.append(h("tr", {}, h("td", {}, g.grantee_user_id), h("td", {}, g.level), h("td", {}, g.revoked_at ? "revoked" : g.expires_at ? "until " + g.expires_at : "active"),
      h("td", {}, g.revoked_at ? "" : h("button", { class: "bad", onclick: () => run(async () => { await api("POST", `/api/documents/${d.id}/grants/${g.id}/revoke`); say("Revoked instantly."); }) }, "Revoke"))));
    card.append(tb, h("div", { class: "row" }, field("te", "email", "transfer ownership to (must be an owner)"),
      h("button", { class: "alt", onclick: () => run(async () => { await api("POST", `/api/documents/${d.id}/transfer-request`, { target_email: val("te") }); say("Transfer requested; recipient must accept."); }) }, "Request transfer"),
      h("button", { class: "alt", onclick: () => run(async () => { await api("POST", `/api/documents/${d.id}/transfer-cancel`); say("Transfer cancelled."); }) }, "Cancel transfer")),
      h("div", { class: "row" }, h("button", { class: "alt", onclick: () => run(async () => { const r = await api("POST", `/api/documents/${d.id}/grantee-suggestions`); say(r.suggestions.length ? "AI suggests (you must still confirm): " + r.suggestions.map(s => `${s.username} - ${s.reason}`).join("; ") : "No suggestions."); }) }, "AI: suggest grantees (advisory)"),
        h("button", { class: "bad", onclick: () => run(async () => { await api("DELETE", `/api/documents/${d.id}`); selected = null; say("Moved to trash. Grants preserved for restore."); }) }, "Delete")));
  }
  return card;
}
async function transfersView() {
  const p = await api("GET", "/api/documents/pending-transfers"); if (!p.length) return null;
  const card = h("div", { class: "card" }, h("h2", {}, "Pending ownership transfers"), h("div", { class: "mute" }, "You can see nothing about the document until you accept."));
  for (const t of p) card.append(h("div", { class: "row" }, `${t.from_username} wants to transfer a "${t.category}" document `,
    h("button", { onclick: () => run(async () => { await api("POST", `/api/documents/${t.document_id}/transfer-accept`); say("You now own it."); }) }, "Accept"),
    h("button", { class: "alt", onclick: () => run(async () => { await api("POST", `/api/documents/${t.document_id}/transfer-reject`); say("Rejected."); }) }, "Reject")));
  return card;
}
async function adminView() {
  const [users, dash] = await Promise.all([api("GET", "/api/admin/users"), api("GET", "/api/admin/dashboard")]);
  const card = h("div", { class: "card" }, h("h2", {}, "Admin: worth noticing (24h)"),
    h("div", { class: "mute" }, `role changes ${dash.role_changes} · admin resets ${dash.admin_triggered_resets} · login failures ${dash.login_failures} · failed verifications ${dash.failed_audit_verifications}`),
    ...dash.repeated_refusals.map(r => h("div", { class: "msg err" }, `${r.subject}: ${r.count} refusals`)),
    h("div", { class: "row" }, h("button", { onclick: () => run(async () => { const r = await api("POST", "/api/admin/audit/verify"); say(r.status === "VALID" ? `Audit chain VALID (${r.total_records} records)` : `Audit chain CORRUPTED at #${r.broken_sequence}`, r.status === "VALID" ? "ok" : "err"); }) }, "Verify audit chain")));
  const tb = h("table", {}, h("tr", {}, h("th", {}, "User"), h("th", {}, "Role"), h("th", {}, "Active"), h("th", {})));
  for (const u of users) tb.append(h("tr", {}, h("td", {}, u.username), h("td", {}, h("select", { onchange: e => run(() => api("POST", `/api/admin/users/${u.id}/role`, { role: e.target.value }).then(() => say("Role changed; their sessions ended."))) },
    ...["admin", "owner", "viewer"].map(r => h("option", { value: r, selected: r === u.role }, r)))), h("td", {}, u.is_active ? "yes" : "no"), h("td", {},
    h("button", { class: "alt", onclick: () => run(async () => { await api("POST", `/api/admin/users/${u.id}/status`, { is_active: !u.is_active }); say("Status changed."); }) }, u.is_active ? "Disable" : "Enable"), " ",
    h("button", { class: "alt", onclick: () => run(async () => { await api("POST", `/api/admin/users/${u.id}/trigger-reset`); say("Reset link emailed to the user."); }) }, "Send reset"))));
  card.append(tb); return card;
}
window.addEventListener("hashchange", render); render();
