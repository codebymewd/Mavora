// Mavora API (Cloudflare Worker). Secrets live here, never in the website.
// Settings > Variables and Secrets:
//   FIREBASE_PROJECT_ID  (text)    e.g. mavora-a8feb
//   ALLOWED_ORIGINS      (text)    e.g. https://mavora-6v1.pages.dev   (comma separated for more)
//   SERVICE_ACCOUNT      (SECRET)  the whole Firebase service-account JSON
const enc = new TextEncoder(), dec = new TextDecoder();
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); return Uint8Array.from(atob(s + "=".repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0)); };
const fail = (m, s = 400) => { throw Object.assign(new Error(m), { http: s, user: true }); };
const json = (o, s, h) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", ...h } });

/* ---- Firebase ID token verification (RS256 against Google's public keys) ---- */
let JWKS = null, JT = 0;
async function verifyToken(tok, env) {
  const [h, p, s] = tok.split("."); if (!s) throw 0;
  const head = JSON.parse(dec.decode(unb64u(h))), pay = JSON.parse(dec.decode(unb64u(p)));
  if (head.alg !== "RS256") throw 0;
  if (!JWKS || Date.now() - JT > 36e5) { JWKS = (await (await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")).json()).keys; JT = Date.now(); }
  const jwk = JWKS.find(k => k.kid === head.kid); if (!jwk) throw 0;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, unb64u(s), enc.encode(h + "." + p)))) throw 0;
  const now = Date.now() / 1e3;
  if (pay.aud !== env.FIREBASE_PROJECT_ID || pay.iss !== "https://securetoken.google.com/" + env.FIREBASE_PROJECT_ID || pay.exp < now || !pay.sub) throw 0;
  return pay;
}

/* ---- Google access token for Firestore (service account) ---- */
let AT = null, AX = 0;
async function accessToken(env) {
  if (AT && Date.now() < AX) return AT;
  const sa = JSON.parse(env.SERVICE_ACCOUNT), now = Math.floor(Date.now() / 1e3);
  const h = b64u(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const c = b64u(enc.encode(JSON.stringify({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 })));
  const pem = sa.private_key.replace(/-----[^-]+-----|\s/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), x => x.charCodeAt(0)), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(h + "." + c)));
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + h + "." + c + "." + sig });
  const j = await r.json(); if (!j.access_token) throw new Error("service account auth failed");
  AT = j.access_token; AX = Date.now() + (j.expires_in - 120) * 1e3; return AT;
}

/* ---- Firestore REST helpers ---- */
const toV = v => v === null || v === undefined ? { nullValue: null } : typeof v === "string" ? { stringValue: v } : typeof v === "boolean" ? { booleanValue: v } : typeof v === "number" ? (Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v }) : v instanceof Date ? { timestampValue: v.toISOString() } : Array.isArray(v) ? { arrayValue: { values: v.map(toV) } } : { mapValue: { fields: Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toV(x)])) } };
const fromV = v => "stringValue" in v ? v.stringValue : "integerValue" in v ? Number(v.integerValue) : "doubleValue" in v ? v.doubleValue : "booleanValue" in v ? v.booleanValue : "timestampValue" in v ? v.timestampValue : "arrayValue" in v ? (v.arrayValue.values || []).map(fromV) : "mapValue" in v ? fromD(v.mapValue) : null;
const fromD = d => Object.fromEntries(Object.entries(d.fields || {}).map(([k, v]) => [k, fromV(v)]));
const toF = o => toV(o).mapValue.fields;
const base = env => `projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
async function fs(env, path, body) {
  const r = await fetch(`https://firestore.googleapis.com/v1/${base(env)}${path}`, { method: "POST", headers: { Authorization: "Bearer " + await accessToken(env), "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json(); if (!r.ok) throw Object.assign(new Error(j.error?.message || "firestore error"), { status: r.status }); return j;
}
const getDocs = async (env, t, paths) => (await fs(env, ":batchGet", { documents: paths.map(p => `${base(env)}/${p}`), transaction: t })).reduce((m, x) => { if (x.found) m[x.found.name.split("/documents/")[1]] = { name: x.found.name, updateTime: x.found.updateTime, data: fromD(x.found) }; return m; }, {});
async function txn(env, fn) {
  for (let i = 0; i < 3; i++) {
    const t = (await fs(env, ":beginTransaction", { options: { readWrite: {} } })).transaction;
    try { const writes = await fn(t); await fs(env, ":commit", { writes, transaction: t }); return; }
    catch (e) { if (!e.user && (e.status === 409 || /aborted|contention/i.test(e.message))) continue; throw e; }
  }
  fail("The shop is busy. Please try again.", 503);
}
const REQ = { updateTransforms: [{ fieldPath: "createdAt", setToServerValue: "REQUEST_TIME" }, { fieldPath: "updatedAt", setToServerValue: "REQUEST_TIME" }] };
const stock = (env, path, n) => ({ transform: { document: `${base(env)}/${path}`, fieldTransforms: [{ fieldPath: "stock", increment: { integerValue: String(n) } }] } });
const price = p => p.discountPrice > 0 && p.discountPrice < p.price ? p.discountPrice : p.price;
const str = (v, min, max, name) => { v = typeof v === "string" ? v.trim() : ""; if (v.length < min || v.length > max) fail(`Please check ${name}.`); return v; };

/* ---- POST /api/orders : checkout ---- */
async function createOrders(req, env, user) {
  const b = await req.json().catch(() => fail("Invalid request"));
  if (!Array.isArray(b.items) || !b.items.length || b.items.length > 30) fail("Your cart is empty or too large.");
  const items = b.items.map(x => {
    if (typeof x.id !== "string" || !/^[A-Za-z0-9]{10,40}$/.test(x.id) || !Number.isInteger(x.qty) || x.qty < 1 || x.qty > 99) fail("Invalid item in cart.");
    return { id: x.id, qty: x.qty, color: typeof x.color === "string" ? x.color.slice(0, 20) : "" };
  });
  const d = b.delivery || {};
  const delivery = { name: str(d.name, 2, 80, "your name"), phone: str(d.phone, 10, 16, "your phone number"), email: str(d.email, 5, 120, "your email"), address: str(d.address, 3, 200, "the address"), state: str(d.state, 2, 60, "the state"), city: str(d.city, 2, 60, "the city"), notes: typeof d.notes === "string" ? d.notes.trim().slice(0, 300) : "" };
  if (!/^[0-9+ ]{10,16}$/.test(delivery.phone) || !/^\S+@\S+\.\S+$/.test(delivery.email)) fail("Please check your phone number and email.");
  let out = [];
  await txn(env, async t => {
    out = [];
    const ids = [...new Set(items.map(i => i.id))];
    const docs = await getDocs(env, t, [...ids.map(i => "products/" + i), "counters/orders"]);
    const need = {}; items.forEach(i => need[i.id] = (need[i.id] || 0) + i.qty);
    const groups = {};
    for (const i of items) {
      const p = docs["products/" + i.id]?.data;
      if (!p || p.status !== "ACTIVE") fail("An item in your cart is no longer available.");
      if (p.sellerId === user.sub) fail("You can't buy your own product.");
      if (!(p.stock >= need[i.id])) fail(p.stock > 0 ? `Only ${p.stock} left of ${p.name}.` : `${p.name} is out of stock.`);
      if ((p.colors || []).length && !p.colors.includes(i.color)) fail(`Please choose a colour for ${p.name}.`);
      (groups[p.sellerId] = groups[p.sellerId] || { sellerName: p.sellerName, items: [] }).items.push({ productId: i.id, name: p.name, price: price(p), qty: i.qty, color: i.color, image: p.image || "" });
    }
    let n = docs["counters/orders"]?.data.count || 0; const writes = [], year = new Date().getFullYear();
    for (const [sellerId, g] of Object.entries(groups)) {
      n++; const id = `MAV-${year}-${String(n).padStart(6, "0")}`, total = g.items.reduce((a, x) => a + x.price * x.qty, 0);
      writes.push({ update: { name: `${base(env)}/orders/${id}`, fields: toF({ orderNumber: id, buyerId: user.sub, buyerName: delivery.name, sellerId, sellerName: g.sellerName || "Seller", items: g.items, subtotal: total, total, status: "Pending", payment: "Pay the seller directly", delivery, history: [{ status: "Pending", at: new Date() }] }) }, currentDocument: { exists: false }, ...REQ });
      out.push({ id, sellerName: g.sellerName, total });
    }
    Object.entries(need).forEach(([pid, q]) => writes.push(stock(env, "products/" + pid, -q)));
    writes.push({ update: { name: `${base(env)}/counters/orders`, fields: toF({ count: n }) } });
    return writes;
  });
  return { orders: out };
}

/* ---- PATCH /api/orders/:id/status ---- */
const NEXT_S = { Pending: ["Confirmed", "Cancelled"], Confirmed: ["Processing", "Cancelled"], Processing: ["Ready for Pickup", "Ready for Delivery"], "Ready for Pickup": ["Delivered"], "Ready for Delivery": ["Shipped"], Shipped: ["Delivered"] };
const NEXT_B = { Pending: ["Cancelled"], Delivered: ["Completed"] };
async function setStatus(req, env, user, id) {
  const b = await req.json().catch(() => fail("Invalid request")), status = b.status;
  if (typeof status !== "string") fail("Invalid status.");
  await txn(env, async t => {
    const od = (await getDocs(env, t, ["orders/" + id]))["orders/" + id]; if (!od) fail("Order not found.", 404);
    const o = od.data, role = o.sellerId === user.sub ? "seller" : o.buyerId === user.sub ? "buyer" : null;
    if (!role) fail("Not allowed.", 403);
    if (!((role === "seller" ? NEXT_S : NEXT_B)[o.status] || []).includes(status)) fail("That status change is not allowed right now.");
    const writes = [{ update: { name: od.name, fields: toF({ status, history: [...(o.history || []).map(h => ({ status: h.status, at: new Date(h.at) })), { status, at: new Date() }] }) }, updateMask: { fieldPaths: ["status", "history"] }, updateTransforms: [{ fieldPath: "updatedAt", setToServerValue: "REQUEST_TIME" }], currentDocument: { updateTime: od.updateTime } }];
    if (status === "Cancelled") { // give the stock back (only for products that still exist)
      const need = {}; o.items.forEach(i => need[i.productId] = (need[i.productId] || 0) + i.qty);
      const ps = await getDocs(env, t, Object.keys(need).map(p => "products/" + p));
      Object.entries(need).forEach(([pid, q]) => { if (ps["products/" + pid]) writes.push(stock(env, "products/" + pid, q)); });
    }
    return writes;
  });
  return { ok: true };
}

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "", allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
    const cors = { "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : "", "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,Authorization", "Access-Control-Max-Age": "86400", Vary: "Origin" };
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      const u = new URL(req.url);
      if (u.pathname === "/api/health") return json({ ok: true }, 200, cors);
      if (origin && !allowed.includes(origin)) return json({ error: "Origin not allowed" }, 403, cors);
      if (Number(req.headers.get("Content-Length") || 0) > 20000) return json({ error: "Request too large" }, 413, cors);
      const tok = (req.headers.get("Authorization") || "").replace(/^Bearer /, "");
      if (!tok) return json({ error: "Please sign in" }, 401, cors);
      let user; try { user = await verifyToken(tok, env); } catch (e) { return json({ error: "Please sign in again" }, 401, cors); }
      if (req.method === "POST" && u.pathname === "/api/orders") return json(await createOrders(req, env, user), 200, cors);
      const m = u.pathname.match(/^\/api\/orders\/([A-Za-z0-9-]{6,40})\/status$/);
      if (m && req.method === "PATCH") return json(await setStatus(req, env, user, m[1]), 200, cors);
      return json({ error: "Not found" }, 404, cors);
    } catch (e) {
      console.error(e.message);
      return json({ error: e.user ? e.message : "Something went wrong. Please try again." }, e.http || 500, cors);
    }
  }
};
