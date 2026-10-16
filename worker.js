// Mavora API (Cloudflare Worker). Secrets live here, never in the website.
// Settings > Variables and Secrets:
//   FIREBASE_PROJECT_ID  (text)    e.g. mavora-a8feb
//   ALLOWED_ORIGINS      (text)    e.g. https://mavora-6v1.pages.dev   (comma separated for more)
//   SERVICE_ACCOUNT      (SECRET)  the whole Firebase service-account JSON
//   TURNSTILE_SECRET     (SECRET)  Cloudflare Turnstile secret key
//   FIREBASE_API_KEY     (text)    your Firebase web apiKey (public by design)
//   CLOUDINARY_CLOUD     (text)    your Cloudinary cloud name (listing image URLs must come from it)
//   ADMIN_EMAILS         (text)    your admin email(s), comma separated. Must be a verified Mavora account.
//   RL                   (KV binding) a KV namespace used for rate limits and lockouts
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
  const c = b64u(enc.encode(JSON.stringify({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/cloud-platform", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 })));
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
      if ((p.ownerId || p.sellerId) === user.sub) fail("You can't buy your own product.");
      if (!(p.stock >= need[i.id])) fail(p.stock > 0 ? `Only ${p.stock} left of ${p.name}.` : `${p.name} is out of stock.`);
      if ((p.colors || []).length && !p.colors.includes(i.color)) fail(`Please choose a colour for ${p.name}.`);
      (groups[p.sellerId] = groups[p.sellerId] || { sellerName: p.sellerName, ownerId: p.ownerId || p.sellerId, items: [] }).items.push({ productId: i.id, name: p.name, price: price(p), qty: i.qty, color: i.color, image: p.image || "" });
    }
    let n = docs["counters/orders"]?.data.count || 0; const writes = [], year = new Date().getFullYear();
    for (const [sellerId, g] of Object.entries(groups)) {
      n++; const id = `MAV-${year}-${String(n).padStart(6, "0")}`, total = g.items.reduce((a, x) => a + x.price * x.qty, 0);
      writes.push({ update: { name: `${base(env)}/orders/${id}`, fields: toF({ orderNumber: id, buyerId: user.sub, buyerName: delivery.name, sellerId, sellerOwnerId: g.ownerId, sellerName: g.sellerName || "Seller", items: g.items, subtotal: total, total, status: "Pending", payment: "Pay the seller directly", delivery, history: [{ status: "Pending", at: new Date() }] }) }, currentDocument: { exists: false }, ...REQ });
      out.push({ id, sellerName: g.sellerName, total });
      writes.push(notif(env, g.ownerId, "order", "New order " + id, `${g.items.length} item(s), ${naira(total)} from ${delivery.name}`, "#/order/" + id));
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
    const o = od.data, role = (o.sellerOwnerId || o.sellerId) === user.sub ? "seller" : o.buyerId === user.sub ? "buyer" : null;
    if (!role) fail("Not allowed.", 403);
    if (!((role === "seller" ? NEXT_S : NEXT_B)[o.status] || []).includes(status)) fail("That status change is not allowed right now.");
    const writes = [{ update: { name: od.name, fields: toF({ status, history: [...(o.history || []).map(h => ({ status: h.status, at: new Date(h.at) })), { status, at: new Date() }] }) }, updateMask: { fieldPaths: ["status", "history"] }, updateTransforms: [{ fieldPath: "updatedAt", setToServerValue: "REQUEST_TIME" }], currentDocument: { updateTime: od.updateTime } }];
    if (status === "Cancelled") { // give the stock back (only for products that still exist)
      const need = {}; o.items.forEach(i => need[i.productId] = (need[i.productId] || 0) + i.qty);
      const ps = await getDocs(env, t, Object.keys(need).map(p => "products/" + p));
      Object.entries(need).forEach(([pid, q]) => { if (ps["products/" + pid]) writes.push(stock(env, "products/" + pid, q)); });
    }
    if (status === "Completed") writes.push(inc(env, "sellerProfiles/" + o.sellerId, "completedSales"));
    writes.push(notif(env, role === "seller" ? o.buyerId : (o.sellerOwnerId || o.sellerId), "order", `Order ${o.orderNumber}: ${status}`, role === "seller" ? "The seller updated your order." : "The buyer updated this order.", "#/order/" + id));
    return writes;
  });
  return { ok: true };
}

/* ================= SECURITY LAYER ================= */
const hex = async s => [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))].map(b => b.toString(16).padStart(2, "0")).join("");
const kvGet = async (env, k) => env.RL ? Number(await env.RL.get(k)) || 0 : 0;
const kvInc = async (env, k, ttl) => { if (env.RL) await env.RL.put(k, String((await kvGet(env, k)) + 1), { expirationTtl: Math.max(60, ttl) }); };
async function limit(env, key, max, ttl) { // rate limit: throws 429 when exceeded
  const n = await kvGet(env, "rl:" + key);
  if (n >= max) throw Object.assign(new Error("Too many requests. Please wait a little and try again."), { http: 429, user: true, retry: ttl });
  await kvInc(env, "rl:" + key, ttl);
}
const body = async (req, keys) => {
  const b = await req.json().catch(() => fail("Invalid request"));
  if (!b || typeof b !== "object" || Array.isArray(b)) fail("Invalid request");
  if (keys) for (const k of Object.keys(b)) if (!keys.includes(k)) fail("Invalid request");
  return b;
};
const mail = v => { v = typeof v === "string" ? v.trim().toLowerCase() : ""; if (v.length < 5 || v.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v)) fail("Please enter a valid email address."); return v; };
const needVerified = u => { if (!u.email_verified) fail("Please verify your email address first. Open Account to resend the email.", 403); };
async function turnstile(env, token, ip) {
  if (!env.TURNSTILE_SECRET || typeof token !== "string" || token.length < 10 || token.length > 2100) return false;
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip }) });
  return (await r.json().catch(() => ({}))).success === true;
}
async function idt(env, method, payload, origin) { // Identity Toolkit REST (server-side use of the public web key)
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/${method}?key=${env.FIREBASE_API_KEY}`, { method: "POST", headers: { "Content-Type": "application/json", Referer: origin }, body: JSON.stringify(payload) });
  return { ok: r.ok, data: await r.json().catch(() => ({})) };
}
let SKEY = null;
async function customToken(env, uid) {
  const sa = JSON.parse(env.SERVICE_ACCOUNT), now = Math.floor(Date.now() / 1e3);
  if (!SKEY) SKEY = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(sa.private_key.replace(/-----[^-]+-----|\s/g, "")), x => x.charCodeAt(0)), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const h = b64u(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const c = b64u(enc.encode(JSON.stringify({ iss: sa.client_email, sub: sa.client_email, aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit", iat: now, exp: now + 3000, uid })));
  return h + "." + c + "." + b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", SKEY, enc.encode(h + "." + c)));
}
const rid = () => [...crypto.getRandomValues(new Uint8Array(15))].map(b => "abcdefghijklmnopqrstuvwxyz0123456789"[b % 36]).join("") + "x" + Date.now().toString(36).slice(-4);

/* ---- public auth endpoints (Turnstile + rate limits + brute-force lockout) ---- */
async function register(req, env, X) {
  const b = await body(req, ["email", "password", "name", "acceptTerms", "turnstile"]);
  await limit(env, "reg:i:" + X.ip, 5, 3600);
  const em = mail(b.email), name = str(b.name, 2, 80, "your name"), pw = typeof b.password === "string" ? b.password : "";
  if (pw.length < 8 || pw.length > 128 || !/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) fail("Password needs 8+ characters with upper case, lower case and a number.");
  if (b.acceptTerms !== true) fail("Please accept the Terms & Conditions and Privacy Policy.");
  if (!(await turnstile(env, b.turnstile, X.ip))) { X.log("turnstile_fail", { where: "register" }); fail("Security check failed. Please try again."); }
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/accounts`, { method: "POST", headers: { Authorization: "Bearer " + await accessToken(env), "Content-Type": "application/json" }, body: JSON.stringify({ email: em, password: pw, displayName: name, emailVerified: false }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { X.log("register_rejected", { reason: String(j.error?.message || "").slice(0, 40) }); fail("Could not create the account. If you already have one, sign in or reset your password."); }
  await fs(env, ":commit", { writes: [{ update: { name: `${base(env)}/users/${j.localId}`, fields: toF({ uid: j.localId, fullName: name, email: em, phone: "", photoURL: "", role: "BUYER", accountStatus: "ACTIVE", theme: "system", termsAccepted: true, termsVersion: TERMS, privacyPolicyVersion: TERMS }) }, currentDocument: { exists: false }, updateTransforms: ["createdAt", "updatedAt", "termsAcceptedAt", "privacyPolicyAcceptedAt"].map(f => ({ fieldPath: f, setToServerValue: "REQUEST_TIME" })) }] }).catch(e => console.error("user doc", e.message));
  const si = await idt(env, "accounts:signInWithPassword", { email: em, password: pw, returnSecureToken: true }, X.origin);
  if (si.ok) await idt(env, "accounts:sendOobCode", { requestType: "VERIFY_EMAIL", idToken: si.data.idToken }, X.origin);
  return { token: await customToken(env, j.localId) };
}
async function login(req, env, X) {
  const b = await body(req, ["email", "password", "turnstile"]);
  const em = mail(b.email), pw = typeof b.password === "string" ? b.password : ""; if (!pw || pw.length > 128) fail("Wrong email or password.", 401);
  const ke = "lf:e:" + (await hex(em)), ki = "lf:i:" + X.ip, fe = await kvGet(env, ke), fi = await kvGet(env, ki);
  if (fe >= 8 || fi >= 25) { X.log("login_locked"); throw Object.assign(new Error("Too many attempts. Please try again in 15 minutes."), { http: 429, user: true, retry: 900 }); }
  if (fe >= 3 || fi >= 10) { // suspicious: require Turnstile
    if (!b.turnstile) return { __status: 401, error: "Please complete the security check.", needCaptcha: true };
    if (!(await turnstile(env, b.turnstile, X.ip))) { X.log("turnstile_fail", { where: "login" }); return { __status: 401, error: "Security check failed. Please try again.", needCaptcha: true }; }
  }
  const r = await idt(env, "accounts:signInWithPassword", { email: em, password: pw, returnSecureToken: true }, X.origin);
  if (!r.ok || !r.data.localId) { await kvInc(env, ke, 900); await kvInc(env, ki, 900); X.log("login_fail"); return { __status: 401, error: "Wrong email or password." }; }
  if (env.RL) await env.RL.delete(ke); // success resets this account's counter
  return { token: await customToken(env, r.data.localId) };
}
async function forgot(req, env, X) {
  const b = await body(req, ["email", "turnstile"]);
  await limit(env, "fp:i:" + X.ip, 5, 900);
  if (!(await turnstile(env, b.turnstile, X.ip))) { X.log("turnstile_fail", { where: "forgot" }); fail("Security check failed. Please try again."); }
  let em; try { em = mail(b.email); } catch (e) { return { ok: true }; } // same answer for everything: no account enumeration
  try { await limit(env, "fp:e:" + (await hex(em)), 3, 3600); await idt(env, "accounts:sendOobCode", { requestType: "PASSWORD_RESET", email: em }, X.origin); } catch (e) { if (e.http !== 429) console.error("forgot", e.message); }
  return { ok: true };
}
async function resend(req, env, X, user, tok) {
  await limit(env, "rv:u:" + user.sub, 3, 3600);
  const r = await idt(env, "accounts:sendOobCode", { requestType: "VERIFY_EMAIL", idToken: tok }, X.origin);
  if (!r.ok) fail("Could not send the email. Please try again later.");
  return { ok: true };
}

/* ---- seller registration and listing creation (server decides sellerId, status, timestamps) ---- */
const PCATS = ["Phones", "Computers", "Electronics", "Fashion", "Home & Living", "Beauty", "Vehicles", "Food", "Other"];
const SCATS = ["Plumbing", "Electrical Services", "Building & Masonry", "Painting", "Carpentry & Furniture", "Welding & Metalwork", "Cleaning Services", "Gardening & Landscaping", "Pest Control", "Phone & Tablet Repair", "Computer & Laptop Repair", "Appliance Repair", "Electronics Repair", "Generator Repair", "Air Conditioner Repair", "Refrigeration", "Other Technical Repairs", "Auto Repair & Mechanics", "Auto Electrical", "Car Wash & Detailing", "Tyre Services", "Towing", "Other Auto Services", "Hair Styling", "Barbering", "Makeup", "Nails", "Spa & Massage", "Other Beauty Services", "Photography", "Videography", "DJ Services", "Event Decoration", "Catering", "Event Planning", "Other Event Services", "Graphic Design", "Web Development", "Digital Marketing", "Accounting", "Legal Services", "Consulting", "Business Services", "Private Tutoring", "Computer Training", "Music Lessons", "Language Lessons", "Vocational Training", "Other Education Services", "Tailoring & Fashion Design", "Moving & Haulage", "Delivery & Logistics", "Security Services", "Childcare & Domestic Services", "Writing & Translation", "Other Services"];
const oneOf = (v, list, name) => { if (!list.includes(v)) fail(`Please check ${name}.`); return v; };
const optStr = (v, max, name) => { if (v === undefined || v === null || v === "") return ""; if (typeof v !== "string" || v.trim().length > max) fail(`Please check ${name}.`); return v.trim(); };
const TERMS = "2026-10-15", MAX_STORES = 10;
async function needTerms(env, user) {
  const u = (await getDocs(env, undefined, ["users/" + user.sub]))["users/" + user.sub]?.data;
  if (!u || u.accountStatus === "DELETED" || u.termsVersion !== TERMS) fail("Please accept the latest Terms & Conditions to continue.", 403);
}
async function sellerRegister(req, env, X, user) { // creates a store (a user can own many)
  needVerified(user);
  const b = await body(req, ["businessName", "description", "location", "providerType", "serviceArea", "hasShop", "shopName", "phone", "address", "landmark", "pickupType", "pickupContactName", "pickupInstructions", "storeCategory", "logo", "turnstile"]);
  await needTerms(env, user);
  await limit(env, "sr:u:" + user.sub, 5, 86400);
  if (!(await turnstile(env, b.turnstile, X.ip))) { X.log("turnstile_fail", { where: "seller" }); fail("Security check failed. Please try again."); }
  const legacy = (await getDocs(env, undefined, ["sellerProfiles/" + user.sub]))["sellerProfiles/" + user.sub];
  const owned = (await runQuery(env, "sellerProfiles", [["ownerId", "EQUAL", user.sub]], null, 50)).filter(x => x.id !== user.sub);
  const active = (legacy && legacy.data.status !== "ARCHIVED" ? 1 : 0) + owned.filter(x => x.data.status !== "ARCHIVED").length;
  if (active >= MAX_STORES) fail(`You can have up to ${MAX_STORES} active stores.`);
  const id = legacy ? rid() : user.sub, hasShop = b.hasShop === true, prefix = `https://res.cloudinary.com/${env.CLOUDINARY_CLOUD}/`, logo = optStr(b.logo, 400, "the logo");
  if (logo && !logo.startsWith(prefix)) fail("Logos must be uploaded through Mavora.");
  const pub = { uid: user.sub, ownerId: user.sub, status: "ACTIVE", businessName: str(b.businessName, 2, 80, "the store name"), description: optStr(b.description, 400, "the description"), location: str(b.location, 2, 80, "the city or area"), storeCategory: oneOf(b.storeCategory || "Mixed / General", [...PCATS, "Services", "Mixed / General"], "the store category"), logo, providerType: oneOf(b.providerType || "INDIVIDUAL", ["INDIVIDUAL", "BUSINESS"], "the provider type"), serviceArea: optStr(b.serviceArea, 120, "the service area"), hasShop, shopName: hasShop ? str(b.shopName, 2, 80, "the shop name") : "", shopVerificationStatus: "NOT_VERIFIED", identityStatus: "NOT_STARTED" };
  const phone = str(b.phone, 10, 20, "the phone number"); if (!/^[0-9+ ]{10,20}$/.test(phone)) fail("Please check the phone number.");
  const priv = { uid: user.sub, ownerId: user.sub, phone, address: str(b.address, 3, 200, "the address"), landmark: optStr(b.landmark, 100, "the landmark"), pickupType: oneOf(b.pickupType, ["SHOP", "HOME", "SCHOOL", "OFFICE", "OTHER"], "the pickup type"), pickupContactName: str(b.pickupContactName, 2, 80, "the pickup contact"), pickupInstructions: optStr(b.pickupInstructions, 300, "the pickup instructions") };
  await fs(env, ":commit", { writes: [
    { update: { name: `${base(env)}/sellerProfiles/${id}`, fields: toF(pub) }, currentDocument: { exists: false }, updateTransforms: [{ fieldPath: "createdAt", setToServerValue: "REQUEST_TIME" }] },
    { update: { name: `${base(env)}/sellerPrivate/${id}`, fields: toF(priv) }, currentDocument: { exists: false }, updateTransforms: [{ fieldPath: "createdAt", setToServerValue: "REQUEST_TIME" }] }] });
  return { ok: true, id };
}
async function createListing(req, env, X, user) {
  needVerified(user);
  const b = await body(req, ["kind", "name", "category", "description", "location", "images", "image", "negotiable", "price", "discountPrice", "stock", "condition", "delivery", "colors", "priceType", "availability", "storeId", "turnstile"]);
  await needTerms(env, user);
  await limit(env, "ls:u:" + user.sub, 20, 3600);
  if (!(await turnstile(env, b.turnstile, X.ip))) { X.log("turnstile_fail", { where: "listing" }); fail("Security check failed. Please try again."); }
  const kind = oneOf(b.kind, ["products", "services"], "the listing type"), pr = kind === "products";
  const sid = b.storeId === undefined ? user.sub : b.storeId; if (!idOk(sid)) fail("Invalid store.");
  const sp = (await getDocs(env, undefined, ["sellerProfiles/" + sid]))["sellerProfiles/" + sid]; if (!sp) fail("Create your store first.", 403);
  if ((sp.data.ownerId || sid) !== user.sub) fail("That store is not yours.", 403);
  if (sp.data.status === "ARCHIVED") fail("This store has been closed.", 403);
  if (sp.data.suspended) fail("Your seller account is suspended. Please contact support.", 403);
  if (!Array.isArray(b.images) || b.images.length > 10) fail("Please check the photos.");
  const prefix = `https://res.cloudinary.com/${env.CLOUDINARY_CLOUD}/`;
  const images = b.images.map(u => { if (typeof u !== "string" || u.length > 400 || !u.startsWith(prefix)) fail("Photos must be uploaded through Mavora."); return u; });
  const num = (v, min, max, name) => { v = Number(v); if (!Number.isFinite(v) || v < min || v > max) fail(`Please check ${name}.`); return Math.round(v); };
  const d = { sellerId: sid, ownerId: user.sub, sellerName: sp.data.businessName, status: "ACTIVE", name: str(b.name, 2, 100, "the name"), category: oneOf(b.category, pr ? PCATS : SCATS, "the category"), description: str(b.description, 5, 2000, "the description"), location: str(b.location, 2, 80, "the location"), images, image: images[0] || "", negotiable: b.negotiable === true };
  if (pr) {
    d.price = num(b.price, 1, 1e9, "the price"); d.discountPrice = b.discountPrice ? num(b.discountPrice, 0, 1e9, "the discount price") : 0;
    if (d.discountPrice >= d.price && d.discountPrice > 0) fail("The discount price must be lower than the price.");
    d.stock = num(b.stock, 0, 1e5, "the stock"); d.condition = oneOf(b.condition, ["New", "Used", "Refurbished"], "the condition"); d.delivery = oneOf(b.delivery || "PICKUP", ["PICKUP", "DELIVERY", "BOTH"], "the delivery option");
    if (!Array.isArray(b.colors) || b.colors.length > 8) fail("Please check the colours."); d.colors = [...new Set(b.colors.map(c => str(c, 1, 20, "a colour")))];
  } else {
    d.priceType = oneOf(b.priceType, ["FIXED", "FROM", "CONTACT"], "the price type"); d.price = d.priceType === "CONTACT" ? 0 : num(b.price, 1, 1e9, "the price");
    d.availability = oneOf(b.availability, ["Available today", "Available this week", "By appointment", "Emergency service"], "the availability");
  }
  const id = rid();
  await fs(env, ":commit", { writes: [{ update: { name: `${base(env)}/${kind}/${id}`, fields: toF(d) }, currentDocument: { exists: false }, ...REQ }] });
  return { id };
}

/* ================= NOTIFICATIONS + SERVICE REQUESTS ================= */
const naira = n => "₦" + Number(n).toLocaleString("en-NG");
const notif = (env, userId, type, title, text, link) => ({ update: { name: `${base(env)}/notifications/${rid()}`, fields: toF({ userId, type, title: title.slice(0, 100), body: text.slice(0, 200), link, read: false }) }, currentDocument: { exists: false }, updateTransforms: [{ fieldPath: "createdAt", setToServerValue: "REQUEST_TIME" }] });
const today = () => new Date().toISOString().slice(0, 10);
const okDate = v => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) && v >= today() && !isNaN(Date.parse(v));
const okTime = v => typeof v === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(v);

async function createRequest(req, env, X, user) {
  needVerified(user);
  await needTerms(env, user);
  const b = await body(req, ["serviceId", "description", "location", "preferredDate", "preferredTime", "notes", "turnstile"]);
  await limit(env, "rq:u:" + user.sub, 10, 3600);
  if (!(await turnstile(env, b.turnstile, X.ip))) { X.log("turnstile_fail", { where: "request" }); fail("Security check failed. Please try again."); }
  if (typeof b.serviceId !== "string" || !/^[A-Za-z0-9]{10,40}$/.test(b.serviceId)) fail("Invalid service.");
  const description = str(b.description, 10, 800, "the description"), location = str(b.location, 2, 120, "the location"), notes = optStr(b.notes, 300, "the notes");
  if (b.preferredDate && !okDate(b.preferredDate)) fail("Please check the preferred date.");
  if (b.preferredTime && !okTime(b.preferredTime)) fail("Please check the preferred time.");
  const ud = (await getDocs(env, undefined, ["users/" + user.sub]))["users/" + user.sub];
  const buyerName = String(ud?.data.fullName || user.name || (user.email || "Customer").split("@")[0]).slice(0, 80);
  let created;
  await txn(env, async t => {
    const docs = await getDocs(env, t, ["services/" + b.serviceId, "counters/requests"]);
    const sv = docs["services/" + b.serviceId]?.data;
    if (!sv || sv.status !== "ACTIVE") fail("That service is no longer available.");
    if ((sv.ownerId || sv.sellerId) === user.sub) fail("You can't request your own service.");
    const n = (docs["counters/requests"]?.data.count || 0) + 1, id = `SR-${new Date().getFullYear()}-${String(n).padStart(6, "0")}`;
    created = { id };
    return [
      { update: { name: `${base(env)}/serviceRequests/${id}`, fields: toF({ requestNumber: id, buyerId: user.sub, buyerName, sellerId: sv.sellerId, sellerOwnerId: sv.ownerId || sv.sellerId, sellerName: sv.sellerName, serviceId: b.serviceId, serviceName: sv.name, priceType: sv.priceType || "CONTACT", description, location, preferredDate: b.preferredDate || "", preferredTime: b.preferredTime || "", notes, status: "Requested", history: [{ status: "Requested", at: new Date(), by: "buyer" }] }) }, currentDocument: { exists: false }, ...REQ },
      { update: { name: `${base(env)}/counters/requests`, fields: toF({ count: n }) } },
      notif(env, sv.ownerId || sv.sellerId, "request", "New service request", `${buyerName}: ${sv.name}`, "#/request/" + id)];
  });
  return { id: created.id };
}

const RQ = {
  seller: { Requested: ["Provider Responded", "Inspection Required", "Quote Sent", "Cancelled"], "Provider Responded": ["Inspection Required", "Quote Sent", "Appointment Scheduled", "Cancelled"], "Inspection Required": ["Appointment Scheduled", "Quote Sent", "Cancelled"], "Quote Sent": ["Quote Sent", "Cancelled"], "Quote Accepted": ["Appointment Scheduled", "Cancelled"], "Appointment Scheduled": ["In Progress", "Appointment Scheduled", "Cancelled"], "In Progress": ["Completed"] },
  buyer: { Requested: ["Cancelled"], "Provider Responded": ["Cancelled"], "Inspection Required": ["Cancelled"], "Quote Sent": ["Quote Accepted", "Cancelled"], "Quote Accepted": ["Cancelled"], "Appointment Scheduled": ["Cancelled"] }
};
async function setRequestStatus(req, env, user, id) {
  const b = await body(req, ["status", "amount", "note", "date", "time", "reason"]), status = b.status;
  if (typeof status !== "string") fail("Invalid status.");
  await limit(env, "rs:u:" + user.sub, 60, 3600);
  const extra = {}; let text = "";
  if (status === "Quote Sent") { const a = Number(b.amount); if (!Number.isFinite(a) || a < 1 || a > 1e9) fail("Please enter a valid quote amount."); extra.quote = { amount: Math.round(a), note: optStr(b.note, 300, "the note"), at: new Date() }; text = "Quote: " + naira(Math.round(a)) + "."; }
  else if (status === "Appointment Scheduled") { if (!okDate(b.date) || !okTime(b.time)) fail("Please choose a valid date and time."); extra.appointment = { date: b.date, time: b.time, note: optStr(b.note, 200, "the note") }; text = `Appointment: ${b.date} at ${b.time}.`; }
  else if (status === "Inspection Required") { extra.inspectionNote = optStr(b.note, 300, "the note"); text = "An inspection is needed before the price is set."; }
  else if (status === "Cancelled") { extra.cancelReason = optStr(b.reason, 200, "the reason"); }
  await txn(env, async t => {
    const rd = (await getDocs(env, t, ["serviceRequests/" + id]))["serviceRequests/" + id]; if (!rd) fail("Request not found.", 404);
    const r = rd.data, role = (r.sellerOwnerId || r.sellerId) === user.sub ? "seller" : r.buyerId === user.sub ? "buyer" : null;
    if (!role) fail("Not allowed.", 403);
    if (!(RQ[role][r.status] || []).includes(status)) fail("That change is not allowed right now.");
    const fields = { status, history: [...(r.history || []).map(h => ({ status: h.status, at: new Date(h.at), by: h.by || "" })), { status, at: new Date(), by: role }], ...extra };
    const W = [
      { update: { name: rd.name, fields: toF(fields) }, updateMask: { fieldPaths: Object.keys(fields) }, updateTransforms: [{ fieldPath: "updatedAt", setToServerValue: "REQUEST_TIME" }], currentDocument: { updateTime: rd.updateTime } },
      notif(env, role === "seller" ? r.buyerId : (r.sellerOwnerId || r.sellerId), "request", `Request ${r.requestNumber}: ${status}`, ((role === "seller" ? "The provider updated your request. " : "The customer updated this request. ") + text).trim(), "#/request/" + id)];
    if (status === "Completed") W.push(inc(env, "sellerProfiles/" + r.sellerId, "completedJobs"));
    return W;
  });
  return { ok: true };
}

/* ================= TRUST & SAFETY: reviews, reports, feedback, admin ================= */
const inc = (env, path, f) => ({ transform: { document: `${base(env)}/${path}`, fieldTransforms: [{ fieldPath: f, increment: { integerValue: "1" } }] } });
const isAdmin = (u, env) => u.email_verified === true && (env.ADMIN_EMAILS || "").toLowerCase().split(",").map(x => x.trim()).filter(Boolean).includes(String(u.email || "").toLowerCase());
const flt = ([field, op, val]) => ({ fieldFilter: { field: { fieldPath: field }, op, value: toV(val) } });
const wh = f => f.length === 1 ? f[0] : { compositeFilter: { op: "AND", filters: f } };
async function runQuery(env, coll, filters = [], order = "createdAt", n = 50) {
  const sq = { from: [{ collectionId: coll }], limit: n };
  if (filters.length) sq.where = wh(filters.map(flt));
  if (order) sq.orderBy = [{ field: { fieldPath: order }, direction: "DESCENDING" }];
  return (await fs(env, ":runQuery", { structuredQuery: sq })).filter(x => x.document).map(x => ({ id: x.document.name.split("/").pop(), name: x.document.name, updateTime: x.document.updateTime, data: fromD(x.document) }));
}
async function countDocs(env, coll, filters = []) {
  const sq = { from: [{ collectionId: coll }] }; if (filters.length) sq.where = wh(filters.map(flt));
  const r = await fs(env, ":runAggregationQuery", { structuredAggregationQuery: { structuredQuery: sq, aggregations: [{ alias: "n", count: {} }] } });
  return Number(r[0]?.result?.aggregateFields?.n?.integerValue || 0);
}
const upd = (env, path, fields, mask) => ({ update: { name: `${base(env)}/${path}`, fields: toF(fields) }, updateMask: { fieldPaths: mask || Object.keys(fields) }, currentDocument: { exists: true }, updateTransforms: [{ fieldPath: "updatedAt", setToServerValue: "REQUEST_TIME" }] });
const audit = (env, admin, action, target, detail) => ({ update: { name: `${base(env)}/auditLogs/${rid()}`, fields: toF({ adminId: admin.sub, action, targetId: String(target).slice(0, 80), detail: String(detail || "").slice(0, 300) }) }, currentDocument: { exists: false }, updateTransforms: [{ fieldPath: "createdAt", setToServerValue: "REQUEST_TIME" }] });
const idOk = v => typeof v === "string" && /^[A-Za-z0-9_-]{6,80}$/.test(v);

async function createReview(req, env, X, user) {
  needVerified(user);
  await needTerms(env, user);
  const b = await body(req, ["kind", "refId", "rating", "comment", "turnstile"]);
  await limit(env, "rv:u:" + user.sub, 10, 3600);
  if (!(await turnstile(env, b.turnstile, X.ip))) { X.log("turnstile_fail", { where: "review" }); fail("Security check failed. Please try again."); }
  const kind = oneOf(b.kind, ["order", "request"], "the review type");
  if (typeof b.refId !== "string" || !/^[A-Za-z0-9-]{6,40}$/.test(b.refId)) fail("Invalid reference.");
  const rating = Number(b.rating); if (!Number.isInteger(rating) || rating < 1 || rating > 5) fail("Please choose 1 to 5 stars.");
  const comment = optStr(b.comment, 500, "the review"), path = (kind === "order" ? "orders/" : "serviceRequests/") + b.refId, rpath = `reviews/${kind}_${b.refId}`;
  await txn(env, async t => {
    const docs = await getDocs(env, t, [path, rpath]), d = docs[path]?.data;
    if (!d || d.buyerId !== user.sub) fail("You can only review your own completed orders and jobs.", 403);
    if (d.status !== "Completed") fail("You can leave a review once it is completed.");
    if (docs[rpath]) fail("You have already reviewed this.");
    const sp = (await getDocs(env, t, ["sellerProfiles/" + d.sellerId]))["sellerProfiles/" + d.sellerId]; if (!sp) fail("Seller not found.", 404);
    const sum = (sp.data.ratingSum || 0) + rating, cnt = (sp.data.ratingCount || 0) + 1, nm = String(d.buyerName || "Customer").trim().split(/\s+/);
    return [
      { update: { name: `${base(env)}/${rpath}`, fields: toF({ reviewerId: user.sub, reviewerName: nm[0] + (nm[1] ? " " + nm[1][0] + "." : ""), sellerId: d.sellerId, kind, refId: b.refId, itemName: kind === "order" ? (d.items?.[0]?.name || "Order") + (d.items?.length > 1 ? ` +${d.items.length - 1} more` : "") : d.serviceName, rating, comment, status: "VISIBLE" }) }, currentDocument: { exists: false }, updateTransforms: [{ fieldPath: "createdAt", setToServerValue: "REQUEST_TIME" }] },
      { update: { name: sp.name, fields: toF({ ratingSum: sum, ratingCount: cnt, rating: Math.round(sum / cnt * 10) / 10 }) }, updateMask: { fieldPaths: ["ratingSum", "ratingCount", "rating"] }, currentDocument: { updateTime: sp.updateTime } },
      notif(env, d.sellerOwnerId || d.sellerId, "review", "New review", `${"★".repeat(rating)} ${comment.slice(0, 80)}`.trim(), kind === "order" ? "#/order/" + b.refId : "#/request/" + b.refId)];
  });
  return { ok: true };
}

const REASONS = ["Fake listing", "Scam", "Inappropriate content", "Suspicious seller", "Incorrect information", "Other"];
async function createReport(req, env, X, user) {
  needVerified(user);
  await needTerms(env, user);
  const b = await body(req, ["targetType", "targetId", "reason", "details", "turnstile"]);
  await limit(env, "rp:u:" + user.sub, 5, 3600);
  if (!(await turnstile(env, b.turnstile, X.ip))) { X.log("turnstile_fail", { where: "report" }); fail("Security check failed. Please try again."); }
  const type = oneOf(b.targetType, ["product", "service", "seller"], "what you are reporting"), reason = oneOf(b.reason, REASONS, "the reason"), details = optStr(b.details, 500, "the details");
  if (!idOk(b.targetId)) fail("Invalid report.");
  const path = (type === "product" ? "products/" : type === "service" ? "services/" : "sellerProfiles/") + b.targetId, t = (await getDocs(env, undefined, [path]))[path];
  if (!t) fail("We couldn't find what you are reporting.", 404);
  const reportedUserId = type === "seller" ? (t.data.ownerId || b.targetId) : (t.data.ownerId || t.data.sellerId);
  if (reportedUserId === user.sub) fail("You can't report your own listing or profile.");
  try {
    await fs(env, ":commit", { writes: [{ update: { name: `${base(env)}/reports/${user.sub}_${type}_${b.targetId}`, fields: toF({ reporterId: user.sub, reportedUserId, targetType: type, targetId: b.targetId, targetName: String(t.data.name || t.data.businessName || "").slice(0, 100), reason, details, status: "Open", adminNote: "" }) }, currentDocument: { exists: false }, updateTransforms: [{ fieldPath: "createdAt", setToServerValue: "REQUEST_TIME" }] }] });
  } catch (e) { if (e.status === 409 || e.status === 400) fail("You have already reported this. Our team will review it."); throw e; }
  X.log("report_created", { type });
  return { ok: true };
}

const FB = ["General Feedback", "Bug Report", "Feature Request", "Design and Usability", "Buying Experience", "Selling Experience", "Services", "Other"];
async function createFeedback(req, env, X, user) {
  const b = await body(req, ["rating", "title", "feedback", "category", "allowPublic", "contactOk", "turnstile"]);
  await limit(env, "fb:u:" + user.sub, 3, 86400);
  if (!(await turnstile(env, b.turnstile, X.ip))) { X.log("turnstile_fail", { where: "feedback" }); fail("Security check failed. Please try again."); }
  const rating = Number(b.rating); if (!Number.isInteger(rating) || rating < 1 || rating > 5) fail("Please choose 1 to 5 stars.");
  await fs(env, ":commit", { writes: [{ update: { name: `${base(env)}/appReviews/${rid()}`, fields: toF({ userId: user.sub, rating, title: optStr(b.title, 100, "the title"), feedback: str(b.feedback, 5, 1000, "your feedback"), category: oneOf(b.category, FB, "the category"), allowPublic: b.allowPublic === true, contactOk: b.contactOk === true, status: "New", adminNote: "" }) }, currentDocument: { exists: false }, updateTransforms: [{ fieldPath: "createdAt", setToServerValue: "REQUEST_TIME" }] }] });
  return { ok: true };
}

async function adminApi(req, env, X, user, u) {
  if (!isAdmin(user, env)) { X.log("admin_denied"); fail("Not allowed.", 403); }
  await limit(env, "ad:u:" + user.sub, 300, 3600);
  const P = u.pathname;
  if (req.method === "GET" && P === "/api/admin/overview") {
    const [users, sellers, products, services, orders, requests, openReports, reviews, feedback] = await Promise.all([countDocs(env, "users"), countDocs(env, "sellerProfiles"), countDocs(env, "products"), countDocs(env, "services"), countDocs(env, "orders"), countDocs(env, "serviceRequests"), countDocs(env, "reports", [["status", "EQUAL", "Open"]]), countDocs(env, "reviews"), countDocs(env, "appReviews")]);
    return { users, sellers, products, services, orders, requests, openReports, reviews, feedback };
  }
  if (req.method === "GET" && P === "/api/admin/list") {
    const c = u.searchParams.get("c"), M = { reports: "reports", sellers: "sellerProfiles", reviews: "reviews", feedback: "appReviews", logs: "securityLogs", audit: "auditLogs" };
    if (c === "listings") { const [a, b] = await Promise.all([runQuery(env, "products", [], "createdAt", 30), runQuery(env, "services", [], "createdAt", 30)]); return { rows: [...a.map(x => ({ id: x.id, kind: "products", ...x.data })), ...b.map(x => ({ id: x.id, kind: "services", ...x.data }))] }; }
    if (!M[c]) fail("Unknown list.");
    return { rows: (await runQuery(env, M[c], [], "createdAt", 50)).map(x => ({ id: x.id, ...x.data })) };
  }
  if (req.method === "POST" && P === "/api/admin/action") {
    const b = await body(req, ["action", "id", "status", "note", "sellerId", "suspend", "reason", "kind", "field", "value"]), A = b.action, W = [];
    if (A === "report_status") { if (!idOk(b.id)) fail("Invalid id."); const st = oneOf(b.status, ["Open", "Investigating", "Resolved", "Dismissed"], "the status"); W.push(upd(env, "reports/" + b.id, { status: st, adminNote: optStr(b.note, 300, "the note") }), audit(env, user, A, b.id, st)); }
    else if (A === "feedback_status") { if (!idOk(b.id)) fail("Invalid id."); const st = oneOf(b.status, ["New", "Reviewed", "Resolved"], "the status"); W.push(upd(env, "appReviews/" + b.id, { status: st, adminNote: optStr(b.note, 300, "the note") }), audit(env, user, A, b.id, st)); }
    else if (A === "listing_status") {
      const kind = oneOf(b.kind, ["products", "services"], "the type"), st = oneOf(b.status, ["REMOVED", "ACTIVE"], "the status"), reason = optStr(b.reason, 200, "the reason");
      if (!idOk(b.id)) fail("Invalid id."); const d = (await getDocs(env, undefined, [kind + "/" + b.id]))[kind + "/" + b.id]; if (!d) fail("Listing not found.", 404);
      W.push(upd(env, kind + "/" + b.id, { status: st }), notif(env, d.data.ownerId || d.data.sellerId, "moderation", st === "REMOVED" ? "A listing was removed" : "A listing was restored", `${String(d.data.name).slice(0, 60)}${reason ? ": " + reason : ""}`, "#/dashboard"), audit(env, user, A, kind + "/" + b.id, st + " " + reason));
    }
    else if (A === "verify") {
      if (!idOk(b.sellerId)) fail("Invalid seller."); const f = oneOf(b.field, ["identityStatus", "shopVerificationStatus"], "the field"), v = oneOf(b.value, f === "identityStatus" ? ["VERIFIED", "NOT_STARTED"] : ["VERIFIED", "NOT_VERIFIED"], "the value");
      W.push(upd(env, "sellerProfiles/" + b.sellerId, { [f]: v }), notif(env, await ownerOfStore(env, b.sellerId), "moderation", v === "VERIFIED" ? "You have been verified" : "Verification removed", f === "identityStatus" ? "Your seller identity status was updated." : "Your shop location status was updated.", "#/verification"), audit(env, user, A, b.sellerId, f + "=" + v));
    }
    else if (A === "seller_suspend") {
      if (!idOk(b.sellerId)) fail("Invalid seller."); const sus = b.suspend === true, reason = optStr(b.reason, 200, "the reason");
      W.push(upd(env, "sellerProfiles/" + b.sellerId, { suspended: sus, suspendReason: sus ? reason : "" }));
      for (const coll of ["products", "services"]) for (const l of await runQuery(env, coll, [["sellerId", "EQUAL", b.sellerId]], null, 200)) {
        if (sus && ["ACTIVE", "PAUSED"].includes(l.data.status)) W.push(upd(env, `${coll}/${l.id}`, { status: "SUSPENDED" }));
        if (!sus && l.data.status === "SUSPENDED") W.push(upd(env, `${coll}/${l.id}`, { status: "ACTIVE" }));
      }
      W.push(notif(env, await ownerOfStore(env, b.sellerId), "moderation", sus ? "Your seller account was suspended" : "Your seller account was restored", sus ? (reason || "Please contact support.") : "Your listings are live again.", "#/account"), audit(env, user, A, b.sellerId, (sus ? "suspend " : "restore ") + reason));
    }
    else if (A === "review_remove") {
      if (!idOk(b.id)) fail("Invalid id.");
      await txn(env, async t => {
        const rv = (await getDocs(env, t, ["reviews/" + b.id]))["reviews/" + b.id]; if (!rv) fail("Review not found.", 404);
        if (rv.data.status !== "VISIBLE") fail("That review is already removed.");
        const sp = (await getDocs(env, t, ["sellerProfiles/" + rv.data.sellerId]))["sellerProfiles/" + rv.data.sellerId], w = [upd(env, "reviews/" + b.id, { status: "REMOVED" }), audit(env, user, A, b.id, "removed review")];
        if (sp) { const sum = Math.max(0, (sp.data.ratingSum || 0) - rv.data.rating), cnt = Math.max(0, (sp.data.ratingCount || 0) - 1); w.push({ update: { name: sp.name, fields: toF({ ratingSum: sum, ratingCount: cnt, rating: cnt ? Math.round(sum / cnt * 10) / 10 : 0 }) }, updateMask: { fieldPaths: ["ratingSum", "ratingCount", "rating"] }, currentDocument: { updateTime: sp.updateTime } }); }
        return w;
      });
      return { ok: true };
    }
    else fail("Unknown action.");
    await fs(env, ":commit", { writes: W });
    return { ok: true };
  }
  fail("Not found.", 404);
}

/* ================= STORES, ACCOUNT DELETION, TERMS, ADMIN CLAIM ================= */
const ownerOfStore = async (env, sid) => { const p = (await getDocs(env, undefined, ["sellerProfiles/" + sid]))["sellerProfiles/" + sid]; return p?.data.ownerId || sid; };
const DONE = ["Completed", "Cancelled"];
const openCount = async (env, coll, field, id) => (await runQuery(env, coll, [[field, "EQUAL", id]], null, 300)).filter(x => !DONE.includes(x.data.status)).length;
async function storeBlockers(env, sid) {
  const [no, nr] = await Promise.all([openCount(env, "orders", "sellerId", sid), openCount(env, "serviceRequests", "sellerId", sid)]), p = [];
  if (no) p.push(`${no} unfinished order${no > 1 ? "s" : ""}`); if (nr) p.push(`${nr} unfinished service request${nr > 1 ? "s" : ""}`);
  return p.join(" and ");
}
async function archiveWrites(env, sid, data) { // a deleted store is archived: records stay, public data and bank details go
  const W = [upd(env, "sellerProfiles/" + sid, { status: "ARCHIVED", shopSlug: "", archivedAt: new Date() }), { update: { name: `${base(env)}/sellerPrivate/${sid}`, fields: toF({ archived: true }) }, updateMask: { fieldPaths: ["bank", "archived"] } }];
  if (data.shopSlug) W.push({ delete: `${base(env)}/shopSlugs/${data.shopSlug}` });
  for (const coll of ["products", "services"]) for (const l of await runQuery(env, coll, [["sellerId", "EQUAL", sid]], null, 200)) if (["ACTIVE", "PAUSED", "SUSPENDED"].includes(l.data.status)) W.push(upd(env, `${coll}/${l.id}`, { status: "ARCHIVED" }));
  return W;
}
async function deleteStore(req, env, X, user) {
  const b = await body(req, ["storeId", "confirm"]);
  await needTerms(env, user); await limit(env, "sd:u:" + user.sub, 10, 3600);
  if (!idOk(b.storeId) || b.confirm !== true) fail("Please confirm the deletion.");
  const sp = (await getDocs(env, undefined, ["sellerProfiles/" + b.storeId]))["sellerProfiles/" + b.storeId];
  if (!sp || (sp.data.ownerId || b.storeId) !== user.sub) fail("Store not found.", 404);
  if (sp.data.status === "ARCHIVED") fail("This store is already closed.");
  const blockers = await storeBlockers(env, b.storeId);
  if (blockers) fail(`This store still has ${blockers}. Finish or cancel them first, then try again.`, 409);
  await fs(env, ":commit", { writes: [...(await archiveWrites(env, b.storeId, sp.data)), audit(env, user, "store_deleted", b.storeId, "")] });
  return { ok: true };
}
const subDocs = async (env, parent, coll) => (await fs(env, `/${parent}:runQuery`, { structuredQuery: { from: [{ collectionId: coll }], limit: 200 } })).filter(x => x.document).map(x => x.document.name);
async function deleteAccount(req, env, X, user) {
  const b = await body(req, ["confirm"]); if (b.confirm !== "DELETE") fail("Please confirm the deletion.");
  await limit(env, "da:u:" + user.sub, 3, 3600);
  if (Date.now() / 1e3 - (user.auth_time || 0) > 300) throw Object.assign(new Error("Please confirm your sign-in again."), { http: 401, user: true, reauth: true });
  const uid = user.sub, [bo, br] = await Promise.all([openCount(env, "orders", "buyerId", uid), openCount(env, "serviceRequests", "buyerId", uid)]), stores = [];
  const legacy = (await getDocs(env, undefined, ["sellerProfiles/" + uid]))["sellerProfiles/" + uid]; if (legacy) stores.push({ id: uid, data: legacy.data });
  (await runQuery(env, "sellerProfiles", [["ownerId", "EQUAL", uid]], null, 50)).forEach(x => { if (x.id !== uid) stores.push({ id: x.id, data: x.data }); });
  const blockers = []; if (bo) blockers.push(`${bo} unfinished order${bo > 1 ? "s" : ""}`); if (br) blockers.push(`${br} unfinished service request${br > 1 ? "s" : ""}`);
  for (const s of stores) if (s.data.status !== "ARCHIVED") { const m = await storeBlockers(env, s.id); if (m) blockers.push(`${s.data.businessName}: ${m}`); }
  if (blockers.length) { X.log("account_delete_blocked"); fail(`We can't delete your account yet: ${blockers.join("; ")}. Please finish or cancel them first.`, 409); }
  const W = [];
  for (const s of stores) if (s.data.status !== "ARCHIVED") W.push(...await archiveWrites(env, s.id, s.data));
  W.push({ update: { name: `${base(env)}/users/${uid}`, fields: toF({ fullName: "Deleted user", email: "", phone: "", photoURL: "", city: "", accountStatus: "DELETED", theme: "system", deletedAt: new Date() }) }, updateMask: { fieldPaths: ["fullName", "email", "phone", "photoURL", "city", "accountStatus", "theme", "deletedAt"] } });
  for (const [parent, coll] of [[`users/${uid}`, "addresses"], [`users/${uid}`, "wishlist"], [`users/${uid}`, "private"], [`supportThreads/${uid}`, "messages"]]) for (const n of await subDocs(env, parent, coll)) W.push({ delete: n });
  W.push({ delete: `${base(env)}/supportThreads/${uid}` });
  for (const x of await runQuery(env, "notifications", [["userId", "EQUAL", uid]], null, 300)) W.push({ delete: x.name });
  for (const x of await runQuery(env, "reviews", [["reviewerId", "EQUAL", uid]], null, 100)) W.push(upd(env, "reviews/" + x.id, { reviewerName: "Deleted user" }));
  for (const c of await runQuery(env, "conversations", [["participants", "ARRAY_CONTAINS", uid]], null, 100)) W.push({ update: { name: c.name, fields: toF({ names: { [uid]: "Deleted user" } }) }, updateMask: { fieldPaths: ["names.`" + uid + "`"] } });
  W.push(audit(env, user, "account_deleted", uid, ""));
  for (let i = 0; i < W.length; i += 400) await fs(env, ":commit", { writes: W.slice(i, i + 400) });
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/accounts:delete`, { method: "POST", headers: { Authorization: "Bearer " + await accessToken(env), "Content-Type": "application/json" }, body: JSON.stringify({ localId: uid }) });
  if (!r.ok) throw new Error("auth delete failed");
  X.log("account_deleted");
  return { ok: true };
}
async function acceptTerms(req, env, X, user) {
  const b = await body(req, ["version"]); await limit(env, "tc:u:" + user.sub, 20, 3600);
  if (b.version !== TERMS) fail("That version is out of date. Please reload the page.");
  await fs(env, ":commit", { writes: [{ update: { name: `${base(env)}/users/${user.sub}`, fields: toF({ termsAccepted: true, termsVersion: TERMS, privacyPolicyVersion: TERMS }) }, updateMask: { fieldPaths: ["termsAccepted", "termsVersion", "privacyPolicyVersion"] }, updateTransforms: ["termsAcceptedAt", "privacyPolicyAcceptedAt", "updatedAt"].map(f => ({ fieldPath: f, setToServerValue: "REQUEST_TIME" })) }] });
  return { ok: true };
}
async function setClaim(env, uid, claims) {
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/accounts:update`, { method: "POST", headers: { Authorization: "Bearer " + await accessToken(env), "Content-Type": "application/json" }, body: JSON.stringify({ localId: uid, customAttributes: JSON.stringify(claims) }) });
  return r.ok;
}

export default {
  async fetch(req, env, ctx) {
    const origin = req.headers.get("Origin") || "", allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
    const cors = { "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : "", "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,Authorization", "Access-Control-Max-Age": "86400", Vary: "Origin" };
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    const ip = req.headers.get("CF-Connecting-IP") || "0", ipH = (await hex(ip)).slice(0, 12);
    const X = { ip, origin: allowed[0] || origin, log: (type, info = {}) => { const rec = { type, ip: ipH, ...info, at: new Date().toISOString() }; console.log(JSON.stringify({ security: rec })); if (env.SERVICE_ACCOUNT) ctx.waitUntil(fs(env, ":commit", { writes: [{ update: { name: `${base(env)}/securityLogs/${crypto.randomUUID()}`, fields: toF(rec) }, updateTransforms: [{ fieldPath: "createdAt", setToServerValue: "REQUEST_TIME" }] }] }).catch(() => { })); } };
    const out = (o, s = 200, extra = {}) => json(o, s, { ...cors, ...extra });
    try {
      const u = new URL(req.url), P = u.pathname;
      if (P === "/api/health") return out({ ok: true, kv: !!env.RL, turnstile: !!env.TURNSTILE_SECRET });
      if (origin && !allowed.includes(origin)) { X.log("bad_origin"); return out({ error: "Origin not allowed" }, 403); }
      if (Number(req.headers.get("Content-Length") || 0) > 20000) return out({ error: "Request too large" }, 413);
      await limit(env, "g:" + ip, 120, 60); // overall per-IP ceiling
      if (req.method === "POST" && ["/api/auth/register", "/api/auth/login", "/api/auth/forgot"].includes(P)) {
        const r = await ({ "/api/auth/register": register, "/api/auth/login": login, "/api/auth/forgot": forgot }[P])(req, env, X);
        if (r.__status) { const { __status, ...rest } = r; return out(rest, __status); }
        return out(r);
      }
      const tok = (req.headers.get("Authorization") || "").replace(/^Bearer /, "");
      if (!tok) return out({ error: "Please sign in" }, 401);
      let user; try { user = await verifyToken(tok, env); } catch (e) { X.log("bad_token"); return out({ error: "Please sign in again" }, 401); }
      if (req.method === "POST" && P === "/api/auth/resend") return out(await resend(req, env, X, user, tok));
      if (req.method === "POST" && (P === "/api/seller/register" || P === "/api/stores")) return out(await sellerRegister(req, env, X, user));
      if (req.method === "POST" && P === "/api/stores/delete") return out(await deleteStore(req, env, X, user));
      if (req.method === "POST" && P === "/api/account/delete") return out(await deleteAccount(req, env, X, user));
      if (req.method === "POST" && P === "/api/terms/accept") return out(await acceptTerms(req, env, X, user));
      if (req.method === "POST" && P === "/api/listings") return out(await createListing(req, env, X, user));
      if (req.method === "POST" && P === "/api/orders") { needVerified(user); await needTerms(env, user); await limit(env, "or:u:" + user.sub, 10, 3600); return out(await createOrders(req, env, user)); }
      if (req.method === "POST" && P === "/api/requests") return out(await createRequest(req, env, X, user));
      const rm = P.match(/^\/api\/requests\/([A-Za-z0-9-]{6,40})\/status$/);
      if (rm && req.method === "PATCH") return out(await setRequestStatus(req, env, user, rm[1]));
      if (req.method === "GET" && P === "/api/me") { const adm = isAdmin(user, env); if (adm && !user.admin) return out({ admin: true, refresh: await setClaim(env, user.sub, { admin: true }) }); if (!adm && user.admin) return out({ admin: false, refresh: await setClaim(env, user.sub, {}) }); return out({ admin: adm }); }
      if (P.startsWith("/api/admin/")) return out(await adminApi(req, env, X, user, u));
      if (req.method === "POST" && P === "/api/reviews") return out(await createReview(req, env, X, user));
      if (req.method === "POST" && P === "/api/reports") return out(await createReport(req, env, X, user));
      if (req.method === "POST" && P === "/api/feedback") return out(await createFeedback(req, env, X, user));
      const m = P.match(/^\/api\/orders\/([A-Za-z0-9-]{6,40})\/status$/);
      if (m && req.method === "PATCH") { await limit(env, "os:u:" + user.sub, 60, 3600); return out(await setStatus(req, env, user, m[1])); }
      X.log("not_found", { path: P.slice(0, 40) });
      return out({ error: "Not found" }, 404);
    } catch (e) {
      console.error(e.message);
      if (e.http === 429) { X.log("rate_limited"); return out({ error: e.message }, 429, { "Retry-After": String(e.retry || 60) }); }
      if (e.http === 403 || e.http === 401) X.log("forbidden", { code: e.http });
      return out({ error: e.user ? e.message : "Something went wrong. Please try again.", ...(e.reauth ? { reauth: true } : {}) }, e.http || 500);
    }
  }
};
