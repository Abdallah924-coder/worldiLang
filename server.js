require("dotenv").config();
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");
const { promisify } = require("util");
const { MongoClient, ObjectId } = require("mongodb");

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || "worldifyai";
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const MAIL_FROM = process.env.MAIL_FROM;
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || "WorldifyAI";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const APP_URL = (process.env.APP_URL || `http://127.0.0.1:${PORT}`).replace(/\/$/, "");
const COOKIE_SECURE = APP_URL.startsWith("https://") || process.env.NODE_ENV === "production";
const rateBuckets = new Map();
const MAX_RATE_BUCKETS = 10_000;
function clientAddress(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) return forwarded.split(",")[0].trim().slice(0, 100);
  const realIp = req.headers["x-real-ip"];
  return typeof realIp === "string" && realIp.trim() ? realIp.trim().slice(0, 100) : (req.socket.remoteAddress || "unknown");
}
function cleanRateBuckets() {
  const now = Date.now();
  for (const [id, bucket] of rateBuckets) if (bucket.resetAt <= now) rateBuckets.delete(id);
}
const rateCleanupTimer = setInterval(cleanRateBuckets, 60_000);
rateCleanupTimer.unref();
const INDEX_FILE = path.join(__dirname, "index.html");
const scrypt = promisify(crypto.scrypt);
let db;

function fail(message, status = 500) { const error = new Error(message); error.status = status; throw error; }
function rateLimit(req, key, limit, windowMs) {
  const now = Date.now();
  const id = `${clientAddress(req)}:${key}`;
  const bucket = rateBuckets.get(id);
  if (!bucket || bucket.resetAt <= now) {
    if (rateBuckets.size >= MAX_RATE_BUCKETS) cleanRateBuckets();
    if (rateBuckets.size >= MAX_RATE_BUCKETS) rateBuckets.delete(rateBuckets.keys().next().value);
    rateBuckets.set(id, { count: 1, resetAt: now + windowMs });
    return;
  }
  if (bucket.count >= limit) fail("Trop de tentatives. Réessayez plus tard.", 429);
  bucket.count += 1;
}
function validateConfig() { const missing = [!MONGODB_URI && "MONGODB_URI", !BREVO_API_KEY && "BREVO_API_KEY", !MAIL_FROM && "MAIL_FROM", !ADMIN_EMAIL && "ADMIN_EMAIL", !ADMIN_PASSWORD && "ADMIN_PASSWORD"].filter(Boolean); if (missing.length) throw new Error(`Variables manquantes: ${missing.join(", ")}`); if (process.env.NODE_ENV === "production" && !APP_URL.startsWith("https://")) throw new Error("APP_URL doit utiliser HTTPS en production."); }
const SECURITY_HEADERS = { "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer" };
function json(res, status, payload, headers = {}) { const body = JSON.stringify(payload); res.writeHead(status, { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers }); res.end(body); }
function parseCookies(req) { return Object.fromEntries((req.headers.cookie || "").split(";").filter(Boolean).map((part) => { const i = part.indexOf("="); return [part.slice(0, i).trim(), decodeURIComponent(part.slice(i + 1).trim())]; })); }
async function requestBody(req) { let raw = ""; for await (const chunk of req) { raw += chunk; if (raw.length > 1_000_000) fail("Payload too large", 413); } try { return raw ? JSON.parse(raw) : {}; } catch { fail("Requête JSON invalide", 400); } }
function validEmail(email) { return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 160; }
async function passwordHash(password, salt = crypto.randomBytes(16).toString("hex")) { return { salt, hash: (await scrypt(password, salt, 64)).toString("hex") }; }
async function passwordMatches(password, user) { const result = await passwordHash(password, user.passwordSalt); return crypto.timingSafeEqual(Buffer.from(result.hash, "hex"), Buffer.from(user.passwordHash, "hex")); }
function defaultData() { return { histories: { en: [], it: [], fr: [] }, stats: { en: { answered: 0, correct: 0, daily: 0, day: "" }, it: { answered: 0, correct: 0, daily: 0, day: "" }, fr: { answered: 0, correct: 0, daily: 0, day: "" } } }; }
function sanitizeData(input) { const clean = defaultData(); for (const lang of Object.keys(clean.histories)) { if (Array.isArray(input?.histories?.[lang])) clean.histories[lang] = input.histories[lang].filter((e) => e && typeof e.id === "string" && typeof e.word === "string" && typeof e.translation === "string").slice(0, 50); const stats = input?.stats?.[lang]; if (stats && typeof stats === "object") clean.stats[lang] = { answered: Number(stats.answered) || 0, correct: Number(stats.correct) || 0, daily: Number(stats.daily) || 0, day: typeof stats.day === "string" ? stats.day.slice(0, 10) : "" }; } return clean; }
function publicUser(user) { return { id: user._id.toString(), email: user.email, name: user.name, role: user.role || "user", createdAt: user.createdAt }; }
function sessionToken(req) { return parseCookies(req).worldify_session; }
function tokenHash(token) { return crypto.createHash("sha256").update(token).digest("hex"); }
async function auth(req) { const token = sessionToken(req); if (!token) return null; const session = await db.collection("sessions").findOne({ tokenHash: tokenHash(token), expiresAt: { $gt: new Date() } }); if (!session) return null; const user = await db.collection("users").findOne({ _id: session.userId }); return user ? { token, user } : null; }
async function startSession(res, userId) { const token = crypto.randomBytes(32).toString("hex"); await db.collection("sessions").insertOne({ tokenHash: tokenHash(token), userId, createdAt: new Date(), expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }); res.setHeader("Set-Cookie", `worldify_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${COOKIE_SECURE ? "; Secure" : ""}`); }
async function endSession(res, req) { const token = sessionToken(req); if (token) await db.collection("sessions").deleteOne({ tokenHash: tokenHash(token) }); res.setHeader("Set-Cookie", `worldify_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${COOKIE_SECURE ? "; Secure" : ""}`); }
function mailConfigured() { return Boolean(BREVO_API_KEY && MAIL_FROM); }
function sendBrevoEmail(to, subject, html) { if (!mailConfigured()) fail("Brevo n’est pas configuré.", 503); return new Promise((resolve, reject) => { const payload = JSON.stringify({ sender: { email: MAIL_FROM, name: MAIL_FROM_NAME }, to: [{ email: to }], subject, htmlContent: html }); const req = https.request({ hostname: "api.brevo.com", path: "/v3/smtp/email", method: "POST", headers: { "api-key": BREVO_API_KEY, "content-type": "application/json", "content-length": Buffer.byteLength(payload) } }, (response) => { let data = ""; response.on("data", (chunk) => { data += chunk; }); response.on("end", () => response.statusCode >= 200 && response.statusCode < 300 ? resolve(true) : reject(new Error(`Brevo ${response.statusCode}: ${data}`))); }); req.on("error", reject); req.write(payload); req.end(); }); }
function safeHtml(value) { return String(value).replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char])); }
async function sendRequiredMail(to, subject, html) { try { await sendBrevoEmail(to, subject, html); } catch (error) { console.error("Envoi Brevo échoué:", error.message); throw error; } }
async function sendBestEffortMail(to, subject, html) { try { await sendBrevoEmail(to, subject, html); } catch (error) { console.error("Envoi Brevo échoué (accès conservé):", error.message); } }
async function seedAdmin() { if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !validEmail(ADMIN_EMAIL) || ADMIN_PASSWORD.length < 8) { console.warn("Compte admin non créé: définissez ADMIN_EMAIL et ADMIN_PASSWORD (8 caractères minimum)."); return; } const existing = await db.collection("users").findOne({ role: "admin" }); if (existing) { console.log(`Compte admin disponible pour ${existing.email}`); return; } const credentials = await passwordHash(ADMIN_PASSWORD); await db.collection("users").insertOne({ email: ADMIN_EMAIL, name: "Administrateur", role: "admin", passwordSalt: credentials.salt, passwordHash: credentials.hash, createdAt: new Date(), data: defaultData(), dataVersion: 0 }); console.log(`Compte admin créé pour ${ADMIN_EMAIL}`); }
async function adminUsers(req, res) { const current = await auth(req); if (!current || current.user.role !== "admin") return json(res, 403, { error: "Accès administrateur requis." }); const records = await db.collection("users").find({}, { projection: { passwordHash: 0, passwordSalt: 0, resetTokenHash: 0, resetExpiresAt: 0 } }).sort({ createdAt: -1 }).toArray(); return json(res, 200, { users: records.map((user) => ({ user: publicUser(user), data: sanitizeData(user.data) })) }); }
async function api(req, res, pathname) {
  if (pathname === "/api/auth/register" && req.method === "POST") { rateLimit(req, "register", 5, 15 * 60 * 1000); const input = await requestBody(req); const email = String(input.email || "").trim().toLowerCase(); const name = String(input.name || "").trim().slice(0, 60); const password = String(input.password || ""); if (!validEmail(email) || !name || password.length < 8) return json(res, 400, { error: "Nom, adresse e-mail et mot de passe de 8 caractères minimum requis." }); if (await db.collection("users").findOne({ email })) return json(res, 409, { error: "Un compte existe déjà avec cette adresse." }); const credentials = await passwordHash(password); const user = { email, name, role: "user", passwordSalt: credentials.salt, passwordHash: credentials.hash, createdAt: new Date(), data: defaultData(), dataVersion: 0 }; let result;
    try { result = await db.collection("users").insertOne(user); }
    catch (error) { if (error?.code === 11000) return json(res, 409, { error: "Un compte existe déjà avec cette adresse." }); throw error; }
    user._id = result.insertedId; await startSession(res, result.insertedId); await sendBestEffortMail(email, "Bienvenue sur WorldifyAI", `<p>Bonjour ${safeHtml(name)},</p><p>Bienvenue sur WorldifyAI. Votre compte est prêt.</p>`); if (ADMIN_EMAIL) await sendBestEffortMail(ADMIN_EMAIL, "Nouvel utilisateur WorldifyAI", `<p>Un nouvel utilisateur vient de s'inscrire.</p><p>Nom : ${safeHtml(name)}<br>E-mail : ${safeHtml(email)}</p>`); return json(res, 201, { user: publicUser(user), data: user.data, revision: user.dataVersion || 0 }); }
  if (pathname === "/api/auth/login" && req.method === "POST") { rateLimit(req, "login", 10, 15 * 60 * 1000); const input = await requestBody(req); const email = String(input.email || "").trim().toLowerCase(); const user = await db.collection("users").findOne({ email }); if (!user || !(await passwordMatches(String(input.password || ""), user))) return json(res, 401, { error: "Adresse e-mail ou mot de passe incorrect." }); await startSession(res, user._id); await sendBestEffortMail(email, "Connexion à votre compte WorldifyAI", `<p>Bonjour ${safeHtml(user.name)},</p><p>Une connexion à votre compte vient d'avoir lieu.</p>`); return json(res, 200, { user: publicUser(user), data: sanitizeData(user.data), revision: user.dataVersion || 0 }); }
  if (pathname === "/api/auth/forgot" && req.method === "POST") { rateLimit(req, "forgot", 5, 15 * 60 * 1000); if (!mailConfigured()) return json(res, 503, { error: "Le service e-mail n’est pas configuré." }); const input = await requestBody(req); const email = String(input.email || "").trim().toLowerCase(); const user = await db.collection("users").findOne({ email }); if (user) { const token = crypto.randomBytes(32).toString("hex"); await db.collection("users").updateOne({ _id: user._id }, { $set: { resetTokenHash: tokenHash(token), resetExpiresAt: new Date(Date.now() + 15 * 60 * 1000) } }); const link = `${APP_URL}/reset-password.html?resetToken=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`; await sendRequiredMail(email, "Réinitialisation de votre mot de passe", `<p>Bonjour ${safeHtml(user.name)},</p><p><a href="${link}">Réinitialiser mon mot de passe</a></p><p>Ce lien expire dans 15 minutes.</p>`); } return json(res, 200, { message: "Si cette adresse existe, un lien de récupération vient d’être envoyé par e-mail." }); }
  if (pathname === "/api/auth/reset" && req.method === "POST") { rateLimit(req, "reset", 8, 15 * 60 * 1000); const input = await requestBody(req); const email = String(input.email || "").trim().toLowerCase(); const token = String(input.token || ""); const password = String(input.password || ""); const user = await db.collection("users").findOne({ email, resetTokenHash: tokenHash(token), resetExpiresAt: { $gt: new Date() } }); if (!user || password.length < 8) return json(res, 400, { error: "Lien invalide ou mot de passe trop court." }); const credentials = await passwordHash(password); await db.collection("users").updateOne({ _id: user._id }, { $set: { passwordSalt: credentials.salt, passwordHash: credentials.hash }, $unset: { resetTokenHash: "", resetExpiresAt: "" } }); await db.collection("sessions").deleteMany({ userId: user._id }); await sendBestEffortMail(email, "Mot de passe modifié", `<p>Bonjour ${safeHtml(user.name)},</p><p>Votre mot de passe WorldifyAI vient d’être modifié.</p>`); return json(res, 200, { message: "Mot de passe mis à jour. Vous pouvez vous connecter." }); }
  if (pathname === "/api/auth/logout" && req.method === "POST") { await endSession(res, req); return json(res, 200, { ok: true }); }
  if (pathname === "/api/auth/me" && req.method === "GET") { const current = await auth(req); return json(res, 200, current ? { user: publicUser(current.user), data: sanitizeData(current.user.data), revision: current.user.dataVersion || 0 } : { user: null }); }
  if (pathname === "/api/sync" && (req.method === "GET" || req.method === "PUT")) { const current = await auth(req); if (!current) return json(res, 401, { error: "Connexion requise." }); if (req.method === "GET") return json(res, 200, { data: sanitizeData(current.user.data), revision: current.user.dataVersion || 0 }); const input = await requestBody(req); const data = sanitizeData(input); const revision = Number.isInteger(input.revision) ? input.revision : 0; const nextRevision = (current.user.dataVersion || 0) + 1; const result = await db.collection("users").updateOne({ _id: current.user._id, $or: [{ dataVersion: revision }, { dataVersion: { $exists: false } }] }, { $set: { data, dataVersion: nextRevision } }); if (!result.matchedCount) return json(res, 409, { error: "Données modifiées sur un autre appareil.", revision: current.user.dataVersion || 0 }); return json(res, 200, { data, revision: nextRevision }); }
  if (pathname === "/api/admin/users" && req.method === "GET") return adminUsers(req, res);
  return json(res, 404, { error: "Route introuvable." });
}
function serve(res, pathname) { const pages = { "/": [INDEX_FILE, "text/html; charset=utf-8"], "/learn_english": [INDEX_FILE, "text/html; charset=utf-8"], "/learn_english/": [INDEX_FILE, "text/html; charset=utf-8"], "/index.html": [INDEX_FILE, "text/html; charset=utf-8"], "/login": [path.join(__dirname, "login.html"), "text/html; charset=utf-8"], "/login.html": [path.join(__dirname, "login.html"), "text/html; charset=utf-8"], "/register": [path.join(__dirname, "register.html"), "text/html; charset=utf-8"], "/register.html": [path.join(__dirname, "register.html"), "text/html; charset=utf-8"], "/forgot-password": [path.join(__dirname, "forgot-password.html"), "text/html; charset=utf-8"], "/forgot-password.html": [path.join(__dirname, "forgot-password.html"), "text/html; charset=utf-8"], "/reset-password": [path.join(__dirname, "reset-password.html"), "text/html; charset=utf-8"], "/reset-password.html": [path.join(__dirname, "reset-password.html"), "text/html; charset=utf-8"], "/auth.css": [path.join(__dirname, "auth.css"), "text/css; charset=utf-8"], "/auth.js": [path.join(__dirname, "auth.js"), "text/javascript; charset=utf-8"] }; if (pathname === "/favicon.ico") { res.writeHead(204, SECURITY_HEADERS); return res.end(); } const page = pages[pathname]; if (!page) return json(res, 404, { error: "Page introuvable." }); res.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": page[1], "Cache-Control": "no-cache" }); fs.createReadStream(page[0]).pipe(res); }
async function main() { validateConfig(); const client = new MongoClient(MONGODB_URI); await client.connect(); db = client.db(MONGODB_DB); await db.collection("users").createIndex({ email: 1 }, { unique: true }); await db.collection("sessions").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }); await db.collection("sessions").createIndex({ tokenHash: 1 }, { unique: true }); await seedAdmin(); http.createServer(async (req, res) => { try { const pathname = new URL(req.url, `http://${req.headers.host || "localhost"}`).pathname; pathname.startsWith("/api/") ? await api(req, res, pathname) : serve(res, pathname); } catch (error) { console.error(error); json(res, error.status || 500, { error: error.status ? error.message : "Erreur serveur." }); } }).listen(PORT, HOST, () => console.log(`WorldifyAI running at http://localhost:${PORT}`)); }
main().catch((error) => { console.error(error.message); process.exit(1); });
