// Department list for Mirs (Cloudflare Pages Function, KV binding "MIRS").
// GET  -> public list (id, name, fingerprint).
// POST {action:"line", t, v, hub} -> a department proves it knows its code (v = one-way proof computed in the app)
//      and gets the key of a hub's call line (e.g. the Moked).
// POST admin only (header x-admin = ADMIN_PASSWORD secret): {action:"list"} or {action:"save", depts:[...]}.
// PBKDF2 is done in the browser (Workers cap PBKDF2 and CPU time), the server only hashes.

const SEED = [
  { id: "moked", n: "מוקד", t: "94813f8c346dd4f0", hub: true },
  { id: "env", n: "איכות הסביבה", t: "693fb8f346b07c67" },
  { id: "dover", n: "דוברות", t: "ad97514814019218" },
  { id: "beaches", n: "חופים", t: "226b9a079101fdfc" },
  { id: "tikshuv", n: "תקשוב", t: "4d3f39f77fd5d515" },
  { id: "shefa", n: "שפ״ע / תברואה", t: "333c61c16907ebcf" },
  { id: "pikuach", n: "פיקוח ואכיפה", t: "7c5c2d3d17c2b8cb" },
  { id: "bitachon", n: "ביטחון וחירום", t: "9cc7287503a484cc" }
];

const TE = new TextEncoder();
const hex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
const sha = async (s) => hex(await crypto.subtle.digest("SHA-256", TE.encode(String(s))));
const json = (data, status = 200) => Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
const FIN = { "ך": "כ", "ם": "מ", "ן": "נ", "ף": "פ", "ץ": "צ" };
// must match normCode() in index.html
const norm = (v) => String(v || "").toLowerCase().replace(/[ךםןףץ]/g, (c) => FIN[c]).replace(/[^a-z0-9א-ת]/g, "").slice(0, 30);
const isHex = (s, n) => typeof s === "string" && new RegExp("^[a-f0-9]{" + n + "}$").test(s);
async function same(a, b) { // constant-time compare of hashes
  const x = await sha(a), y = await sha(b); let d = 0;
  for (let i = 0; i < x.length; i++) d |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return d === 0;
}
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

// brute-force guard: after MAX failed attempts from one IP, block it for 15 minutes
const MAX = 10, LOCK = 15 * 60 * 1000;
const failKey = async (ip) => "fail-" + (await sha(ip)).slice(0, 24);
async function blocked(kv, ip) {
  const f = await kv.get(await failKey(ip), "json").catch(() => null);
  return !!(f && f.n >= MAX && Date.now() - f.at < LOCK);
}
async function fail(kv, ip) {
  const k = await failKey(ip), now = Date.now();
  const f = (await kv.get(k, "json").catch(() => null)) || { n: 0, at: now };
  const n = now - f.at > LOCK ? 1 : f.n + 1;
  await kv.put(k, JSON.stringify({ n, at: now }), { expirationTtl: 900 }).catch(() => {});
  await new Promise((r) => setTimeout(r, 800));
}
const clearFail = async (kv, ip) => kv.delete(await failKey(ip)).catch(() => {});

async function load(kv) {
  const d = kv ? await kv.get("depts", "json").catch(() => null) : null;
  return Array.isArray(d) ? d : SEED.map((x) => ({ ...x, code: "" }));
}

export async function onRequest({ request: req, env }) {
  const kv = env.MIRS;
  if (req.method === "GET") {
    const list = await load(kv);
    return json(list.map(({ id, n, t, hub }) => ({ id, n, t, hub: !!hub })));
  }
  if (req.method !== "POST") return json({ ok: false }, 405);
  if (!kv) return json({ ok: false, error: "no-kv" }, 503);

  let b;
  try { b = await req.json(); } catch { return json({ ok: false, error: "bad" }, 400); }
  const ip = req.headers.get("CF-Connecting-IP") || "x";
  if (await blocked(kv, ip)) return json({ ok: false, error: "locked" }, 429);

  if (b.action === "line") {
    const list = await load(kv);
    const hub = list.find((x) => x.id === b.hub && x.hub);
    const me = isHex(b.t, 16) && isHex(b.v, 64) && list.find((x) => x.t === b.t);
    if (!hub || !me || !me.vh || !(await same(await sha(b.v), me.vh))) {
      await fail(kv, ip);
      return json({ ok: false, error: me && !me.vh ? "noproof" : "auth" }, 403);
    }
    let secret = await kv.get("line-secret");
    if (!secret) { secret = randHex(32); await kv.put("line-secret", secret); }
    const key = await crypto.subtle.importKey("raw", TE.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return json({ ok: true, key: hex(await crypto.subtle.sign("HMAC", key, TE.encode("line:" + hub.id))) });
  }

  const pass = env.ADMIN_PASSWORD;
  if (!pass) return json({ ok: false, error: "no-admin" }, 503);
  if (!(await same(req.headers.get("x-admin") || "", pass))) {
    await fail(kv, ip);
    return json({ ok: false, error: "auth" }, 401);
  }
  await clearFail(kv, ip);
  const current = await load(kv);
  const pub = (l) => l.map(({ id, n, t, code, hub, vh }) => ({ id, n, t, code, hub: !!hub, proof: !!vh }));

  if (b.action === "list") return json({ ok: true, depts: pub(current) });

  if (b.action === "save") {
    if (!Array.isArray(b.depts) || b.depts.length > 50) return json({ ok: false, error: "bad" }, 400);
    const out = [], codes = new Set(), tags = new Set();
    for (const d of b.depts) {
      const n = String(d.n || "").replace(/[<>]/g, "").trim().slice(0, 30);
      if (!n) return json({ ok: false, error: "name" }, 400);
      const id = /^[a-z0-9-]{1,24}$/.test(d.id || "") ? d.id : "d" + randHex(5);
      const code = norm(d.code);
      const prev = current.find((x) => x.id === id);
      let t, vh;
      if (code) {
        if (code.length < 6) return json({ ok: false, error: "short", n }, 400);
        if (codes.has(code)) return json({ ok: false, error: "dup", n }, 400);
        codes.add(code);
        if (prev && prev.code === code && prev.t && prev.vh) { t = prev.t; vh = prev.vh; }
        else if (isHex(d.t, 16) && isHex(d.v, 64)) { t = d.t; vh = await sha(d.v); } // computed by the admin page
        else return json({ ok: false, error: "bad", n }, 400);
      } else if (prev && prev.t && !prev.code) {
        t = prev.t; vh = prev.vh || ""; // department whose code was not entered here yet
      } else return json({ ok: false, error: "nocode", n }, 400);
      if (tags.has(t)) return json({ ok: false, error: "dup", n }, 400);
      tags.add(t);
      out.push({ id, n, t, code, hub: !!d.hub, vh });
    }
    await kv.put("depts", JSON.stringify(out));
    return json({ ok: true, depts: pub(out) });
  }
  return json({ ok: false, error: "bad" }, 400);
}
