// Department list for Mirs.
// GET  -> public list (id, name, fingerprint) used by the app to recognise a code.
// POST {action:"line", code, hub} -> any valid department code gets the key of a hub's call line (e.g. the Moked)
// POST -> admin only (header x-admin = ADMIN_PASSWORD env var): {action:"list"} or {action:"save", depts:[...]}
import { getStore } from "@netlify/blobs";
import { pbkdf2Sync, timingSafeEqual, createHash, createHmac, randomBytes } from "node:crypto";

// initial departments (fingerprints only; the codes themselves are never stored in the repo)
const SEED = [
  { id: "moked", n: "מוקד", t: "a156735a33712b71", hub: true },
  { id: "env", n: "איכות הסביבה", t: "693fb8f346b07c67" },
  { id: "dover", n: "דוברות", t: "4f0fac11d079bcd0" },
  { id: "beaches", n: "חופים", t: "cbd81a76647baf7f" },
  { id: "tikshuv", n: "תקשוב", t: "4d3f39f77fd5d515" },
  { id: "shefa", n: "שפ״ע / תברואה", t: "333c61c16907ebcf" },
  { id: "pikuach", n: "פיקוח ואכיפה", t: "7c5c2d3d17c2b8cb" },
  { id: "bitachon", n: "ביטחון וחירום", t: "9cc7287503a484cc" }
];

const FIN = { "ך": "כ", "ם": "מ", "ן": "נ", "ף": "פ", "ץ": "צ" };
// must match normCode() in index.html
const norm = (v) => String(v || "").toLowerCase().replace(/[ךםןףץ]/g, (c) => FIN[c]).replace(/[^a-z0-9א-ת]/g, "").slice(0, 30);
// must match deriveChannel() in index.html (bytes 56..64 of the PBKDF2 output)
const tagOf = (code) => pbkdf2Sync(code, "mirs-channel-v3", 150000, 64, "sha256").subarray(56, 64).toString("hex");
const json = (data, status = 200) => Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
const sameSecret = (a, b) => timingSafeEqual(createHash("sha256").update(String(a)).digest(), createHash("sha256").update(String(b)).digest());

// brute-force guard: after MAX failed attempts from one IP, block it for LOCK ms
const MAX = 10, LOCK = 15 * 60 * 1000;
const ipOf = (req, ctx) => (ctx && ctx.ip) || req.headers.get("x-nf-client-connection-ip") || "x";
const failKey = (ip) => "fail-" + createHash("sha256").update(ip).digest("hex").slice(0, 24);
async function blocked(store, ip) {
  const f = await store.get(failKey(ip), { type: "json" }).catch(() => null);
  return !!(f && f.n >= MAX && Date.now() - f.at < LOCK);
}
async function fail(store, ip) {
  const k = failKey(ip), now = Date.now();
  const f = (await store.get(k, { type: "json" }).catch(() => null)) || { n: 0, at: now };
  const n = now - f.at > LOCK ? 1 : f.n + 1;
  await store.setJSON(k, { n, at: now });
  await new Promise((r) => setTimeout(r, 800));
}
const clearFail = (store, ip) => store.delete(failKey(ip)).catch(() => {});

async function load(store) {
  const d = await store.get("depts", { type: "json" });
  return Array.isArray(d) ? d : SEED.map((x) => ({ ...x, code: "" }));
}

export default async (req, ctx) => {
  const store = getStore({ name: "mirs", consistency: "strong" });

  if (req.method === "GET") {
    const list = await load(store);
    return json(list.map(({ id, n, t, hub }) => ({ id, n, t, hub: !!hub })));
  }
  if (req.method !== "POST") return json({ ok: false }, 405);

  let b;
  try { b = await req.json(); } catch { return json({ ok: false, error: "bad" }, 400); }

  const ip = ipOf(req, ctx);
  if (await blocked(store, ip)) return json({ ok: false, error: "locked" }, 429);

  if (b.action === "line") {
    const list = await load(store), code = norm(b.code);
    const me = code.length >= 6 && list.find((x) => x.t === tagOf(code));
    const hub = list.find((x) => x.id === b.hub && x.hub);
    if (!me || !hub) { await fail(store, ip); return json({ ok: false, error: "auth" }, 403); }
    let secret = await store.get("line-secret");
    if (!secret) { secret = randomBytes(32).toString("hex"); await store.set("line-secret", secret); }
    return json({ ok: true, key: createHmac("sha256", secret).update("line:" + hub.id).digest("hex") });
  }

  const pass = process.env.ADMIN_PASSWORD;
  if (!pass) return json({ ok: false, error: "no-admin" }, 503);
  if (!sameSecret(req.headers.get("x-admin") || "", pass)) {
    await fail(store, ip);
    return json({ ok: false, error: "auth" }, 401);
  }
  await clearFail(store, ip);

  const current = await load(store);

  if (b.action === "list") return json({ ok: true, depts: current });

  if (b.action === "save") {
    if (!Array.isArray(b.depts) || b.depts.length > 50) return json({ ok: false, error: "bad" }, 400);
    const out = [], codes = new Set(), tags = new Set();
    for (const d of b.depts) {
      const n = String(d.n || "").replace(/[<>]/g, "").trim().slice(0, 30);
      if (!n) return json({ ok: false, error: "name" }, 400);
      const id = /^[a-z0-9-]{1,24}$/.test(d.id || "") ? d.id : "d" + randomBytes(5).toString("hex");
      const code = norm(d.code);
      const prev = current.find((x) => x.id === id);
      let t;
      if (code) {
        if (code.length < 6) return json({ ok: false, error: "short", n }, 400);
        if (codes.has(code)) return json({ ok: false, error: "dup", n }, 400);
        codes.add(code);
        t = prev && prev.code === code && prev.t ? prev.t : tagOf(code);
      } else if (prev && prev.t && !prev.code) {
        t = prev.t; // seeded department whose code was not entered yet
      } else return json({ ok: false, error: "nocode", n }, 400);
      if (tags.has(t)) return json({ ok: false, error: "dup", n }, 400);
      tags.add(t);
      out.push({ id, n, t, code, hub: !!d.hub });
    }
    await store.setJSON("depts", out);
    return json({ ok: true, depts: out });
  }
  return json({ ok: false, error: "bad" }, 400);
};
