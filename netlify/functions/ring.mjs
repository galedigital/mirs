// Sends a OneSignal push ("someone is calling you") to devices that are not currently open.
const ID = /^m[a-z0-9]{6,12}$/;
const recent = new Map();

export default async (req) => {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const appId = process.env.ONESIGNAL_APP_ID || "88290d9d-35aa-414d-bac4-74227002a020", key = process.env.ONESIGNAL_REST_API_KEY;
  if (!appId || !key) return Response.json({ ok: false, error: "not configured" }, { status: 500 });

  let b;
  try { b = await req.json(); } catch { return Response.json({ ok: false }, { status: 400 }); }
  const ch = String(b.ch || "").replace(/\D/g, "").slice(0, 6);
  const from = String(b.from || "");
  const to = String(b.to || "");
  const name = String(b.name || "מישהו").replace(/[<>]/g, "").slice(0, 18);
  const kind = b.kind === "talk" ? "talk" : "alert";
  if (!ch || !ID.test(from) || !(to === "all" || ID.test(to))) return Response.json({ ok: false }, { status: 400 });

  // simple throttle per sender+target
  const k = from + ">" + to, now = Date.now();
  if (now - (recent.get(k) || 0) < 15000) return Response.json({ ok: true, throttled: true });
  recent.set(k, now);

  let url = String(b.url || "");
  const origin = new URL(req.url).origin;
  if (!url.startsWith(origin)) url = origin + "/#" + ch;

  const text = kind === "talk" ? `${name} מנסה לדבר איתך בערוץ ${ch}` : `${name} קורא לך בערוץ ${ch}`;
  const body = {
    app_id: appId,
    target_channel: "push",
    headings: { en: "📟 מירס", he: "📟 מירס" },
    contents: { en: text, he: text },
    url,
    priority: 10,
    ttl: 120,
  };

  if (to === "all") {
    const online = Array.isArray(b.online) ? b.online.filter((x) => ID.test(x)).slice(0, 60) : [];
    const filters = [{ field: "tag", key: "ch", relation: "=", value: ch },
                     { field: "tag", key: "uid", relation: "!=", value: from }];
    for (const id of online) if (id !== from) filters.push({ field: "tag", key: "uid", relation: "!=", value: id });
    body.filters = filters;
  } else {
    body.include_aliases = { external_id: [to] };
  }

  const r = await fetch("https://api.onesignal.com/notifications?c=push", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Key ${key}` },
    body: JSON.stringify(body),
  });
  const out = await r.json().catch(() => ({}));
  return Response.json({ ok: r.ok, id: out.id || null, errors: out.errors || null }, { status: r.ok ? 200 : 502 });
};
