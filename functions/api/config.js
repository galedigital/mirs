export const onRequest = ({ env }) =>
  Response.json({ appId: env.ONESIGNAL_APP_ID || "88290d9d-35aa-414d-bac4-74227002a020" }, { headers: { "Cache-Control": "no-store" } });
