export default async () =>
  Response.json({ appId: process.env.ONESIGNAL_APP_ID || "88290d9d-35aa-414d-bac4-74227002a020" }, { headers: { "Cache-Control": "no-store" } });
