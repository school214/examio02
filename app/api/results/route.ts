import { db } from "@/lib/db";
import { guard, readJson } from "@/lib/guard";
import { json, audit, clientIp } from "@/lib/security";

export async function POST(req: Request) {
  const g = await guard(req, { write: true });
  if ("res" in g) return g.res;
  const { user } = g;
  const body = await readJson(req, 300_000);
  const r = body?.result;
  if (!r || typeof r !== "object" || !Number.isFinite(Number(r.id))) return json({ error: "Invalid result" }, 400);
  // The owner is ALWAYS the authenticated user, whatever the client claims.
  const data = { ...r, user: user.username };
  try {
    await db.result.create({ data: { id: String(Math.trunc(Number(r.id))), userId: user.id, data } });
  } catch { return json({ error: "Duplicate" }, 409); }
  await audit("result.submit", { userId: user.id, ip: clientIp(req), target: String(r.examTitle ?? "").slice(0, 100) });
  return json({ ok: true }, 201);
}
