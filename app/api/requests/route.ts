import { db } from "@/lib/db";
import { guard, readJson } from "@/lib/guard";
import { audit, clientIp, json } from "@/lib/security";

export async function PUT(req: Request) {
  const g = await guard(req, { write: true });
  if ("res" in g) return g.res;
  const { user } = g;
  const admin = user.role === "ADMIN";
  const body = await readJson(req, 500_000);
  if (!body || !Array.isArray(body.requests)) return json({ error: "Invalid body" }, 400);

  const ops: any[] = [];
  for (const r of body.requests.slice(0, 500)) {
    if (!r || !Number.isFinite(Number(r.id))) continue;
    const id = String(Math.trunc(Number(r.id)));
    const cur = await db.publishRequest.findUnique({ where: { id } });

    if (!cur) {
      // Anyone may request publication of THEIR OWN private exam, once at a time. Status is forced to "pending".
      const exam = await db.exam.findUnique({ where: { key: String(r.examKey) } });
      if (!exam || exam.builtin || exam.ownerId !== user.id || exam.visibility === "public") continue;
      const pending = await db.publishRequest.findFirst({ where: { examKey: exam.key, status: "pending" } });
      if (pending) continue;
      ops.push(db.publishRequest.create({ data: { id, examKey: exam.key, userId: user.id, username: user.username, status: "pending" } }));
    } else if (admin && cur.status === "pending" && ["approved", "declined"].includes(r.status)) {
      ops.push(db.publishRequest.update({ where: { id }, data: { status: r.status, handledBy: user.username, handledAt: new Date() } }));
      await audit("request." + r.status, { userId: user.id, target: cur.examKey, ip: clientIp(req) });
    }
  }
  if (ops.length) await db.$transaction(ops);
  return json({ ok: true });
}
