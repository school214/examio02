import { db } from "@/lib/db";
import { guard, readJson } from "@/lib/guard";
import { audit, clientIp, json } from "@/lib/security";

const KEY = /^[A-Za-z0-9_-]{1,64}$/;
const VIS = ["private", "public"], STATUS = ["active", "inactive", "expired"];
const MAX_EXAM_BYTES = 300_000;

/**
 * Sync endpoint. The client sends its view; the SERVER decides what is actually allowed:
 *  - USER:  create/edit/delete only their own private, non-builtin exams. Visibility/status are forced server-side.
 *  - ADMIN: full control, incl. visibility/status and built-in exams.
 */
export async function PUT(req: Request) {
  const g = await guard(req, { write: true });
  if ("res" in g) return g.res;
  const { user } = g;
  const admin = user.role === "ADMIN";
  const body = await readJson(req, 4_000_000);
  if (!body || typeof body.exams !== "object" || body.exams === null) return json({ error: "Invalid body" }, 400);

  const incoming = body.exams as Record<string, any>;
  const existing = await db.exam.findMany({ where: admin ? {} : { ownerId: user.id, builtin: false } });
  const byKey = new Map(existing.map((e) => [e.key, e]));
  const ops: any[] = [];
  const log: string[] = [];

  for (const [key, e] of Object.entries(incoming)) {
    if (!KEY.test(key) || typeof e !== "object" || e === null) continue;
    const cur = byKey.get(key) ?? (await db.exam.findUnique({ where: { key } }));
    const { owner, builtin, visibility, status, ...data } = e;
    if (JSON.stringify(data).length > MAX_EXAM_BYTES) continue;

    if (e.builtin) {
      if (!admin) continue; // built-ins are admin-only
      const v = VIS.includes(visibility) ? visibility : "public", s = STATUS.includes(status) ? status : "active";
      ops.push(db.exam.upsert({ where: { key }, create: { key, builtin: true, visibility: v, status: s, data: {} }, update: { visibility: v, status: s, deleted: false } }));
      log.push(`builtin:${key}`);
      continue;
    }
    if (!cur) {
      // New exam. Non-admins can only ever create PRIVATE/ACTIVE exams.
      ops.push(db.exam.create({ data: {
        key, ownerId: user.id, builtin: false, data,
        visibility: admin && VIS.includes(visibility) ? visibility : "private",
        status: admin && STATUS.includes(status) ? status : "active",
      } }));
      log.push(`create:${key}`);
    } else if (admin || (cur.ownerId === user.id && cur.visibility !== "public" && !cur.builtin)) {
      ops.push(db.exam.update({ where: { key }, data: {
        data,
        ...(admin ? { visibility: VIS.includes(visibility) ? visibility : cur.visibility, status: STATUS.includes(status) ? status : cur.status } : {}),
      } }));
      log.push(`update:${key}`);
    } // else: not permitted -> silently ignored
  }

  // Deletions: only for exams the caller may delete
  for (const cur of existing) {
    if (incoming[cur.key]) continue;
    if (cur.builtin) {
      if (admin && Array.isArray(body.builtinKeys) && body.builtinKeys.includes(cur.key)) {
        ops.push(db.exam.update({ where: { key: cur.key }, data: { deleted: true } })); log.push(`delete-builtin:${cur.key}`);
      }
      continue;
    }
    if (admin || (cur.ownerId === user.id && cur.visibility !== "public")) {
      ops.push(db.exam.delete({ where: { key: cur.key } }), db.publishRequest.deleteMany({ where: { examKey: cur.key } }));
      log.push(`delete:${cur.key}`);
    }
  }
  // Admin deleting a built-in that has no DB row yet
  if (admin && Array.isArray(body.builtinKeys)) {
    for (const k of body.builtinKeys) {
      if (typeof k === "string" && KEY.test(k) && !incoming[k] && !byKey.has(k)) {
        ops.push(db.exam.upsert({ where: { key: k }, create: { key: k, builtin: true, deleted: true, data: {} }, update: { deleted: true } }));
      }
    }
  }

  await db.$transaction(ops);
  if (log.length) await audit("exams.sync", { userId: user.id, ip: clientIp(req), detail: log.slice(0, 50) });
  return json({ ok: true });
}
