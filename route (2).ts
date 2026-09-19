import bcrypt from "bcryptjs";
import { z } from "zod";
import { db } from "@/lib/db";
import { audit, clientIp, json, rateLimit, sameOrigin } from "@/lib/security";

const schema = z.object({
  username: z.string().trim().min(3).max(24).regex(/^[\p{L}0-9_-]+$/u, "Letters, digits, _ and - only"),
  password: z.string().min(10, "Min 10 characters").max(72),
});
const RESERVED = ["examio", "admin", "administrator", "root", "system"];

export async function POST(req: Request) {
  if (!sameOrigin(req)) return json({ error: "Bad origin" }, 403);
  const ip = clientIp(req);
  if (!(await rateLimit(`register:${ip}`, 5, 3600))) return json({ error: "Too many attempts, try later" }, 429);

  const raw = await req.text();
  if (raw.length > 2000) return json({ error: "Too large" }, 413);
  let body: unknown; try { body = JSON.parse(raw); } catch { return json({ error: "Invalid JSON" }, 400); }
  const p = schema.safeParse(body);
  if (!p.success) return json({ error: p.error.issues[0]?.message ?? "Invalid input" }, 400);

  const { username, password } = p.data;
  if (RESERVED.includes(username.toLowerCase())) return json({ error: "Username reserved" }, 400);
  const passwordHash = await bcrypt.hash(password, 12);
  try {
    // Role is always USER here. Admins can only be created via the server-side seed script.
    const u = await db.user.create({ data: { username, usernameLower: username.toLowerCase(), passwordHash, role: "USER" } });
    await audit("register", { userId: u.id, ip });
    return json({ ok: true }, 201);
  } catch {
    return json({ error: "Username taken" }, 409);
  }
}
