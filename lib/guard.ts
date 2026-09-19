import { auth } from "@/auth";
import { db } from "./db";
import { json, sameOrigin, rateLimit, clientIp } from "./security";

export type AuthedUser = { id: string; username: string; role: "USER" | "ADMIN" };

/** Authenticate + CSRF-check + global per-user rate limit. Role comes from the DB, never from the client or token. */
export async function guard(req: Request, opts: { write?: boolean; admin?: boolean } = {}): Promise<{ user: AuthedUser } | { res: Response }> {
  if (opts.write) {
    if (!sameOrigin(req)) return { res: json({ error: "Bad origin" }, 403) };
    if (!(req.headers.get("content-type") || "").includes("application/json")) return { res: json({ error: "JSON only" }, 415) };
  }
  const session = await auth();
  const id = (session?.user as any)?.id as string | undefined;
  if (!id) return { res: json({ error: "Unauthorized" }, 401) };
  const user = await db.user.findUnique({ where: { id }, select: { id: true, username: true, role: true } });
  if (!user) return { res: json({ error: "Unauthorized" }, 401) };
  if (opts.admin && user.role !== "ADMIN") return { res: json({ error: "Forbidden" }, 403) };
  if (!(await rateLimit(`api:${user.id}`, 300, 60))) return { res: json({ error: "Too many requests" }, 429) };
  return { user };
}

export async function readJson(req: Request, maxBytes: number): Promise<any | null> {
  const text = await req.text();
  if (text.length > maxBytes) return null;
  try { return JSON.parse(text); } catch { return null; }
}
export { clientIp };
