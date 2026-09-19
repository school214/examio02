import { auth } from "@/auth";
import { db } from "@/lib/db";
import { json } from "@/lib/security";

// Returns ONLY what the caller is allowed to see. Anonymous callers get nothing.
export async function GET() {
  const session = await auth();
  const id = (session?.user as any)?.id as string | undefined;
  const user = id ? await db.user.findUnique({ where: { id } }) : null;
  if (!user) return json({ user: null });
  const admin = user.role === "ADMIN";

  const exams = await db.exam.findMany({
    where: admin ? {} : { OR: [{ visibility: "public" }, { ownerId: user.id }] },
    include: { owner: { select: { username: true } } },
  });
  const requests = await db.publishRequest.findMany({ where: admin ? {} : { userId: user.id }, orderBy: { createdAt: "asc" } });
  const results = await db.result.findMany({ where: admin ? {} : { userId: user.id }, orderBy: { createdAt: "desc" }, take: 500 });

  return json({
    user: { username: user.username, role: admin ? "admin" : "user" },
    exams: exams.map((e) => ({
      key: e.key, builtin: e.builtin, deleted: e.deleted,
      exam: { ...(e.data as object), owner: e.builtin ? "Examio" : e.owner?.username ?? "?", builtin: e.builtin, visibility: e.visibility, status: e.status },
    })),
    requests: requests.map((r) => ({
      id: Number(r.id), examKey: r.examKey, user: r.username, status: r.status, date: r.createdAt.toISOString(),
      handledBy: r.handledBy ?? undefined, handledAt: r.handledAt?.toISOString(),
      examTitle: (exams.find((e) => e.key === r.examKey)?.data as any)?.title,
    })),
    results: results.map((r) => ({ ...(r.data as object), id: Number(r.id), user: user.role === "ADMIN" ? (r.data as any).user : user.username })),
  });
}
