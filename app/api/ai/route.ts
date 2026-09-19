import { guard, readJson } from "@/lib/guard";
import { json, rateLimit } from "@/lib/security";

// Server-side proxy: the API key never reaches the browser; model, size and rate are enforced here.
export async function POST(req: Request) {
  const g = await guard(req, { write: true });
  if ("res" in g) return g.res;
  const { user } = g;
  if (!(await rateLimit(`ai:${user.id}`, 60, 3600))) return json({ error: "AI rate limit reached" }, 429);

  const body = await readJson(req, 40_000);
  const content = body?.messages?.[0]?.content;
  if (typeof body?.system !== "string" || typeof content !== "string" || body.system.length > 6000 || content.length > 20_000)
    return json({ error: "Invalid request" }, 400);
  if (!process.env.ANTHROPIC_API_KEY) return json({ error: "AI not configured" }, 503);

  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({
      model: process.env.ANTHROPIC_MODEL || "claude-sonnet-4-6",
      max_tokens: Math.min(Number(body.max_tokens) || 300, 4000),
      system: body.system,
      messages: [{ role: "user", content }],
    }),
  });
  if (!r.ok) return json({ error: "Upstream error" }, 502);
  return json(await r.json());
}
