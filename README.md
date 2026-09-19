# Examio (secure edition)

Next.js 15 + Auth.js v5 + Neon PostgreSQL + Prisma. Same UI as the original `index.html`
(served from `public/index.html`), but all authority moved to the server.

## Setup (≈5 min)
1. Create a free Neon project → copy the pooled + direct connection strings.
2. `cp .env.example .env` and fill in: `DATABASE_URL`, `DIRECT_URL`, `AUTH_SECRET` (`openssl rand -base64 32`),
   `ANTHROPIC_API_KEY`, and `SEED_ADMINS` (e.g. `Elton:a-long-password-here,Emanuel:another-long-one`).
3. `npm install && npm run db:push && npm run db:seed`
4. `npm run dev` (or deploy to Vercel and set the same env vars).

**The old admin passwords in the original HTML were public to anyone who viewed the source. Treat them as compromised and never reuse them.**

## What is enforced (all server-side)
| Requirement | Where |
|---|---|
| PostgreSQL (Neon) | `prisma/schema.prisma` |
| Auth.js | `auth.ts` (credentials, JWT in httpOnly + Secure + SameSite=Lax cookie, 8h lifetime) |
| Password hashing | bcrypt cost 12, min 10 / max 72 chars; equal-time compare for unknown users |
| Role checks | `lib/guard.ts` reads role from the DB on every request; the client/token is never trusted. Admins only exist via seed script |
| CSRF | Auth.js CSRF token for login/logout; `Origin` must match host + JSON-only bodies + SameSite=Lax on all API writes |
| Rate limiting | Postgres-backed (`lib/security.ts`): login per IP and per account, register per IP, AI per user, global API per user |
| Account lockout | 5 failed logins → 15 min lock |
| Audit log | `AuditLog` table: logins (ok/failed/limited), registrations, exam changes, approvals, result submissions |
| Security headers | `next.config.mjs`: CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP |
| AI key | Server-side proxy `/api/ai`; model/size/rate enforced; key never in browser |
| Data isolation | `/api/state` returns only what the caller may see; users can only create private exams, and only admins can publish, edit built-ins, or see others' results |

## Known limitations (honest list)
- **Answer keys are still shipped to the browser** (the original app grades on the client and contains correct answers inside the exam JSON). A determined student can read them from DevTools. Real fix: move grading to `/api/submit` and strip `correct`/`keywords` from exams sent to students.
- CSP allows `'unsafe-inline'` scripts because the UI uses inline `onclick` handlers. User content is escaped with `esc()`; a later refactor to event listeners + nonces would allow a strict CSP.
- Rate limiting and audit logs live in Postgres (simple, but adds a few DB queries per request).
- No email/password reset flow or MFA yet.
- Not tested against a live database in this build environment. Run through the flows once after setup (register, login, create exam, request publish, approve as admin).
