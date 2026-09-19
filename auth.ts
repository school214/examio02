import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import { db } from "@/lib/db";
import { audit, clientIp, rateLimit } from "@/lib/security";

// Valid bcrypt hash used to keep timing equal when the user does not exist (prevents user enumeration).
const DUMMY_HASH = bcrypt.hashSync("timing-equalizer-not-a-password", 12);
const MAX_FAILS = 5;
const LOCK_MINUTES = 15;

export const { handlers, auth, signIn, signOut } = NextAuth({
  trustHost: true,
  session: { strategy: "jwt", maxAge: 60 * 60 * 8, updateAge: 60 * 30 }, // 8h absolute session
  pages: { signIn: "/" },
  cookies: {
    sessionToken: {
      name: process.env.NODE_ENV === "production" ? "__Secure-examio.session" : "examio.session",
      options: { httpOnly: true, sameSite: "lax", path: "/", secure: process.env.NODE_ENV === "production" },
    },
  },
  providers: [
    Credentials({
      credentials: { username: {}, password: {} },
      async authorize(creds, request) {
        const username = String(creds?.username ?? "").trim();
        const password = String(creds?.password ?? "");
        const ip = clientIp(request as Request);
        if (!username || username.length > 24 || !password || password.length > 72) return null;

        // Rate limit per IP and per account
        const okIp = await rateLimit(`login:ip:${ip}`, 20, 900);
        const okUser = await rateLimit(`login:user:${username.toLowerCase()}`, 10, 900);
        if (!okIp || !okUser) { await audit("login.ratelimited", { ip, target: username }); return null; }

        const user = await db.user.findUnique({ where: { usernameLower: username.toLowerCase() } });
        const locked = user?.lockedUntil && user.lockedUntil > new Date();
        const valid = await bcrypt.compare(password, user?.passwordHash ?? DUMMY_HASH);

        if (!user || locked || !valid) {
          if (user && !locked) {
            const fails = user.failedLogins + 1;
            await db.user.update({
              where: { id: user.id },
              data: fails >= MAX_FAILS
                ? { failedLogins: 0, lockedUntil: new Date(Date.now() + LOCK_MINUTES * 60_000) }
                : { failedLogins: fails },
            });
          }
          await audit("login.failed", { userId: user?.id, ip, target: username });
          return null;
        }
        await db.user.update({ where: { id: user.id }, data: { failedLogins: 0, lockedUntil: null } });
        await audit("login.success", { userId: user.id, ip });
        return { id: user.id, name: user.username };
      },
    }),
  ],
  callbacks: {
    // Only the user id goes in the token. The role is ALWAYS re-read from the DB on each API call.
    jwt({ token, user }) { if (user?.id) token.uid = user.id; return token; },
    session({ session, token }) { (session.user as any).id = token.uid as string; return session; },
  },
});
