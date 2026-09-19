// One-time bootstrap of admin accounts from SEED_ADMINS env var. Passwords never live in the front end.
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
const db = new PrismaClient();
const raw = process.env.SEED_ADMINS || "";
if (!raw) { console.log("SEED_ADMINS empty, nothing to do."); process.exit(0); }
for (const pair of raw.split(",")) {
  const i = pair.indexOf(":");
  const username = pair.slice(0, i).trim(), password = pair.slice(i + 1);
  if (!username || password.length < 12) { console.error(`Skipping "${username}": password must be >= 12 chars`); continue; }
  const passwordHash = await bcrypt.hash(password, 12);
  await db.user.upsert({
    where: { usernameLower: username.toLowerCase() },
    update: { passwordHash, role: "ADMIN", failedLogins: 0, lockedUntil: null },
    create: { username, usernameLower: username.toLowerCase(), passwordHash, role: "ADMIN" },
  });
  console.log(`Admin ready: ${username}`);
}
await db.$disconnect();
