import { PRISMA_GLOBAL_OMIT } from "./client-options";
import { minidauthSeal } from "./minidauth-seal";
import { PrismaClient } from "./prisma";
import { createPrismaPgAdapter } from "./prisma-adapter";

// The return type is inferred (not annotated `PrismaClient`) because `.$extends` returns an extended
// client; the minidauth-seal extension only intercepts Response reads/writes and adds no surface.
const prismaClientSingleton = () => {
  const { adapter } = createPrismaPgAdapter();

  return new PrismaClient({
    adapter,
    omit: PRISMA_GLOBAL_OMIT,
    ...(process.env.DEBUG === "1" && {
      log: ["query", "info"],
    }),
  }).$extends(minidauthSeal);
};

type PrismaClientSingleton = ReturnType<typeof prismaClientSingleton>;

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClientSingleton | undefined;
};

export const prisma = globalForPrisma.prisma ?? prismaClientSingleton();

if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;
