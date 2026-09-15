// Create a real Formbricks survey response through the actual extended Prisma client, then show what
// lands in Postgres. Run with sealing on and the sidecar up:
//   set -a && . ./.env && set +a
//   MINIDAUTH_SEAL_URL=http://localhost:3020 npx tsx integrations/minidauth/live-demo.ts
import { prisma } from "../../packages/database/src/client";

async function main() {
  const org = await prisma.organization.create({ data: { name: "minidauth-poc-" + Date.now() } });
  const workspace = await prisma.workspace.create({ data: { name: "PoC Workspace", organizationId: org.id } });
  const survey = await prisma.survey.create({
    data: {
      name: "Customer feedback",
      workspaceId: workspace.id,
      status: "inProgress",
      type: "link",
      blocks: [{ id: "blk1", name: "Main Block", elements: [] }] as any,
    },
    select: { id: true },
  });

  console.log("submitting a response — each answer is sealed by the ORK cohort before it is stored...");
  const resp = await prisma.response.create({
    data: {
      surveyId: survey.id,
      finished: true,
      data: { q_email: "alice@example.com", q_feedback: "the checkout flow is confusing" } as any,
      contactAttributes: { email: "alice@example.com" } as any,
    },
    select: { id: true },
  });
  console.log("stored response", resp.id);

  // Exactly what a `pg_dump` or a stolen backup returns.
  const raw: any[] = await prisma.$queryRawUnsafe(
    `select data, "contactAttributes" from "Response" where id = $1`,
    resp.id
  );
  console.log("\n=== what Postgres actually holds (a DB dump) ===");
  console.log(JSON.stringify(raw[0], null, 2));

  // Read back through the app. Open is best-effort: with a PUBLIC decrypt policy and the reader's
  // role granted it returns plaintext; without, it safely stays sealed.
  const back = await prisma.response.findUnique({ where: { id: resp.id }, select: { data: true } });
  console.log("\n=== read back through the app ===");
  console.log(JSON.stringify(back?.data, null, 2));

  await prisma.$disconnect();
}

main().catch((e) => { console.error(e); process.exit(1); });
