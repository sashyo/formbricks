// Create a real, PUBLISHED link survey so it can be filled in at /s/<id> in the browser.
// The write goes through the sealed Prisma client, so any response submitted is sealed by the
// ORK cohort before it touches Postgres.
import { createId } from "@paralleldrive/cuid2";
import { prisma } from "../../packages/database/src/client";

const i18n = (s: string) => ({ default: s });

async function main() {
  const org = await prisma.organization.create({ data: { name: "Acme Feedback " + Date.now() } });
  const workspace = await prisma.workspace.create({
    data: { name: "Customer Research", organizationId: org.id },
  });

  const element = {
    id: createId(),
    type: "openText",
    headline: i18n("What could we improve about the checkout?"),
    subheader: i18n("Your answer is encrypted before it is stored. Not even this server can read it."),
    placeholder: i18n("Type your honest feedback…"),
    required: true,
    inputType: "text",
    longAnswer: true,
    charLimit: { enabled: false },
  };
  const emailElement = {
    id: createId(),
    type: "openText",
    headline: i18n("Your email (so we can follow up)"),
    placeholder: i18n("you@example.com"),
    required: false,
    inputType: "email",
    charLimit: { enabled: false },
  };
  const block = { id: createId(), name: "Feedback", elements: [element, emailElement] };
  const ending = {
    id: createId(),
    type: "endScreen",
    headline: i18n("Thank you!"),
    subheader: i18n("Your response was sealed and stored as ciphertext."),
    buttonLabel: i18n("Close"),
  };

  const survey = await prisma.survey.create({
    data: {
      name: "Checkout feedback",
      workspaceId: workspace.id,
      status: "inProgress",
      type: "link",
      welcomeCard: { enabled: false } as any,
      questions: [] as any,
      blocks: [block] as any,
      endings: [ending] as any,
      hiddenFields: { enabled: false } as any,
    },
    select: { id: true, name: true },
  });

  const base = process.env.WEBAPP_URL || "http://localhost:3000";
  console.log(JSON.stringify({ surveyId: survey.id, url: `${base}/s/${survey.id}`, workspaceId: workspace.id, orgId: org.id }, null, 2));
  await prisma.$disconnect();
}
main().catch((e) => { console.error(e); process.exit(1); });
