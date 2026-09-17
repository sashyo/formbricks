// minidauth field sealing for survey responses.
//
// Seals the Response JSON columns (`data`, the answers, and `contactAttributes`) before they reach
// Postgres, and opens them again on the way out. The engine lives in the `minidauth-prisma` package
// (JSON-column mode: each column is a Record whose values are sealed, stored as { _ms: 1, fields });
// this file only supplies Formbricks' config and exports the ready extension the client wraps.
//
// Off by default. Set MINIDAUTH_SEAL_URL (or MINIDAUTH_SEAL=1) to turn it on, so an unconfigured
// checkout behaves exactly like upstream Formbricks. The sidecar itself holds the reading role here
// (no per-request reader is threaded), so opens go out without a bearer: openWithoutReader is on.
import { createMinidauthSeal } from "minidauth-prisma";

import { Prisma } from "./prisma";

const seal = createMinidauthSeal({
  Prisma,
  json: { response: ["data", "contactAttributes"] },
  openWithoutReader: true,
  sealUrl: () => process.env.MINIDAUTH_SEAL_URL ?? "http://localhost:3020",
  enabled: () => Boolean(process.env.MINIDAUTH_SEAL_URL) || process.env.MINIDAUTH_SEAL === "1",
});

export const minidauthSeal = seal.extension;
