// minidauth field sealing for survey responses.
//
// A Prisma client extension that seals the Response Json fields (`data`, the answers, and
// `contactAttributes`) before they reach Postgres, and opens them again on the way out. The crypto
// runs in the minidauth-seal sidecar (integrations/minidauth), which talks to minidauth and the ORK
// cohort. This process, and Postgres, only ever hold ciphertext: the vendor key lives as shares
// across the ORK network and is never assembled here, so a stolen database or a leaked backup is
// unreadable, and a quorum, not this app, controls whether responses can be read at all.
//
// Off by default. Set MINIDAUTH_SEAL_URL (or MINIDAUTH_SEAL=1) to turn it on, so an unconfigured
// checkout behaves exactly like upstream Formbricks.
//
// Note this is a proof of concept: every sealed field is one round trip to the cohort, so it suits a
// demo, not a high-throughput deployment. A production integration would have the cohort protect one
// per-response data key and AES the payload under it locally (envelope encryption), one cohort op per
// response rather than per field.
import { Prisma } from "./prisma";

const SEAL_URL = process.env.MINIDAUTH_SEAL_URL ?? "http://localhost:3020";
const ENABLED = Boolean(process.env.MINIDAUTH_SEAL_URL) || process.env.MINIDAUTH_SEAL === "1";

// The Response Json columns worth sealing: each is a Record<questionId|attr, value>.
const SEALED_FIELDS = ["data", "contactAttributes"];

interface SealedBag { _ms: 1; fields: Record<string, string>; }
const isSealed = (v: unknown): v is SealedBag =>
  !!v && typeof v === "object" && (v as SealedBag)._ms === 1 && typeof (v as SealedBag).fields === "object";

async function sidecar(path: string, body: unknown): Promise<any> {
  const r = await fetch(SEAL_URL + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`minidauth-seal ${path} -> ${r.status} ${text}`);
  return text ? JSON.parse(text) : {};
}

// Turn one { questionId: value } bag into a sealed bag of ciphertext, JSON-serialising each value so
// numbers, arrays and objects survive the round trip.
async function sealBag(bag: unknown): Promise<unknown> {
  if (!bag || typeof bag !== "object" || isSealed(bag)) return bag;
  const fields: Record<string, string> = {};
  for (const [k, v] of Object.entries(bag as Record<string, unknown>)) {
    if (v !== undefined && v !== null) fields[k] = JSON.stringify(v);
  }
  if (Object.keys(fields).length === 0) return bag;
  const { sealed } = await sidecar("/seal", { fields });
  return { _ms: 1, fields: sealed } satisfies SealedBag;
}

async function openBag(bag: unknown): Promise<unknown> {
  if (!isSealed(bag)) return bag;
  const { fields } = await sidecar("/open", { fields: bag.fields });
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields as Record<string, string>)) out[k] = JSON.parse(v);
  return out;
}

async function sealWriteInput(data: any): Promise<any> {
  if (!data || typeof data !== "object") return data;
  for (const f of SEALED_FIELDS) if (f in data) data[f] = await sealBag(data[f]);
  return data;
}

let openWarned = false;
async function openRow(row: any): Promise<any> {
  if (!row || typeof row !== "object") return row;
  for (const f of SEALED_FIELDS) {
    if (!isSealed(row[f])) continue;
    try {
      row[f] = await openBag(row[f]);
    } catch (e) {
      // Best-effort: if the reader is not (yet) allowed to open — no PUBLIC decrypt policy, the
      // response-reader role not granted, the sidecar down — leave the field sealed rather than crash
      // the app. The value stays ciphertext, which is the safe failure.
      if (!openWarned) { openWarned = true; console.warn("[minidauth-seal] leaving responses sealed:", (e as Error).message); }
    }
  }
  return row;
}

export const minidauthSeal = Prisma.defineExtension({
  name: "minidauth-seal",
  query: {
    response: {
      async create({ args, query }) {
        if (ENABLED) args.data = await sealWriteInput(args.data);
        return query(args);
      },
      async update({ args, query }) {
        if (ENABLED) args.data = await sealWriteInput(args.data);
        return query(args);
      },
      async upsert({ args, query }) {
        if (ENABLED) {
          args.create = await sealWriteInput(args.create);
          args.update = await sealWriteInput(args.update);
        }
        return query(args);
      },
      async createMany({ args, query }) {
        if (ENABLED && Array.isArray(args.data)) args.data = await Promise.all(args.data.map(sealWriteInput));
        return query(args);
      },
      async findMany({ args, query }) {
        const res: any = await query(args);
        if (ENABLED && Array.isArray(res)) for (const r of res) await openRow(r);
        return res;
      },
      async findUnique({ args, query }) {
        const res: any = await query(args);
        return ENABLED ? openRow(res) : res;
      },
      async findFirst({ args, query }) {
        const res: any = await query(args);
        return ENABLED ? openRow(res) : res;
      },
      async findUniqueOrThrow({ args, query }) {
        const res: any = await query(args);
        return ENABLED ? openRow(res) : res;
      },
      async findFirstOrThrow({ args, query }) {
        const res: any = await query(args);
        return ENABLED ? openRow(res) : res;
      },
    },
  },
});
