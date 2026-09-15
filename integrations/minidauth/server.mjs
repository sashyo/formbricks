// A tiny sealing service for Formbricks.
//
// It holds no key. minidauth and the ORK cohort do the crypto; this only orchestrates it and injects
// the reader identity on the open side, so Formbricks itself never holds a Tide credential, a role,
// or anything that can read a sealed value. Formbricks calls /seal before a response reaches
// Postgres and /open when an authorised reader needs it back.
//
//   MINIDAUTH_URL=…  MINIDAUTH_TOKEN=…  MINIDAUTH_OPS_TOKEN=…  \
//   MINIDAUTH_READER_UID=…  MINIDAUTH_READER_ROLE=response-reader \
//   node --import ./register.mjs server.mjs

import { createServer } from "node:http";
import { sealValue, openValue } from "./seal.mjs";

const PORT = Number(process.env.PORT ?? 3020);
// Who reads, and the role a quorum has to have granted them. Revoke the role in minidauth and every
// open below stops working, with no change to Formbricks. That is the whole point.
const READER_UID = process.env.MINIDAUTH_READER_UID ?? "formbricks-reader";
const READER_ROLE = process.env.MINIDAUTH_READER_ROLE ?? "response-reader";

const readBody = (req) => new Promise((resolve, reject) => {
  let b = ""; req.on("data", (c) => (b += c));
  req.on("end", () => { try { resolve(JSON.parse(b || "{}")); } catch (e) { reject(e); } });
  req.on("error", reject);
});
const send = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };

const server = createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") return send(res, 200, { status: "up", reader: READER_UID, role: READER_ROLE });

    if (req.method === "POST" && req.url === "/seal") {
      // { fields: { key: plaintextString } } -> { sealed: { key: ciphertextB64 } }
      const { fields } = await readBody(req);
      const sealed = {};
      for (const [k, v] of Object.entries(fields || {})) sealed[k] = await sealValue(String(v));
      return send(res, 200, { sealed });
    }

    if (req.method === "POST" && req.url === "/open") {
      // { fields: { key: ciphertextB64 } } -> { fields: { key: plaintextString } }, gated on the reader's role
      const { fields } = await readBody(req);
      const out = {};
      for (const [k, v] of Object.entries(fields || {})) out[k] = await openValue(READER_UID, READER_ROLE, String(v));
      return send(res, 200, { fields: out });
    }

    send(res, 404, { error: "not found" });
  } catch (e) {
    const refused = /does not hold|will not voucher|403/.test(String(e.message || e));
    send(res, refused ? 403 : 502, { error: String(e.message || e) });
  }
});

server.listen(PORT, () => console.log(`minidauth-seal on http://localhost:${PORT}  (reader ${READER_UID} needs ${READER_ROLE})`));
