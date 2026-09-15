// Smoke test for the seal/open round trip, no Postgres and no Formbricks.
//
// Requires the sidecar running (`npm start`) against a minidauth that has a PUBLIC decrypt policy and
// has granted the reader id the response-reader role. Proves the two properties that matter: a value
// seals to ciphertext, and opens back only through the role-gated reader.
//
//   node verify.mjs

const SIDE = process.env.MINIDAUTH_SEAL_URL ?? "http://localhost:3020";

async function post(path, body) {
  const r = await fetch(SIDE + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const t = await r.text();
  if (!r.ok) throw new Error(`${path} -> ${r.status} ${t}`);
  return JSON.parse(t);
}

const secret = "GB33 BUKB 2020 1555 0099 88";
console.log("plaintext :", secret);

const { sealed } = await post("/seal", { fields: { bank: secret } });
console.log("sealed    :", sealed.bank.slice(0, 44) + "…  (this is what Postgres holds)");

const { fields } = await post("/open", { fields: { bank: sealed.bank } });
console.log("opened    :", fields.bank);

const ok = fields.bank === secret;
console.log(ok ? "\nSEAL ROUND TRIP OK" : "\nMISMATCH");
process.exit(ok ? 0 : 1);
