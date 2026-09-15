// Seal and open individual field values with minidauth, server-side, no Tide account and no doken.
//
// This is the tideless round trip (minidauth/examples/tideless) refactored into two functions a
// server can call: sealValue turns a string into a ciphertext blob the ORK cohort signed, and
// openValue turns it back, but only when the given uid holds the gating role. The vendor key is
// never here: it lives as shares across the ORK network and is never assembled, so this process
// holds nothing that can read a sealed value on its own.

import { webcrypto } from "node:crypto";

// tide-js expects a browser: give it crypto on window and globalThis.
if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis.window || {};
globalThis.window.crypto = globalThis.crypto;

const MC = process.env.MINIDAUTH_URL ?? "http://localhost:8081";
const OPS_TOKEN = process.env.MINIDAUTH_OPS_TOKEN ?? "dev-admin-token";     // mints encrypt (vendorsign) vouchers
const APP_TOKEN = process.env.MINIDAUTH_TOKEN ?? "dev-sample-app-token";    // the app's relying-party token
// The published @tideorg/js is built for the 14-of-20 network. Override only for a different network.
const DIST = process.env.TIDE_JS_DIST ?? new URL("./node_modules/@tideorg/js/dist", import.meta.url).pathname;

const bearer = (t) => ({ Authorization: `Bearer ${t}`, "Content-Type": "application/json" });
const b64ToBytes = (b64) => Uint8Array.from(Buffer.from(b64, "base64"));
async function mc(path, opts) {
  const r = await fetch(MC + path, opts);
  const t = await r.text();
  if (!r.ok) throw new Error(`${path} -> ${r.status} ${t}`);
  return t;
}
const mcJson = async (p, o) => JSON.parse(await mc(p, o));

let TP; // cached tide-js bundle + network config
async function tide() {
  if (TP) return TP;
  const NetworkClient = (await import(`${DIST}/Clients/NetworkClient.js`)).default;
  const dVVKSigningFlow = (await import(`${DIST}/Flow/SigningFlows/dVVKSigningFlow.js`)).default;
  const dVVKDecryptionFlow = (await import(`${DIST}/Flow/DecryptionFlows/dVVKDecryptionFlow.js`)).default;
  const { PolicyAuthorizedEncryptionFlow } = await import(`${DIST}/Flow/EncryptionFlows/PolicyAuthorizedEncryptionFlow.js`);
  const TideKey = (await import(`${DIST}/Cryptide/TideKey.js`)).default;
  const Ed25519Scheme = (await import(`${DIST}/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js`)).default;
  const PPSF = (await import(`${DIST}/Models/PolicyProtectedSerializedField.js`)).default;
  const AES = await import(`${DIST}/Cryptide/Encryption/AES.js`);

  const cfg = await mcJson("/tide/enclave/config", { headers: bearer(APP_TOKEN) });
  const enc = b64ToBytes((await mcJson("/vault/encrypt-policy")).policy);
  const dec = b64ToBytes((await mcJson("/vault/decrypt-policy", { headers: bearer(APP_TOKEN) })).policy);
  const keyInfo = await new NetworkClient(cfg.homeOrkUrl).GetKeyInfo(cfg.vvkId);
  TP = { dVVKSigningFlow, dVVKDecryptionFlow, PolicyAuthorizedEncryptionFlow, TideKey, Ed25519Scheme, PPSF, AES, cfg, enc, dec, keyInfo };
  return TP;
}

// A guest session key stands in for a doken: the flows use only doken.serialize() as the ORK bearer,
// and returning "" trips the SDK's no-token (gSessKey) path, so the crypto runs doken-less.
const guestOf = (t) => {
  const k = t.TideKey.NewKey(t.Ed25519Scheme);
  return { k, tok: { payload: { sessionKey: k.get_public_component() }, serialize: () => "" } };
};

// The two vouchers, both from minidauth. The decrypt one goes through the role-gated endpoint, so
// minidauth issues it only if uid holds role in its committed, quorum-approved grant.
const fnEncrypt = (req) => mc("/tide/vouchers", { method: "POST", headers: bearer(OPS_TOKEN), body: JSON.stringify({ voucherRequest: req }) });
const fnDecrypt = (uid, role) => (req) => mc("/vault/voucher", { method: "POST", headers: bearer(APP_TOKEN), body: JSON.stringify({ uid, role, voucherRequest: req }) });

/** Seal a string. Returns base64 ciphertext anyone can store but no one can read without a voucher. */
export async function sealValue(plaintext) {
  const t = await tide(), g = guestOf(t);
  const pae = new t.PolicyAuthorizedEncryptionFlow({ vendorId: t.cfg.vvkId, token: g.tok, sessionKey: g.k, voucherURL: "", keyInfo: t.keyInfo });
  const { request, encReqs, timestamp } = await pae.createEncryptionRequest([{ data: new TextEncoder().encode(plaintext), tags: ["formbricks"] }]);
  request.addPolicy(t.enc);
  const sf = new t.dVVKSigningFlow(t.cfg.vvkId, t.keyInfo.UserPublic, t.keyInfo.OrkInfo.slice(), g.k, g.tok, "");
  sf.setVoucherRetrievalFunction(fnEncrypt);
  const sigs = await sf.start(request);
  const cipher = t.PPSF.create(encReqs[0].encryptedData, timestamp, encReqs[0].sizeLessThan32 ? null : encReqs[0].encryptionToSign, sigs[0]);
  return Buffer.from(cipher).toString("base64");
}

/** Open a sealed string, but only if uid holds role. Throws when minidauth refuses the voucher. */
export async function openValue(uid, role, cipherB64) {
  const t = await tide(), g = guestOf(t);
  const cipher = Uint8Array.from(Buffer.from(cipherB64, "base64"));
  const pae = new t.PolicyAuthorizedEncryptionFlow({ vendorId: t.cfg.vvkId, token: g.tok, sessionKey: g.k, voucherURL: "", keyInfo: t.keyInfo });
  const { request } = pae.createDecryptionRequest([{ encrypted: cipher, tags: ["formbricks"] }]);
  request.addPolicy(t.dec);
  const df = new t.dVVKDecryptionFlow(t.cfg.vvkId, t.keyInfo.UserPublic, t.keyInfo.OrkInfo.slice(), g.k, g.tok, "");
  df.setVoucherRetrievalFunction(fnDecrypt(uid, role));
  const keys = await df.start(request);
  const b = t.PPSF.deserialize(cipher);
  const AES = t.AES;
  const out = b.encKey && b.encKey.length
    ? await AES.decryptDataRawOutput(b.encFieldChk, await AES.decryptDataRawOutput(b.encKey.slice(32), keys[0]))
    : await AES.decryptDataRawOutput(b.encFieldChk.slice(32), keys[0]);
  return new TextDecoder().decode(out);
}
