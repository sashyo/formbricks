// Seal and open individual field values with minidauth, server-side, no Tide account and no doken.
//
// This is the tideless round trip (minidauth/examples/tideless) refactored into two functions a
// server can call: sealValue turns a string into a ciphertext blob the ORK cohort signed, and
// openValue turns it back, but only when the given uid holds the gating role. The vendor key is
// never here: it lives as shares across the ORK network and is never assembled, so this process
// holds nothing that can read a sealed value on its own.

import { webcrypto, createPrivateKey, sign as edSign, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

// tide-js expects a browser: give it crypto on window and globalThis.
if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis.window || {};
globalThis.window.crypto = globalThis.crypto;

const MC = process.env.MINIDAUTH_URL ?? "http://localhost:8081";
const OPS_TOKEN = process.env.MINIDAUTH_OPS_TOKEN ?? "dev-admin-token";     // mints encrypt (vendorsign) vouchers
const APP_TOKEN = process.env.MINIDAUTH_TOKEN ?? "dev-sample-app-token";    // legacy shared relying-party token (fallback only)
// The published @tideorg/js is built for the 14-of-20 network. Override only for a different network.
const DIST = process.env.TIDE_JS_DIST ?? new URL("./node_modules/@tideorg/js/dist", import.meta.url).pathname;

const bearer = (t) => ({ Authorization: `Bearer ${t}`, "Content-Type": "application/json" });

// Relying-party authentication to minidauth. Prefer a private-key Assertion: the sidecar signs a
// short-lived JWT with an Ed25519 key it alone holds, and minidauth verifies it against the public
// key registered for this app. There is then no shared app token to find in the code or config, so a
// copy of minidauth's operators file is worth nothing and the old "Bearer dev-sample-app-token" route
// is dead. Falls back to the static Bearer token only if no key is configured.
//   MINIDAUTH_APP_ASSERTION_KEY_FILE=… (PKCS8 PEM)  or  MINIDAUTH_APP_ASSERTION_KEY=<inline PEM>
//   MINIDAUTH_APP_ASSERTION_ISS=sample-app          (the operator name minidauth knows this app as)
//   MINIDAUTH_APP_ASSERTION_AUD=<minidauth public URL>   (defaults to MINIDAUTH_URL)
const ASSERTION_ISS = process.env.MINIDAUTH_APP_ASSERTION_ISS ?? "sample-app";
const ASSERTION_AUD = (process.env.MINIDAUTH_APP_ASSERTION_AUD ?? MC).replace(/\/+$/, "");
const b64url = (b) => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

let _appKey; // cached KeyObject | null
function appAssertionKey() {
  if (_appKey !== undefined) return _appKey;
  const pem = process.env.MINIDAUTH_APP_ASSERTION_KEY
    ?? (process.env.MINIDAUTH_APP_ASSERTION_KEY_FILE ? readFileSync(process.env.MINIDAUTH_APP_ASSERTION_KEY_FILE, "utf8") : null);
  _appKey = pem ? createPrivateKey(pem) : null;
  return _appKey;
}

// One fresh, single-use assertion per call (unique jti, short lifetime): minidauth replay-protects them.
function mintAssertion() {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT" }));
  const claims = b64url(JSON.stringify({ iss: ASSERTION_ISS, aud: ASSERTION_AUD, iat: now, exp: now + 120, jti: randomUUID() }));
  const sig = b64url(edSign(null, Buffer.from(`${header}.${claims}`, "ascii"), appAssertionKey()));
  return `${header}.${claims}.${sig}`;
}

const appAuth = () => appAssertionKey()
  ? { Authorization: `Assertion ${mintAssertion()}`, "Content-Type": "application/json" }
  : bearer(APP_TOKEN);
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

  const cfg = await mcJson("/tide/enclave/config", { headers: appAuth() });
  const enc = b64ToBytes((await mcJson("/vault/encrypt-policy")).policy);
  const dec = b64ToBytes((await mcJson("/vault/decrypt-policy", { headers: appAuth() })).policy);
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
// userToken (when present) is the end user's own verified token, forwarded to minidauth in X-Tide-User
// so minidauth derives the uid from it and no longer trusts uid asserted here. uid/role are still sent
// (uid must match the token) for minidauth deployments that have not turned user-token checking on.
const fnDecrypt = (uid, role, userToken) => (req) => mc("/vault/voucher", {
  method: "POST",
  headers: { ...appAuth(), ...(userToken ? { "X-Tide-User": userToken } : {}) },
  body: JSON.stringify({ uid, role, voucherRequest: req }),
});

export const MARKER = "ms1:"; // a sealed column is "ms1:<ciphertextB64>"

/** Seal one field value. There is NO passthrough: a value that merely looks sealed is sealed anyway.
 *  A client cannot forge a genuine sealed field, but it can forge the structure of one (an unsigned
 *  envelope full of plaintext, a copied prefix), and the only way to tell forgery from a genuine seal
 *  is the VVK signature, which only the cohort can check. So we never trust the shape: every inbound
 *  value is treated as plaintext and sealed, marker included. A client "ms1:..." string is sealed as
 *  the literal string it is. The caller must therefore only send NEW values here (plaintext writes),
 *  never re-feed a stored ciphertext, or it would be double-sealed. */
export async function sealField(value) {
  return MARKER + (await sealValue(value));
}

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

// Recover one plaintext from its ciphertext bytes and the cohort-returned key for it.
async function decryptWith(t, cipher, key) {
  const b = t.PPSF.deserialize(cipher);
  const AES = t.AES;
  const out = b.encKey && b.encKey.length
    ? await AES.decryptDataRawOutput(b.encFieldChk, await AES.decryptDataRawOutput(b.encKey.slice(32), key))
    : await AES.decryptDataRawOutput(b.encFieldChk.slice(32), key);
  return new TextDecoder().decode(out);
}

/** Open MANY sealed strings in ONE cohort round trip, gated on uid holding role. The decryption
 *  flow takes an array and returns one key per ciphertext, so N fields (or a whole page of records)
 *  cost a single fan-out to the ORKs instead of N. Order is preserved: keys[i] belongs to ciphers[i]. */
export async function openValues(uid, role, cipherB64s, userToken) {
  if (!cipherB64s || cipherB64s.length === 0) return [];
  const t = await tide(), g = guestOf(t);
  const ciphers = cipherB64s.map((c) => Uint8Array.from(Buffer.from(c, "base64")));
  const pae = new t.PolicyAuthorizedEncryptionFlow({ vendorId: t.cfg.vvkId, token: g.tok, sessionKey: g.k, voucherURL: "", keyInfo: t.keyInfo });
  const { request } = pae.createDecryptionRequest(ciphers.map((c) => ({ encrypted: c, tags: ["formbricks"] })));
  request.addPolicy(t.dec);
  const df = new t.dVVKDecryptionFlow(t.cfg.vvkId, t.keyInfo.UserPublic, t.keyInfo.OrkInfo.slice(), g.k, g.tok, "");
  df.setVoucherRetrievalFunction(fnDecrypt(uid, role, userToken));
  const keys = await df.start(request); // ONE fan-out, one partial-share set per ciphertext
  return Promise.all(ciphers.map((c, i) => decryptWith(t, c, keys[i])));
}

/** Open a single sealed string, but only if uid holds role. Throws when minidauth refuses the voucher. */
export async function openValue(uid, role, cipherB64, userToken) {
  return (await openValues(uid, role, [cipherB64], userToken))[0];
}

// --- Level 2b: relying-party relay for a client that holds its own session key ---------------------
//
// When the decrypt runs in the user's client (browser), the client cannot hold this app's relying-
// party credential and must not. So the sidecar lends it: these forward to minidauth with the app
// Assertion attached, and nothing else. The sidecar mints no user identity here and never decrypts.
// The client's identity rides in the user token (minted user doken) and its authority to use that
// doken rides in a proof of possession only it can produce. config and decrypt-policy are not secret;
// they let the client bootstrap the tide-js decrypt flow without ever seeing an app credential.
export const proxyConfig = () => mcJson("/tide/enclave/config", { headers: appAuth() });
export const proxyDecryptPolicy = () => mcJson("/vault/decrypt-policy", { headers: appAuth() });
export const proxyMintUserDoken = (userToken, sessionKey, role) =>
  mcJson("/vault/user-token", { method: "POST", headers: appAuth(), body: JSON.stringify({ userToken, sessionKey, role }) });
export const proxyVoucher = ({ role, voucherRequest, doken, popTs, popNonce, popSig }) =>
  mc("/vault/voucher", {
    method: "POST",
    headers: {
      ...appAuth(),
      "X-Tide-Doken": doken,
      "X-Tide-PoP-TS": String(popTs),
      "X-Tide-PoP-Nonce": popNonce,
      "X-Tide-PoP": popSig,
    },
    body: JSON.stringify({ role, voucherRequest }),
  });
