// Level 2b: decrypt in the client, so the server never sees plaintext.
//
// This stands in for the user's browser. It holds a session keypair the server never sees, gets a
// session-bound user doken from minidauth (through the sidecar relay, which lends its relying-party
// credential and nothing else), and runs the tide-js decrypt flow here. Every voucher carries a fresh
// proof of possession only this process can make. The sidecar relays vouchers and config; it mints no
// identity and never holds a plaintext. The same code runs in a browser with Web Crypto in place of
// node:crypto and a bundled tide-js.
//
//   SIDECAR=http://localhost:3021  USER_SECRET=<same as minidauth MC_USER_TOKEN_SECRET>  UID=<user id>
//   node client-decrypt.mjs "ms1-or-raw-ciphertext-b64" ["another" ...]

import { webcrypto, generateKeyPairSync, sign as edSign, createHmac, createHash, createPrivateKey, randomUUID } from "node:crypto";
import { readFileSync as readKey } from "node:fs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis.window || {};
globalThis.window.crypto = globalThis.crypto;

const SIDECAR = process.env.SIDECAR ?? "http://localhost:3021";
const USER_SECRET = process.env.USER_SECRET ?? "sidecar-test-secret-do-not-ship"; // proves the login; in a real app this token comes from the app's session, not minted here
const UID = process.env.UID ?? "20202020-9e3b-46d4-a556-88b9ddc2b034";
const DIST = process.env.TIDE_JS_DIST ?? new URL("./node_modules/@tideorg/js/dist", import.meta.url).pathname;

const b64url = (b) => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64ToBytes = (b64) => Uint8Array.from(Buffer.from(b64, "base64"));
const post = async (path, body) => {
  const r = await fetch(SIDECAR + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) });
  const t = await r.text();
  if (!r.ok) throw new Error(`${path} -> ${r.status} ${t}`);
  return t;
};
const postJson = async (p, b) => JSON.parse(await post(p, b));

// The session key the server never sees. Its private half signs every proof of possession.
const session = generateKeyPairSync("ed25519");
const sessionPubB64 = session.publicKey.export({ type: "spki", format: "der" }).toString("base64");

// Stand-in for the token the app hands the browser after login. In a real app the app server mints
// this from its session. Prefer the app's Ed25519 signing key (MINIDAUTH_SEAL_SIGNING_KEY_FILE), which
// minidauth verifies with the public half; fall back to the HS256 secret only if no key is set.
const signingKey = process.env.MINIDAUTH_SEAL_SIGNING_KEY_FILE
  ? createPrivateKey(readKey(process.env.MINIDAUTH_SEAL_SIGNING_KEY_FILE, "utf8"))
  : null;
function loginToken() {
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(JSON.stringify({ sub: UID, iat: now, exp: now + 60 }));
  if (signingKey) {
    const h = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT" }));
    return `${h}.${payload}.${b64url(edSign(null, Buffer.from(`${h}.${payload}`, "ascii"), signingKey))}`;
  }
  const h = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  return `${h}.${payload}.${b64url(createHmac("sha256", USER_SECRET).update(`${h}.${payload}`).digest())}`;
}

// Fresh proof of possession per voucher: a signature by the session key over the request too, so a
// captured proof cannot be redirected to a different decryption. Replay- and freshness-checked.
function proofOfPossession(boundRequest) {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomUUID();
  const hash = createHash("sha256").update(boundRequest ?? "").digest("hex");
  const sig = b64url(edSign(null, Buffer.from(`${UID}.${ts}.${nonce}.${hash}`, "ascii"), session.privateKey));
  return { popTs: ts, popNonce: nonce, popSig: sig };
}

async function main() {
  const ciphersB64 = process.argv.slice(2);
  if (ciphersB64.length === 0) { console.error("usage: client-decrypt.mjs <ciphertextB64> [...]"); process.exit(1); }
  // strip an "ms1:" marker if a stored column value was passed verbatim
  const rawB64 = ciphersB64.map((c) => (c.startsWith("ms1:") ? c.slice(4) : c));

  // 1. Get a session-bound doken (through the relay). The server sees our public key, never the private one.
  const { userDoken } = await postJson("/proxy/user-token", { userToken: loginToken(), sessionKey: sessionPubB64 });
  console.log("got a session-bound user doken from minidauth (via relay)\n");

  // 2. Bootstrap tide-js from config/policy the relay forwards (neither is secret).
  const NetworkClient = (await import(`${DIST}/Clients/NetworkClient.js`)).default;
  const dVVKDecryptionFlow = (await import(`${DIST}/Flow/DecryptionFlows/dVVKDecryptionFlow.js`)).default;
  const { PolicyAuthorizedEncryptionFlow } = await import(`${DIST}/Flow/EncryptionFlows/PolicyAuthorizedEncryptionFlow.js`);
  const TideKey = (await import(`${DIST}/Cryptide/TideKey.js`)).default;
  const Ed25519Scheme = (await import(`${DIST}/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js`)).default;
  const PPSF = (await import(`${DIST}/Models/PolicyProtectedSerializedField.js`)).default;
  const AES = await import(`${DIST}/Cryptide/Encryption/AES.js`);

  const cfg = await postJson("/proxy/config");
  const decPolicy = b64ToBytes((await postJson("/proxy/decrypt-policy")).policy);
  const keyInfo = await new NetworkClient(cfg.homeOrkUrl).GetKeyInfo(cfg.vvkId);

  // A guest key stands in as the ORK bearer (the doken-less gSessKey path); authority comes from the
  // voucher, which minidauth issues only against our doken + proof of possession.
  const gk = TideKey.NewKey(Ed25519Scheme);
  const gtok = { payload: { sessionKey: gk.get_public_component() }, serialize: () => "" };
  const ciphers = rawB64.map(b64ToBytes);

  // 3. Decrypt here. The voucher function is the only thing that leaves this process, and it carries a
  //    fresh proof of possession; the sidecar relays it to minidauth and returns the voucher.
  const pae = new PolicyAuthorizedEncryptionFlow({ vendorId: cfg.vvkId, token: gtok, sessionKey: gk, voucherURL: "", keyInfo });
  const { request } = pae.createDecryptionRequest(ciphers.map((c) => ({ encrypted: c, tags: ["formbricks"] })));
  request.addPolicy(decPolicy);
  const df = new dVVKDecryptionFlow(cfg.vvkId, keyInfo.UserPublic, keyInfo.OrkInfo.slice(), gk, gtok, "");
  df.setVoucherRetrievalFunction((voucherRequest) => post("/proxy/voucher", { voucherRequest, doken: userDoken, ...proofOfPossession(voucherRequest) }));
  const keys = await df.start(request);

  const plains = await Promise.all(ciphers.map(async (c, i) => {
    const b = PPSF.deserialize(c);
    const out = b.encKey && b.encKey.length
      ? await AES.decryptDataRawOutput(b.encFieldChk, await AES.decryptDataRawOutput(b.encKey.slice(32), keys[i]))
      : await AES.decryptDataRawOutput(b.encFieldChk.slice(32), keys[i]);
    return new TextDecoder().decode(out);
  }));
  console.log("decrypted IN THIS CLIENT (the sidecar never saw plaintext):");
  plains.forEach((p, i) => console.log(`  [${i}] ${p}`));
}

main().catch((e) => { console.error("client decrypt failed:", e.message); process.exit(1); });
