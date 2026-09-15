# Formbricks + minidauth: responses your own server can't read

A proof of concept that seals Formbricks survey responses with [minidauth](https://github.com/sashyo/minidauth)
so **Postgres holds only ciphertext**, the key that decrypts it is never on the Formbricks server, and a
**quorum, not the app, decides whether responses can be read at all**.

Formbricks is self-hosted precisely because survey responses contain personal data teams don't want
leaving their infrastructure. But those responses still sit in plaintext in Postgres, so a stolen
database, a leaked backup, or a compromised admin session hands over everyone who ever answered. This
changes that: the answers are sealed by the Tide ORK cohort before they reach the database, and no
single machine, including this one, holds a key that can read them back.

## What changed in this fork

Two files, plus a small keyless sidecar. The whole integration is behind one Prisma client extension,
so it covers every read and write path at once.

| | |
|---|---|
| `packages/database/src/minidauth-seal.ts` | A Prisma extension: seals `Response.data` (the answers) and `contactAttributes` on write, opens them on read. |
| `packages/database/src/client.ts` | One line: `.$extends(minidauthSeal)` on the shared client. |
| `integrations/minidauth/` | The **minidauth-seal sidecar**: it orchestrates the crypto with minidauth and the ORK cohort. It holds **no key** and Formbricks holds no Tide credential. |

Off by default: with nothing configured the fork behaves exactly like upstream Formbricks. Set
`MINIDAUTH_SEAL_URL` (pointing at the sidecar) to turn it on.

## The threat model it changes

- **A stolen database or backup reads nothing.** `Response.data` is `{ "_ms": 1, "fields": { "<questionId>": "<ciphertext>" } }`. There is no key in Postgres, in Formbricks' env, or in the sidecar to make it readable.
- **A compromised Formbricks server still can't read responses on its own.** Decryption is a threshold operation across the ORK cohort, gated on a `response-reader` role a **quorum granted** to the reader identity. Revoke that role in minidauth and reads stop everywhere, with no change to Formbricks.
- **The vendor key is never assembled.** It lives as shares across ~20 independent nodes and is never put back together, not even to decrypt.

## Run it

You need a minidauth up with a vendor key, an encrypt policy, and a **PUBLIC** (voucher-gated) decrypt
policy, and a `response-reader` role granted through the quorum to your reader id. See the
[minidauth operator guide](https://github.com/sashyo/minidauth/blob/main/docs/running.md) and its
[tideless example](https://github.com/sashyo/minidauth/tree/main/examples/tideless).

```sh
# 1. the keyless sealing sidecar
cd integrations/minidauth
npm install
MINIDAUTH_URL=http://localhost:8081 \
MINIDAUTH_OPS_TOKEN=<operator token> \
MINIDAUTH_TOKEN=<relying-party token> \
MINIDAUTH_READER_UID=<an id a quorum granted response-reader> \
MINIDAUTH_READER_ROLE=response-reader \
npm start                                   # http://localhost:3020

# 2. tell Formbricks to use it, then start Formbricks as usual
export MINIDAUTH_SEAL_URL=http://localhost:3020
```

Now submit a survey response. Then look at what the database actually holds:

```sh
psql "$DATABASE_URL" -c \
  "select id, data from \"Response\" order by created_at desc limit 1;"
# data => {"_ms":1,"fields":{"abc123":"AQAAAAEAAAAC…","def456":"AQAAAAEAAAAC…"}}
```

Ciphertext, no key anywhere near it. The responses view in Formbricks still shows the answers, because
the extension opens them through the sidecar for the quorum-granted reader. Revoke `response-reader` in
the minidauth console and the same view can no longer read them.

A minimal end-to-end smoke test of the seal/open round trip (no Postgres needed) is in
[`verify.mjs`](verify.mjs).

## Honest status

- **It is a proof of concept.** Every sealed field is one round trip to the cohort, so it fits a demo,
  not a busy production instance. A real integration would have the cohort protect a single per-response
  data key and AES the payload under it locally (envelope encryption): one cohort operation per response
  instead of per field. The sidecar is the right place to add that.
- **The decrypt policy must be PUBLIC** (voucher-gated) for the sidecar's doken-less reads. A minidauth
  set up for the doken flow (PRIVATE decrypt) needs that policy deployed first.
- **Reads are transparent and therefore slow at list scale.** For a demo, keep the response set small,
  or open on demand (a reveal action) rather than decrypting an entire list.
- Types on the shared `prisma` export are inferred from the extended client; if a strict build objects
  at a call site that annotates `PrismaClient`, widen or cast there.
