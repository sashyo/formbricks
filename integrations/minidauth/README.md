# Formbricks + minidauth — responses your own server can't read

A proof of concept that seals Formbricks survey responses with [minidauth](https://github.com/sashyo/minidauth)
so **Postgres holds only ciphertext**, the key that decrypts it is **never on the Formbricks server**, and a
**quorum — not the app — decides whether responses can be read at all**.

Formbricks is self-hosted precisely because survey responses hold personal data teams don't want leaving
their infrastructure. But self-hosting alone still leaves those answers sitting in plaintext in Postgres, so
a stolen database, a leaked backup, or one compromised admin session hands over everyone who ever answered.
This changes that: each answer is sealed by the Tide ORK cohort before it reaches the database, and no single
machine — including this one — ever holds a key that can read it back.

## What changed in this fork

Two touch points in the Formbricks codebase, plus a small keyless sidecar. The whole thing is **10 files,
+475 / −3 lines**, and the change to Formbricks' own code is a single line.

| | |
|---|---|
| `packages/database/src/minidauth-seal.ts` | A Prisma client extension: seals `Response.data` (the answers) and `Response.contactAttributes` on write, opens them on read. **130 lines, one file.** |
| `packages/database/src/client.ts` | One line: `.$extends(minidauthSeal)` on the shared Prisma client. |
| `integrations/minidauth/` | The **minidauth-seal sidecar**: it orchestrates the crypto with minidauth and the ORK cohort. It holds **no key**, and Formbricks holds no Tide credential. |

Because it's a Prisma extension, it covers **every read and write path at once** — the survey link page, the
dashboard, the API, exports — with no changes to survey logic, routes, or UI.

Off by default: with nothing configured the fork behaves exactly like upstream Formbricks. Set
`MINIDAUTH_SEAL_URL` (pointing at the sidecar) to turn it on.

## What is sealed, and what is not

Only two JSON columns on the `Response` model:

- **`data`** — the answers themselves (`questionId → value`): every rating, every free-text field.
- **`contactAttributes`** — contact info attached to a response (email, name, custom attributes).

Everything else stays plaintext and queryable: the **survey definition and its questions**, and response
**metadata** (browser, OS, device, source URL, timestamps). The line is deliberate — the respondent's
personal answers are protected; the structure the team authored stays readable.

In Postgres a sealed field looks like this — the exact bytes on disk for one answer:

```json
{ "_ms": 1, "fields": { "ljo4h395adwlbpsxno4tlsom": "AQAAAAEAAAAC…", "s33kewa2cyfh8blkz9zfrnjh": "AQAAAAEAAAAC…" } }
```

## Why minidauth is the right tool here

App-level encryption usually means a key that lives next to the data — in an env var, or a KMS the same app
can call — so whatever can read the database can also read the key. minidauth removes that:

- **No key on the server.** The vendor key exists only as threshold shares across ~20 independent ORK nodes and
  is **never assembled**, not even to decrypt. A stolen Formbricks host, database, or backup yields ciphertext
  and nothing to unlock it.
- **Decryption is a network operation across a cohort, not a local call.** Each reveal sends the ciphertext to
  the ORK nodes; **14 of 20** must return a partial share for the answer to come back. There is no single point
  where a key can be copied.
- **A quorum controls reads, not the app.** Decryption is gated on a `response-reader` role that a **quorum
  granted** through minidauth's governance. Revoke that role and reads stop everywhere — instantly, with no
  change to Formbricks. Access is *governed*, not asserted by whoever holds the server.
- **No accounts for respondents.** This runs "tideless": respondents never create a Tide account. The app's own
  identity plus a quorum-granted role is what unlocks a read, so nothing about the survey-taker flow changes.
- **Drop-in and reversible.** One Prisma extension, off by default. Nothing else in Formbricks is aware of it.

The net effect: the trust that used to sit in "whoever holds the database and the key" is split across an
independent cohort and a governance quorum. Compromising the app is no longer enough to read the data.

## The threat model it changes

- **A stolen database or backup reads nothing.** There is no key in Postgres, in Formbricks' env, or in the
  sidecar to make `Response.data` readable.
- **A compromised Formbricks server still can't read responses on its own.** Decryption is a threshold operation
  across the ORK cohort, gated on a quorum-granted role. Revoke the role in minidauth and reads stop.
- **The vendor key is never assembled** — it lives as shares across independent nodes and is never put back
  together, not even to decrypt.

## Run it

You need a minidauth up with a vendor key, an encrypt policy, and a **PUBLIC** (voucher-gated) decrypt policy,
and a `response-reader` role granted through the quorum to your reader id. See the
[minidauth operator guide](https://github.com/sashyo/minidauth/blob/main/docs/running.md) and its
[tideless example](https://github.com/sashyo/minidauth/tree/main/examples/tideless).

```sh
# 1. the keyless sealing sidecar
cd integrations/minidauth
npm install
MINIDAUTH_URL=http://localhost:8082 \
MINIDAUTH_OPS_TOKEN=<operator token> \
MINIDAUTH_TOKEN=<relying-party token> \
MINIDAUTH_READER_UID=<an id a quorum granted response-reader> \
MINIDAUTH_READER_ROLE=response-reader \
npm start                                   # http://localhost:3020

# 2. tell Formbricks to use it, then start Formbricks as usual
export MINIDAUTH_SEAL_URL=http://localhost:3020
```

Submit a survey response, then look at what the database actually holds:

```sh
psql "$DATABASE_URL" -c 'select id, data from "Response" order by created_at desc limit 1;'
# data => {"_ms":1,"fields":{"abc123":"AQAAAAEAAAAC…","def456":"AQAAAAEAAAAC…"}}
```

Ciphertext, no key near it. The responses view in Formbricks still shows the answers, because the extension
opens them through the sidecar for the quorum-granted reader. Revoke `response-reader` in the minidauth console
and the same view can no longer read them.

- [`verify.mjs`](verify.mjs) — a minimal seal/open round trip (no Postgres needed).
- [`live-demo.ts`](live-demo.ts) — creates a real response through the extended Prisma client and prints the
  ciphertext Postgres holds next to the plaintext read back through the app.

## Honest status

- **It is a proof of concept.** Every sealed field is one round trip to the cohort, so it fits a demo, not a busy
  production instance. A real integration would have the cohort protect a single per-response data key and AES the
  payload under it locally (envelope encryption): one cohort operation per response instead of per field. The
  sidecar is the right place to add that.
- **The decrypt policy must be PUBLIC** (voucher-gated) for the sidecar's doken-less reads.
- **Reads are transparent and therefore slow at list scale.** For a demo keep the response set small, or open on
  demand (a reveal action) rather than decrypting an entire list.
